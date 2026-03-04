package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/auth"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/scan"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

func newScanCmd() *cobra.Command {
	var (
		workingDir string
		outputJSON bool
	)

	cmd := &cobra.Command{
		Use:   "scan [scan-type] [path...]",
		Short: "Run security scan directly (without MCP server)",
		Long: `Run a security scan on the specified paths without starting an MCP server.
This is useful for quick scans, CI/CD integration, or testing.

Available scan types:
  all     - Run all scans (SAST + Secrets)
  sast    - Static Application Security Testing only
  secrets - Hardcoded secrets detection only
  sca     - Software Composition Analysis (vulnerability scanning)

The scan will analyze the specified files or directories and output results
in human-readable format (default) or JSON format (with --json flag).

Examples:
  # Scan everything in current directory
  datadog-code-security-mcp scan all .

  # Scan source directory for SAST issues
  datadog-code-security-mcp scan sast ./src

  # Scan config files for hardcoded secrets
  datadog-code-security-mcp scan secrets ./config

  # Scan existing SBOM for vulnerabilities
  datadog-code-security-mcp scan sca sbom.json

  # Scan multiple paths with JSON output
  datadog-code-security-mcp scan all ./src ./config --json

  # Scan from a specific working directory
  datadog-code-security-mcp scan all ./app --working-dir /path/to/project`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanType := args[0]
			paths := args[1:]
			return runDirectScan(scanType, paths, workingDir, outputJSON)
		},
	}

	cmd.Flags().StringVarP(&workingDir, "working-dir", "w", "", "Working directory for resolving relative paths (defaults to current directory)")
	cmd.Flags().BoolVarP(&outputJSON, "json", "j", false, "Output results in JSON format")

	return cmd
}

func runDirectScan(scanType string, paths []string, workingDir string, outputJSON bool) error {
	ctx := context.Background()

	// Load and set auth credentials if available
	authConfig, err := auth.LoadConfig()
	if err == nil && authConfig.IsConfigured() {
		authProvider, err := auth.NewProvider(authConfig)
		if err == nil {
			creds, err := authProvider.GetCredentials(ctx)
			if err == nil && creds != nil {
				if creds.APIKey != "" {
					os.Setenv("DD_API_KEY", creds.APIKey)
				}
				if creds.APPKey != "" {
					os.Setenv("DD_APP_KEY", creds.APPKey)
				}
				if creds.Site != "" {
					os.Setenv("DD_SITE", creds.Site)
				}
			}
		}
	}
	scanType = strings.ToLower(scanType)

	// Validate that at least one path is provided
	if len(paths) == 0 {
		return fmt.Errorf("%s scan requires at least one path to scan", scanType)
	}

	// Build scan args
	scanArgs := scan.ScanArgs{
		FilePaths:  paths,
		WorkingDir: workingDir,
	}

	// Set scan types based on command
	switch scanType {
	case "all":
		scanArgs.ScanTypes = []string{string(types.DetectionTypeSAST), string(types.DetectionTypeSecrets), string(types.DetectionTypeSCA)}
	case "sast":
		scanArgs.ScanTypes = []string{string(types.DetectionTypeSAST)}
	case "secrets":
		scanArgs.ScanTypes = []string{string(types.DetectionTypeSecrets)}
	case "sca":
		scanArgs.ScanTypes = []string{string(types.DetectionTypeSCA)}
	default:
		return fmt.Errorf("invalid scan type: %s (valid options: all, sast, secrets, sca)", scanType)
	}

	// Execute scan
	result, err := scan.ExecuteScan(ctx, scanArgs)
	if err != nil {
		return err
	}

	// Output results
	if outputJSON {
		return outputResultsJSON(result)
	}

	return outputResultsHuman(result, scanType)
}

func outputResultsJSON(result *scan.ScanResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputResultsHuman(result *scan.ScanResult, scanType string) error {
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║       Datadog Code Security Scan Results                      ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Summary
	fmt.Printf("Scan Type: %s\n", strings.ToUpper(scanType))
	fmt.Printf("Total Violations: %d\n", result.Summary.Total)
	fmt.Println()

	// Severity breakdown
	if len(result.Summary.BySeverity) > 0 {
		fmt.Println("Severity Breakdown:")
		for severity, count := range result.Summary.BySeverity {
			icon := getSeverityIcon(severity)
			fmt.Printf("  %s %s: %d\n", icon, severity, count)
		}
		fmt.Println()
	}

	// Detection type breakdown
	if len(result.Summary.ByDetectionType) > 0 {
		fmt.Println("Detection Type Breakdown:")
		for detType, count := range result.Summary.ByDetectionType {
			fmt.Printf("  • %s: %d\n", detType, count)
		}
		fmt.Println()
	}

	// No violations found
	if result.Summary.Total == 0 {
		fmt.Println("✅ No security issues found!")
		return nil
	}

	// Detailed violations
	fmt.Println("─────────────────────────────────────────────────────────────────")
	fmt.Println("Detailed Violations:")
	fmt.Println("─────────────────────────────────────────────────────────────────")
	fmt.Println()

	// Group and display violations by detection type
	for detType, violations := range result.Results {
		if len(violations) == 0 {
			continue
		}

		fmt.Printf("▼ %s (%d issues)\n", strings.ToUpper(string(detType)), len(violations))
		fmt.Println()

		for i, v := range violations {
			// Severity icon
			icon := getSeverityIcon(v.Severity)

			// Print violation header
			fmt.Printf("%d. %s [%s] %s\n", i+1, icon, v.Severity, v.Rule)

			// Location
			fmt.Printf("   Location: %s:%d\n", v.File, v.Line)

			// Message
			if v.Message != "" {
				fmt.Printf("   Message: %s\n", v.Message)
			}

			// Rule URL
			if v.RuleURL != "" {
				fmt.Printf("   Documentation: %s\n", v.RuleURL)
			}

			fmt.Println()
		}
	}

	// Errors if any
	if len(result.Errors) > 0 {
		fmt.Println("─────────────────────────────────────────────────────────────────")
		fmt.Println("⚠️  Warnings:")
		fmt.Println("─────────────────────────────────────────────────────────────────")
		for _, scanErr := range result.Errors {
			fmt.Printf("  • %s: %s\n", scanErr.DetectionType, scanErr.Error)
			if scanErr.Hint != "" {
				fmt.Printf("    Hint: %s\n", scanErr.Hint)
			}
		}
		fmt.Println()
	}

	// Exit with non-zero if violations found
	if result.Summary.Total > 0 {
		os.Exit(1)
	}

	return nil
}

func getSeverityIcon(severity string) string {
	switch strings.ToUpper(severity) {
	case types.SeverityCritical:
		return "🔴"
	case types.SeverityHigh:
		return "🟠"
	case types.SeverityMedium:
		return "🟡"
	case types.SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}
