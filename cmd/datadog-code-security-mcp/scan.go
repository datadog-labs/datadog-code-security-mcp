package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/auth"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/libraryscan"
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
  all     - Run all scans (SAST + Secrets + SCA + IaC)
  sast    - Static Application Security Testing only
  secrets - Hardcoded secrets detection only
  sca     - Software Composition Analysis (vulnerability scanning)
  iac     - Infrastructure-as-Code scanning

Use 'scan library' to scan specific libraries by PURL via the Datadog cloud API.

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

	cmd.AddCommand(newLibraryScanCmd())

	return cmd
}

// loadAuthToEnv attempts to load Datadog credentials from the auth provider and
// sets them as environment variables. Errors are silently ignored so callers can
// fall back to env vars already set by the user.
func loadAuthToEnv(ctx context.Context) {
	authConfig, err := auth.LoadConfig()
	if err != nil || !authConfig.IsConfigured() {
		return
	}
	provider, err := auth.NewProvider(authConfig)
	if err != nil {
		return
	}
	creds, err := provider.GetCredentials(ctx)
	if err != nil || creds == nil {
		return
	}
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

func runDirectScan(scanType string, paths []string, workingDir string, outputJSON bool) error {
	ctx := context.Background()

	loadAuthToEnv(ctx)
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
		scanArgs.ScanTypes = []string{string(types.DetectionTypeSAST), string(types.DetectionTypeSecrets), string(types.DetectionTypeSCA), string(types.DetectionTypeIaC)}
	case "sast":
		scanArgs.ScanTypes = []string{string(types.DetectionTypeSAST)}
	case "secrets":
		scanArgs.ScanTypes = []string{string(types.DetectionTypeSecrets)}
	case "sca":
		scanArgs.ScanTypes = []string{string(types.DetectionTypeSCA)}
	case "iac":
		scanArgs.ScanTypes = []string{string(types.DetectionTypeIaC)}
	default:
		return fmt.Errorf("invalid scan type: %s (valid options: all, sast, secrets, sca, iac)", scanType)
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

func newLibraryScanCmd() *cobra.Command {
	var (
		purls      []string
		workingDir string
		outputJSON bool
	)

	cmd := &cobra.Command{
		Use:   "library",
		Short: "Scan specific libraries for known vulnerabilities via the Datadog API",
		Long: `Scan one or more libraries identified by Package URL (PURL) for known
vulnerabilities using the Datadog cloud API.

Requires DD_API_KEY and DD_APP_KEY to be set (or configured via 'dd-auth').

Examples:
  # Scan a single Go module
  datadog-code-security-mcp scan library \
    --purl pkg:golang/github.com/gin-gonic/gin@v1.9.0

  # Scan multiple libraries
  datadog-code-security-mcp scan library \
    --purl pkg:golang/github.com/gin-gonic/gin@v1.9.0 \
    --purl pkg:npm/lodash@4.17.21

  # Output as JSON
  datadog-code-security-mcp scan library \
    --purl pkg:npm/lodash@4.17.21 \
    --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLibraryScan(purls, workingDir, outputJSON)
		},
	}

	cmd.Flags().StringArrayVar(&purls, "purl", nil, "Package URL to scan (can be specified multiple times)")
	cmd.Flags().StringVarP(&workingDir, "working-dir", "w", "", "Working directory for git context detection (defaults to current directory)")
	cmd.Flags().BoolVarP(&outputJSON, "json", "j", false, "Output results in JSON format")
	_ = cmd.MarkFlagRequired("purl")

	return cmd
}

func runLibraryScan(purls []string, workingDir string, outputJSON bool) error {
	ctx := context.Background()

	loadAuthToEnv(ctx)

	apiKey := os.Getenv("DD_API_KEY")
	appKey := os.Getenv("DD_APP_KEY")
	site := os.Getenv("DD_SITE")
	if site == "" {
		site = "datadoghq.com"
	}

	if apiKey == "" || appKey == "" {
		return fmt.Errorf("DD_API_KEY and DD_APP_KEY are required for library scanning\n\nSet them via environment variables or run 'datadog-code-security-mcp dd-auth'")
	}

	libs := make([]libraryscan.Library, 0, len(purls))
	for _, p := range purls {
		if err := libraryscan.ValidatePURL(p); err != nil {
			return err
		}
		libs = append(libs, libraryscan.Library{Purl: p})
	}

	// Use working dir (or ".") for git context
	dir := workingDir
	if dir == "" {
		dir = "."
	}
	repoName, commitHash := libraryscan.DetectGitContext(ctx, dir)

	client := libraryscan.NewClient(apiKey, appKey, site)
	result, err := client.Scan(ctx, libraryscan.ScanRequest{
		Libraries:    libs,
		ResourceName: repoName,
		CommitHash:   commitHash,
	})
	if err != nil {
		return fmt.Errorf("library scan failed: %w", err)
	}

	if outputJSON {
		return outputLibraryScanJSON(result)
	}
	return outputLibraryScanHuman(result)
}

func outputLibraryScanJSON(result *libraryscan.ScanResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func outputLibraryScanHuman(result *libraryscan.ScanResult) error {
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║       Library Vulnerability Scan Results                      ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	if len(result.Findings) == 0 {
		fmt.Println("✅ No vulnerabilities found!")
		return nil
	}

	// Count by severity
	counts := map[string]int{}
	for _, f := range result.Findings {
		counts[strings.ToUpper(f.Severity)]++
	}

	fmt.Printf("Total Vulnerabilities: %d\n", len(result.Findings))
	fmt.Println()
	fmt.Println("Severity Breakdown:")
	for _, sev := range []string{types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow} {
		if c := counts[sev]; c > 0 {
			fmt.Printf("  %s %s: %d\n", getSeverityIcon(sev), sev, c)
		}
	}
	fmt.Println()

	fmt.Println("─────────────────────────────────────────────────────────────────")
	fmt.Println("Vulnerabilities:")
	fmt.Println("─────────────────────────────────────────────────────────────────")
	fmt.Println()

	for i, f := range result.Findings {
		icon := getSeverityIcon(strings.ToUpper(f.Severity))
		fmt.Printf("%d. %s [%s] %s\n", i+1, icon, strings.ToUpper(f.Severity), f.GHSAID)
		if f.CVE != "" {
			fmt.Printf("   CVE: %s\n", f.CVE)
		}
		fmt.Printf("   Library: %s @ %s\n", f.LibraryName, f.LibraryVersion)
		if f.Ecosystem != "" {
			fmt.Printf("   Ecosystem: %s (%s)\n", f.Ecosystem, f.Relation)
		}
		if f.LicenseID != "" {
			fmt.Printf("   License: %s\n", f.LicenseID)
		}
		if f.LatestVersion != "" && f.LatestVersion != f.LibraryVersion {
			fmt.Printf("   Latest version: %s\n", f.LatestVersion)
		}
		if f.RootParent != nil {
			fmt.Printf("   Root dependency: %s\n", *f.RootParent)
		}
		if f.CVSSScore > 0 {
			fmt.Printf("   CVSS Score: %.1f\n", f.CVSSScore)
		}
		if f.CVSSVector != "" {
			fmt.Printf("   CVSS Vector: %s\n", f.CVSSVector)
		}
		if f.DatadogScore > 0 {
			fmt.Printf("   Datadog Score: %.1f\n", f.DatadogScore)
		}
		if f.EPSSScore != nil {
			fmt.Printf("   EPSS Score: %.5f", *f.EPSSScore)
			if f.EPSSPercentile != nil {
				fmt.Printf(" (%.1f%% percentile)", *f.EPSSPercentile*100)
			}
			fmt.Println()
		}
		if f.Summary != "" {
			fmt.Printf("   Summary: %s\n", f.Summary)
		}
		if len(f.CWEs) > 0 {
			fmt.Printf("   CWEs: %s\n", strings.Join(f.CWEs, ", "))
		}
		if f.Reachability != "" {
			fmt.Printf("   Reachability: %s\n", f.Reachability)
		}
		if f.ClosestFixVersion != "" {
			fmt.Printf("   Closest safe version: %s\n", f.ClosestFixVersion)
		}
		if f.LatestFixVersion != "" {
			fmt.Printf("   Latest safe version: %s\n", f.LatestFixVersion)
		}
		if f.ExploitAvailable != nil && *f.ExploitAvailable {
			exploit := "   ⚠️  Exploit available"
			if f.ExploitPoC != nil && *f.ExploitPoC {
				exploit += " (PoC exists)"
			}
			if len(f.ExploitSources) > 0 {
				exploit += " — sources: " + strings.Join(f.ExploitSources, ", ")
			}
			fmt.Println(exploit)
		}
		if f.CISAAdded != nil {
			fmt.Printf("   🏛️  CISA KEV: added %s\n", *f.CISAAdded)
		}
		fmt.Println()
	}

	// Exit non-zero when vulnerabilities are found (consistent with other scan commands)
	os.Exit(1)
	return nil
}
