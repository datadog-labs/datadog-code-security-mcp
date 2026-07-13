package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/auth"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/libraryscan"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/scan"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/telemetry"
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
//
// TODO(refactor): this duplicates the credential-loading logic in auth.go's
// setAuthCredentials. Both should be consolidated into internal/auth so the CLI
// and MCP paths share a single implementation. Track in a follow-up PR.
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
	start := time.Now()

	loadAuthToEnv(ctx)
	scanType = strings.ToLower(scanType)

	// Validate that at least one path is provided
	if len(paths) == 0 {
		err := fmt.Errorf("%s scan requires at least one path to scan", scanType)
		trackCLIScan(ctx, scanType, nil, start, 0, outputJSON, err)
		return err
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
		err := fmt.Errorf("invalid scan type: %s (valid options: all, sast, secrets, sca, iac)", scanType)
		trackCLIScan(ctx, scanType, nil, start, len(paths), outputJSON, err)
		return err
	}

	// Execute scan
	result, err := scan.ExecuteScan(ctx, scanArgs)
	// Track before any os.Exit paths inside output funcs.
	trackCLIScan(ctx, scanType, result, start, len(scanArgs.FilePaths), outputJSON, err)
	if err != nil {
		return err
	}

	// Output results
	if outputJSON {
		return outputResultsJSON(result)
	}

	exitOne, err := outputResultsHuman(result, scanType)
	if exitOne {
		flushTelemetry()
		os.Exit(1)
	}
	return err
}

// trackCLIScan emits telemetry for a direct CLI scan invocation.
//
// Single scan type: emits one per-scan event (standalone=true).
// "all" (multi-type): emits the aggregate code_security_scan event enriched with
// scan_durations_breakdown and partial_errors_breakdown, then one per-scan event
// per executed type (standalone=false).
// Initialization errors (result==nil): emits only the aggregate event.
func trackCLIScan(ctx context.Context, scanType string, result *scan.ScanResult, start time.Time, pathsCount int, outputJSON bool, err error) {
	if telemetryClient == nil {
		return
	}
	outputFormat := "human"
	if outputJSON {
		outputFormat = "json"
	}

	base := map[string]any{
		"paths_count":   pathsCount,
		"output_format": outputFormat,
	}

	if scanType != "all" {
		// Standalone single-type scan: emit one per-scan event directly.
		var durationMS int64
		if result != nil && result.Durations != nil {
			durationMS = result.Durations[scanType]
		}
		emitPerScanEvent(ctx, telemetryClient, "cli", scanType, result, durationMS, true, base, err)
		return
	}

	// "scan all": generate a batch_id shared by the aggregate event and all per-scan
	// events so the entire batch can be isolated in dashboards/queries.
	batchID := uuid.New().String()

	// Aggregate event first.
	operation := "code_security_scan"
	totalDuration := time.Since(start).Milliseconds()
	attrs := telemetry.CommonAttrs()
	attrs["operation"] = operation
	attrs["interface"] = "cli"
	attrs["duration_ms"] = totalDuration
	attrs["success"] = err == nil
	attrs["paths_count"] = pathsCount
	attrs["output_format"] = outputFormat
	attrs["batch_id"] = batchID
	if result != nil {
		attrs["findings_count"] = result.Summary.Total
		attrs["scan_types_breakdown"] = result.Summary.ByDetectionType
		attrs["severity_breakdown"] = result.Summary.BySeverity
		attrs["partial_errors_count"] = len(result.Errors)
		if len(result.Durations) > 0 {
			attrs["scan_durations_breakdown"] = result.Durations
		}
		if len(result.Errors) > 0 {
			attrs["partial_errors_breakdown"] = buildErrorKindBreakdown(result)
		}
	}
	if err != nil {
		telemetryClient.TrackError(ctx, err, operation+" failed", attrs)
	} else {
		telemetryClient.TrackInfo(ctx, operation+" completed", attrs)
	}

	// Per-scan events for each executed scan type (standalone=false, same batch_id).
	if result != nil {
		base["batch_id"] = batchID
		emitPerScanEvents(ctx, telemetryClient, "cli", result, false, base)
	}
}

func outputResultsJSON(result *scan.ScanResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// outputResultsHuman prints scan results in human-readable form.
// It returns (true, nil) when violations were found so the caller can flush
// telemetry before calling os.Exit(1) — keeping output non-blocking.
func outputResultsHuman(result *scan.ScanResult, scanType string) (exitOne bool, err error) {
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
		return false, nil
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
	return result.Summary.Total > 0, nil
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

// TODO(refactor): the library scan orchestration here (PURL validation, auth
// loading, git context detection, API client construction) is largely duplicated
// in handlers.go's handleLibraryVulnerabilityScan. Extract the shared core into
// internal/libraryscan so both the CLI and MCP paths can reuse it. Track in a
// follow-up PR.
func runLibraryScan(purls []string, workingDir string, outputJSON bool) error {
	ctx := context.Background()
	start := time.Now()

	loadAuthToEnv(ctx)

	apiKey := os.Getenv("DD_API_KEY")
	appKey := os.Getenv("DD_APP_KEY")
	site := os.Getenv("DD_SITE")
	if site == "" {
		site = "datadoghq.com"
	}

	if apiKey == "" || appKey == "" {
		err := fmt.Errorf("DD_API_KEY and DD_APP_KEY are required for library scanning\n\nSet them via environment variables or run 'datadog-code-security-mcp dd-auth'")
		trackCLILibraryScan(ctx, len(purls), 0, start, err)
		return err
	}

	libs := make([]libraryscan.Library, 0, len(purls))
	for _, p := range purls {
		if err := libraryscan.ValidatePURL(p); err != nil {
			trackCLILibraryScan(ctx, len(purls), 0, start, err)
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
		trackCLILibraryScan(ctx, len(purls), 0, start, fmt.Errorf("library scan failed: %w", err))
		return fmt.Errorf("library scan failed: %w", err)
	}

	// Count total vulnerabilities for telemetry (before os.Exit in outputLibraryScanHuman).
	totalVulns := 0
	for _, lib := range result.Libraries {
		totalVulns += len(lib.Vulnerabilities)
	}
	trackCLILibraryScan(ctx, len(purls), totalVulns, start, nil)

	if outputJSON {
		return outputLibraryScanJSON(result)
	}

	exitOne, err := outputLibraryScanHuman(result)
	if exitOne {
		flushTelemetry()
		os.Exit(1)
	}
	return err
}

// trackCLILibraryScan emits a telemetry event for a library scan CLI invocation.
func trackCLILibraryScan(ctx context.Context, libCount, vulnCount int, start time.Time, err error) {
	if telemetryClient == nil {
		return
	}
	attrs := telemetry.CommonAttrs()
	attrs["operation"] = "library_scan"
	attrs["interface"] = "cli"
	attrs["duration_ms"] = time.Since(start).Milliseconds()
	attrs["success"] = err == nil
	attrs["libraries_count"] = libCount
	if err == nil {
		attrs["findings_count"] = vulnCount
	}
	if err != nil {
		telemetryClient.TrackError(ctx, err, "library scan failed", attrs)
	} else {
		telemetryClient.TrackInfo(ctx, "library scan completed", attrs)
	}
}

func outputLibraryScanJSON(result *libraryscan.ScanResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// outputLibraryScanHuman prints library scan results in human-readable form.
// It returns (true, nil) when vulnerabilities were found so the caller can
// flush telemetry before calling os.Exit(1).
func outputLibraryScanHuman(result *libraryscan.ScanResult) (exitOne bool, err error) {
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║       Library Vulnerability Scan Results                      ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Count total vulnerabilities and by severity
	totalVulns := 0
	counts := map[string]int{}
	for _, lib := range result.Libraries {
		for _, v := range lib.Vulnerabilities {
			totalVulns++
			counts[strings.ToUpper(v.Severity)]++
		}
	}

	if totalVulns == 0 {
		fmt.Println("✅ No vulnerabilities found!")
		fmt.Println()
		printLibrarySummaryTable(result.Libraries)
		return false, nil
	}

	fmt.Printf("Total Vulnerabilities: %d\n", totalVulns)
	fmt.Println()
	fmt.Println("Severity Breakdown:")
	for _, sev := range []string{types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow} {
		if c := counts[sev]; c > 0 {
			fmt.Printf("  %s %s: %d\n", getSeverityIcon(sev), sev, c)
		}
	}
	fmt.Println()
	printLibrarySummaryTable(result.Libraries)

	vulnIdx := 1
	for _, lib := range result.Libraries {
		if len(lib.Vulnerabilities) == 0 {
			continue
		}
		fmt.Println("─────────────────────────────────────────────────────────────────")
		fmt.Printf("📦 %s @ %s", lib.Name, lib.Version)
		if lib.Ecosystem != "" {
			fmt.Printf(" (%s", lib.Ecosystem)
			if lib.Relation != "" {
				fmt.Printf(", %s", lib.Relation)
			}
			fmt.Print(")")
		}
		if lib.LicenseID != "" {
			fmt.Printf(" [%s]", lib.LicenseID)
		}
		if lib.LatestVersion != "" && lib.LatestVersion != lib.Version {
			fmt.Printf(" — latest: %s", lib.LatestVersion)
		}
		if lib.RootParent != nil {
			fmt.Printf(" — root: %s", *lib.RootParent)
		}
		if len(lib.Risks) > 0 {
			fmt.Printf(" — risks: %s", strings.Join(lib.Risks, ", "))
		}
		vulnWord := "vulnerability"
		if len(lib.Vulnerabilities) != 1 {
			vulnWord = "vulnerabilities"
		}
		fmt.Printf(" — %d %s\n", len(lib.Vulnerabilities), vulnWord)
		fmt.Println("─────────────────────────────────────────────────────────────────")
		fmt.Println()

		for _, v := range lib.Vulnerabilities {
			icon := getSeverityIcon(strings.ToUpper(v.Severity))
			fmt.Printf("%d. %s [%s] %s\n", vulnIdx, icon, strings.ToUpper(v.Severity), v.GHSAID)
			vulnIdx++
			if v.CVE != "" {
				fmt.Printf("   CVE: %s\n", v.CVE)
			}
			if v.CVSSScore > 0 {
				fmt.Printf("   CVSS Score: %.1f\n", v.CVSSScore)
			}
			if v.CVSSVector != "" {
				fmt.Printf("   CVSS Vector: %s\n", v.CVSSVector)
			}
			if v.DatadogScore > 0 {
				fmt.Printf("   Datadog Score: %.1f\n", v.DatadogScore)
			}
			if v.EPSSScore != nil {
				if v.EPSSPercentile != nil {
					fmt.Printf("   EPSS Score: %.5f (%.1f%% percentile)\n", *v.EPSSScore, *v.EPSSPercentile*100)
				} else {
					fmt.Printf("   EPSS Score: %.5f\n", *v.EPSSScore)
				}
			}
			if v.Summary != "" {
				fmt.Printf("   Summary: %s\n", v.Summary)
			}
			if len(v.CWEs) > 0 {
				fmt.Printf("   CWEs: %s\n", strings.Join(v.CWEs, ", "))
			}
			if v.Reachability != "" {
				fmt.Printf("   Reachability: %s\n", v.Reachability)
			}
			if v.ClosestFixVersion != "" {
				fmt.Printf("   Closest safe version: %s\n", v.ClosestFixVersion)
			}
			if v.LatestFixVersion != "" {
				fmt.Printf("   Latest safe version: %s\n", v.LatestFixVersion)
			}
			if v.ExploitAvailable != nil && *v.ExploitAvailable {
				exploit := "   ⚠️  Exploit available"
				if v.ExploitPoC != nil && *v.ExploitPoC {
					exploit += " (PoC exists)"
				}
				if len(v.ExploitSources) > 0 {
					exploit += " — sources: " + strings.Join(v.ExploitSources, ", ")
				}
				fmt.Println(exploit)
				for _, u := range v.ExploitURLs {
					fmt.Printf("      %s\n", u)
				}
			}
			if v.CISAAdded != nil {
				fmt.Printf("   🏛️  CISA KEV: added %s\n", *v.CISAAdded)
			}
			fmt.Println()
		}
	}

	// Exit non-zero when vulnerabilities are found (consistent with other scan commands)
	return true, nil
}

// printLibrarySummaryTable prints a compact table of all scanned libraries.
func printLibrarySummaryTable(libraries []libraryscan.LibraryInfo) {
	if len(libraries) == 0 {
		return
	}
	fmt.Printf("Libraries Scanned: %d\n", len(libraries))
	fmt.Println()
	fmt.Printf("  %-40s %-12s %-12s %-12s %-10s %s\n", "Library", "Version", "Latest", "Ecosystem", "Relation", "Vulns")
	fmt.Printf("  %-40s %-12s %-12s %-12s %-10s %s\n",
		strings.Repeat("─", 40), strings.Repeat("─", 12), strings.Repeat("─", 12),
		strings.Repeat("─", 12), strings.Repeat("─", 10), strings.Repeat("─", 5))
	for _, lib := range libraries {
		latest := lib.LatestVersion
		if latest == "" || latest == lib.Version {
			latest = "—"
		}
		vulns := fmt.Sprintf("%d", len(lib.Vulnerabilities))
		if len(lib.Vulnerabilities) > 0 {
			vulns = "⚠️  " + vulns
		} else {
			vulns = "✅  0"
		}
		name := lib.Name
		if lib.EolDate != nil {
			name += " (EOL)"
		}
		fmt.Printf("  %-40s %-12s %-12s %-12s %-10s %s\n",
			name, lib.Version, latest, lib.Ecosystem, lib.Relation, vulns)
	}
	fmt.Println()
}
