package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/constants"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/libraryscan"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/sbom"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/scan"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/telemetry"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

// Generic handler that eliminates duplication across SAST/Secrets handlers
func handleAuthenticatedScan(ctx context.Context, request mcp.CallToolRequest, scanTypes []string) (*mcp.CallToolResult, error) {
	start := time.Now()
	operation := operationFromScanTypes(scanTypes)
	pathsCount := 0 // updated after successful arg parsing

	argsMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		err := fmt.Errorf(constants.ErrInvalidArguments)
		trackMCPScan(ctx, operation, scanTypes, nil, start, pathsCount, err)
		return errorResult(err), nil
	}

	args, err := parseScanArgs(argsMap)
	if err != nil {
		trackMCPScan(ctx, operation, scanTypes, nil, start, pathsCount, err)
		return errorResult(err), nil
	}
	pathsCount = len(args.FilePaths)

	// Authenticate
	if err := setAuthCredentials(ctx); err != nil {
		authErr := fmt.Errorf("%s: %v\n\n%s\n\n%s",
			constants.ErrAuthRequired, err,
			constants.AuthInstructionDDAuth,
			constants.AuthInstructionAPIKey)
		trackMCPScan(ctx, operation, scanTypes, nil, start, pathsCount, authErr)
		return errorResult(authErr), nil
	}

	if os.Getenv(constants.EnvAPIKey) == "" {
		authErr := fmt.Errorf("%s.\n\n%s\n\n%s",
			constants.ErrAPIKeyRequired,
			constants.AuthInstructionDDAuth,
			constants.AuthInstructionAPIKey)
		trackMCPScan(ctx, operation, scanTypes, nil, start, pathsCount, authErr)
		return errorResult(authErr), nil
	}

	// Execute scan
	args.ScanTypes = scanTypes
	result, err := scan.ExecuteScan(ctx, args)
	trackMCPScan(ctx, operation, scanTypes, result, start, pathsCount, err)
	if err != nil {
		return errorResult(err), nil
	}

	return formatScanResult(result), nil
}

func handleCodeSecurityScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return handleAuthenticatedScan(ctx, request, []string{string(types.DetectionTypeSAST), string(types.DetectionTypeSecrets), string(types.DetectionTypeSCA), string(types.DetectionTypeIaC)})
}

func handleSASTScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return handleAuthenticatedScan(ctx, request, []string{string(types.DetectionTypeSAST)})
}

func handleSecretsScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return handleAuthenticatedScan(ctx, request, []string{string(types.DetectionTypeSecrets)})
}

func handleGenerateSBOM(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	start := time.Now()

	argsMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		err := fmt.Errorf(constants.ErrInvalidArguments)
		trackMCPEvent(ctx, "generate_sbom", nil, start, err)
		return errorResult(err), nil
	}

	args, err := parseSBOMArgs(argsMap)
	if err != nil {
		trackMCPEvent(ctx, "generate_sbom", nil, start, err)
		return errorResult(err), nil
	}

	generator := sbom.NewGenerator()
	result, err := generator.Generate(ctx, args)
	if err != nil {
		trackMCPEvent(ctx, "generate_sbom", nil, start, err)
		return errorResult(err), nil
	}

	trackMCPEvent(ctx, "generate_sbom", map[string]any{
		"findings_count": result.Summary.TotalComponents,
	}, start, nil)
	return formatSBOMResult(result), nil
}

// handleSCAScan handles SCA (Software Composition Analysis) scan requests
// Redesigned to follow modular pattern: takes directories as input (like SAST/Secrets)
func handleSCAScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return handleAuthenticatedScan(ctx, request, []string{string(types.DetectionTypeSCA)})
}

// handleIaCScan handles Infrastructure-as-Code scan requests
func handleIaCScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return handleAuthenticatedScan(ctx, request, []string{string(types.DetectionTypeIaC)})
}

// parseScanArgs extracts scan arguments from MCP request
func parseScanArgs(arguments map[string]any) (scan.ScanArgs, error) {
	args := scan.ScanArgs{}

	// Parse file_paths
	if filePaths, ok := arguments[constants.ArgFilePaths].([]any); ok {
		for _, fp := range filePaths {
			if path, ok := fp.(string); ok {
				args.FilePaths = append(args.FilePaths, path)
			}
		}
	}

	if len(args.FilePaths) == 0 {
		return args, fmt.Errorf("file_paths is required and must be a non-empty array")
	}

	// Parse working_dir (optional)
	if wd, ok := arguments[constants.ArgWorkingDir].(string); ok && wd != "" {
		args.WorkingDir = wd
	} else {
		args.WorkingDir = constants.DefaultWorkingDir
	}

	return args, nil
}

// parseSBOMArgs extracts SBOM arguments from MCP request
func parseSBOMArgs(arguments map[string]any) (types.SBOMArgs, error) {
	args := types.SBOMArgs{}

	// Parse path (optional)
	if path, ok := arguments[constants.ArgPath].(string); ok && path != "" {
		args.Path = path
	} else {
		args.Path = constants.DefaultScanPath
	}

	// Parse working_dir (optional)
	if wd, ok := arguments[constants.ArgWorkingDir].(string); ok && wd != "" {
		args.WorkingDir = wd
	} else {
		args.WorkingDir = constants.DefaultWorkingDir
	}

	return args, nil
}

// TODO(refactor): the library scan orchestration here (PURL validation, auth
// loading, git context detection, API client construction) is largely duplicated
// in scan.go's runLibraryScan. Extract the shared core into internal/libraryscan
// so both the CLI and MCP paths can reuse it. Track in a follow-up PR.

// handleLibraryVulnerabilityScan scans specific libraries for vulnerabilities via the Datadog API.
func handleLibraryVulnerabilityScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	start := time.Now()

	argsMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		err := fmt.Errorf(constants.ErrInvalidArguments)
		trackMCPEvent(ctx, "library_scan", nil, start, err)
		return errorResult(err), nil
	}

	librariesRaw, ok := argsMap["libraries"].([]any)
	if !ok || len(librariesRaw) == 0 {
		err := fmt.Errorf("libraries is required and must be a non-empty array")
		trackMCPEvent(ctx, "library_scan", nil, start, err)
		return errorResult(err), nil
	}

	libs := make([]libraryscan.Library, 0, len(librariesRaw))
	for _, raw := range librariesRaw {
		libMap, ok := raw.(map[string]any)
		if !ok {
			err := fmt.Errorf("each library must be an object with at least a 'purl' field")
			trackMCPEvent(ctx, "library_scan", nil, start, err)
			return errorResult(err), nil
		}
		purl, ok := libMap["purl"].(string)
		if !ok || purl == "" {
			err := fmt.Errorf("each library must have a non-empty 'purl' field")
			trackMCPEvent(ctx, "library_scan", nil, start, err)
			return errorResult(err), nil
		}
		if err := libraryscan.ValidatePURL(purl); err != nil {
			trackMCPEvent(ctx, "library_scan", nil, start, err)
			return errorResult(err), nil
		}
		lib := libraryscan.Library{Purl: purl}
		if isDev, ok := libMap["is_dev"].(bool); ok {
			lib.IsDev = isDev
		}
		if isDirect, ok := libMap["is_direct"].(bool); ok {
			lib.IsDirect = isDirect
		}
		if pm, ok := libMap["package_manager"].(string); ok {
			lib.PackageManager = pm
		}
		libs = append(libs, lib)
	}

	// Require credentials — this scan always calls the Datadog cloud API
	if err := setAuthCredentials(ctx); err != nil {
		authErr := fmt.Errorf("%s: %v\n\n%s\n\n%s",
			constants.ErrAuthRequired, err,
			constants.AuthInstructionDDAuth,
			constants.AuthInstructionAPIKey)
		trackMCPEvent(ctx, "library_scan", nil, start, authErr)
		return errorResult(authErr), nil
	}

	apiKey := os.Getenv(constants.EnvAPIKey)
	appKey := os.Getenv(constants.EnvAPPKey)
	// DD_SITE was validated by LoadConfig at startup (whitelist + domain regex).
	// Re-reading from env here since setAuthCredentials may have updated it.
	site := os.Getenv(constants.EnvSite)
	if site == "" {
		site = "datadoghq.com"
	}

	// Both keys are required for the library scan cloud API (unlike SAST which only
	// needs DD_API_KEY locally). This check is a safeguard in case setAuthCredentials
	// partially configured the environment.
	if apiKey == "" || appKey == "" {
		authErr := fmt.Errorf("%s.\n\n%s\n\n%s",
			constants.ErrAPIKeyRequired,
			constants.AuthInstructionDDAuth,
			constants.AuthInstructionAPIKey)
		trackMCPEvent(ctx, "library_scan", nil, start, authErr)
		return errorResult(authErr), nil
	}

	workingDir := constants.DefaultWorkingDir
	if wd, ok := argsMap[constants.ArgWorkingDir].(string); ok && wd != "" {
		workingDir = filepath.Clean(wd)
	}
	repoName, commitHash := libraryscan.DetectGitContext(ctx, workingDir)

	client := libraryscan.NewClient(apiKey, appKey, site)
	result, err := client.Scan(ctx, libraryscan.ScanRequest{
		Libraries:    libs,
		ResourceName: repoName,
		CommitHash:   commitHash,
	})
	if err != nil {
		wrappedErr := fmt.Errorf("library scan failed: %w", err)
		trackMCPEvent(ctx, "library_scan", map[string]any{
			"libraries_count": len(libs),
		}, start, wrappedErr)
		return errorResult(wrappedErr), nil
	}

	totalVulns := 0
	for _, lib := range result.Libraries {
		totalVulns += len(lib.Vulnerabilities)
	}
	trackMCPEvent(ctx, "library_scan", map[string]any{
		"libraries_count": len(libs),
		"findings_count":  totalVulns,
	}, start, nil)
	return formatLibraryScanResult(result), nil
}

// trackMCPScan sends telemetry for a scan tool call.
//
// Single scan type: emits one per-scan event (standalone=true).
// Multiple scan types (scan all): emits the aggregate code_security_scan event
// enriched with scan_durations_breakdown and partial_errors_breakdown, then one
// per-scan event per executed type (standalone=false).
// Initialization errors (result==nil): emits only the aggregate event.
func trackMCPScan(ctx context.Context, operation string, scanTypes []string, result *scan.ScanResult, start time.Time, pathsCount int, err error) {
	if mcpTelemetryClient == nil {
		return
	}

	base := map[string]any{"paths_count": pathsCount}

	if len(scanTypes) == 1 {
		// Standalone single-type scan: emit one event directly.
		emitPerScanEvent(ctx, mcpTelemetryClient, "mcp", scanTypes[0], result, 0, true, base, err)
		return
	}

	// Multi-type (scan all): generate a batch_id shared by the aggregate event and
	// all per-scan events so the batch can be isolated in dashboards/queries.
	batchID := uuid.New().String()

	// Aggregate event first.
	totalDuration := time.Since(start).Milliseconds()
	attrs := telemetry.CommonAttrs()
	attrs["operation"] = operation
	attrs["interface"] = "mcp"
	attrs["scan_types"] = strings.Join(scanTypes, ",")
	attrs["duration_ms"] = totalDuration
	attrs["success"] = err == nil
	attrs["paths_count"] = pathsCount
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
		mcpTelemetryClient.TrackError(ctx, err, operation+" failed", attrs)
	} else {
		mcpTelemetryClient.TrackInfo(ctx, operation+" completed", attrs)
	}

	// Per-scan events for each executed scan type (standalone=false, same batch_id).
	if result != nil {
		base["batch_id"] = batchID
		emitPerScanEvents(ctx, mcpTelemetryClient, "mcp", result, false, base)
	}
}

// trackMCPEvent sends a telemetry event for non-scan MCP tool calls. Track is non-blocking.
func trackMCPEvent(ctx context.Context, operation string, extraAttrs map[string]any, start time.Time, err error) {
	if mcpTelemetryClient == nil {
		return
	}
	attrs := telemetry.CommonAttrs()
	attrs["operation"] = operation
	attrs["interface"] = "mcp"
	attrs["duration_ms"] = time.Since(start).Milliseconds()
	attrs["success"] = err == nil
	for k, v := range extraAttrs {
		attrs[k] = v
	}
	if err != nil {
		mcpTelemetryClient.TrackError(ctx, err, operation+" failed", attrs)
	} else {
		mcpTelemetryClient.TrackInfo(ctx, operation+" completed", attrs)
	}
}

// operationFromScanTypes returns a stable operation name for a given set of scan
// types. Single-type slices map to "<type>_scan"; any multi-type combination is
// treated as the full code-security scan, matching the CLI's "scan all" command.
func operationFromScanTypes(scanTypes []string) string {
	if len(scanTypes) == 1 {
		return scanTypes[0] + "_scan"
	}
	return "code_security_scan"
}

// canonicalScanOrder defines the stable order used when iterating scan types for
// per-scan events, ensuring deterministic event ordering in tests.
var canonicalScanOrder = []string{"sast", "secrets", "sca", "iac"}

// executedScanTypes returns the union of successful and failed scan types from
// result, ordered canonically (sast, secrets, sca, iac) for determinism.
func executedScanTypes(result *scan.ScanResult) []string {
	seen := make(map[string]bool)
	for dt := range result.Results {
		seen[string(dt)] = true
	}
	for _, e := range result.Errors {
		seen[e.DetectionType] = true
	}
	var out []string
	for _, st := range canonicalScanOrder {
		if seen[st] {
			out = append(out, st)
		}
	}
	// Any type not in canonical order (future-proofing) appended last.
	for st := range seen {
		if !contains(canonicalScanOrder, st) {
			out = append(out, st)
		}
	}
	return out
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// buildErrorKindBreakdown returns a map of {detectionType: errorKind} for failed
// scan types, using telemetry.CategorizeError. No raw error messages are included.
func buildErrorKindBreakdown(result *scan.ScanResult) map[string]string {
	breakdown := make(map[string]string, len(result.Errors))
	for _, e := range result.Errors {
		breakdown[e.DetectionType] = telemetry.CategorizeError(errors.New(e.Error))
	}
	return breakdown
}

// emitPerScanEvents emits one telemetry event per executed scan type in result.
// standalone=true for single-type invocations, false when part of a scan all.
// base contains extra attrs (e.g. paths_count, output_format) merged into each event.
func emitPerScanEvents(ctx context.Context, client *telemetry.Client, iface string, result *scan.ScanResult, standalone bool, base map[string]any) {
	for _, st := range executedScanTypes(result) {
		var scanErr error
		for _, e := range result.Errors {
			if e.DetectionType == st {
				scanErr = errors.New(e.Error)
				break
			}
		}
		var durationMS int64
		if result.Durations != nil {
			durationMS = result.Durations[st]
		}
		emitPerScanEvent(ctx, client, iface, st, result, durationMS, standalone, base, scanErr)
	}
}

// emitPerScanEvent sends a single per-scan telemetry event.
func emitPerScanEvent(ctx context.Context, client *telemetry.Client, iface, scanType string, result *scan.ScanResult, durationMS int64, standalone bool, base map[string]any, scanErr error) {
	operation := scanType + "_scan"
	attrs := telemetry.CommonAttrs()
	attrs["operation"] = operation
	attrs["interface"] = iface
	attrs["standalone"] = standalone
	attrs["duration_ms"] = durationMS
	attrs["success"] = scanErr == nil
	for k, v := range base {
		attrs[k] = v
	}
	if result != nil && scanErr == nil {
		violations := result.Results[types.DetectionType(scanType)]
		attrs["findings_count"] = len(violations)
		attrs["severity_breakdown"] = severityBreakdownFor(violations)
	}
	if scanErr != nil {
		client.TrackError(ctx, scanErr, operation+" failed", attrs)
	} else {
		client.TrackInfo(ctx, operation+" completed", attrs)
	}
}

// severityBreakdownFor counts violations by severity for a single scan type.
func severityBreakdownFor(violations []types.Violation) map[string]int {
	m := make(map[string]int)
	for _, v := range violations {
		m[v.Severity]++
	}
	return m
}
