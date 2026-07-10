package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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

// trackMCPScan sends a telemetry event for scan tool calls. Track is non-blocking.
func trackMCPScan(ctx context.Context, operation string, scanTypes []string, result *scan.ScanResult, start time.Time, pathsCount int, err error) {
	if mcpTelemetryClient == nil {
		return
	}
	attrs := telemetry.CommonAttrs()
	attrs["operation"] = operation
	attrs["interface"] = "mcp"
	attrs["scan_types"] = strings.Join(scanTypes, ",")
	attrs["duration_ms"] = time.Since(start).Milliseconds()
	attrs["success"] = err == nil
	attrs["paths_count"] = pathsCount
	if result != nil {
		attrs["findings_count"] = result.Summary.Total
		attrs["scan_types_breakdown"] = result.Summary.ByDetectionType
		attrs["severity_breakdown"] = result.Summary.BySeverity
		attrs["partial_errors_count"] = len(result.Errors)
	}
	if err != nil {
		mcpTelemetryClient.TrackError(ctx, err, operation+" failed", attrs)
	} else {
		mcpTelemetryClient.TrackInfo(ctx, operation+" completed", attrs)
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
