package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	tracking := telemetry.ScanEvent{
		StartedAt:  time.Now(),
		AuthMethod: detectAuthMethod(),
	}
	defer func() { trackMCPScan(ctx, tracking) }()

	// fail records a pre-execution failure as the canonical outcome and returns
	// the MCP error result. The deferred emit above sends exactly one event.
	fail := func(err error) (*mcp.CallToolResult, error) {
		tracking.Outcome = scan.NewFailedOutcome(scanTypes, err)
		return errorResult(err), nil
	}

	argsMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return fail(fmt.Errorf(constants.ErrInvalidArguments))
	}

	args, err := parseScanArgs(argsMap)
	if err != nil {
		return fail(err)
	}
	tracking.PathsCount = len(args.FilePaths)
	tracking.WorkingDir = args.WorkingDir

	if err := setAuthCredentials(ctx); err != nil {
		return fail(fmt.Errorf("%s: %v\n\n%s\n\n%s",
			constants.ErrAuthRequired, err,
			constants.AuthInstructionDDAuth,
			constants.AuthInstructionAPIKey))
	}

	if os.Getenv(constants.EnvAPIKey) == "" {
		return fail(fmt.Errorf("%s.\n\n%s\n\n%s",
			constants.ErrAPIKeyRequired,
			constants.AuthInstructionDDAuth,
			constants.AuthInstructionAPIKey))
	}

	args.ScanTypes = scanTypes
	outcome := scan.ExecuteScan(ctx, args)
	tracking.Outcome = outcome
	if err := outcome.Err(); err != nil {
		return errorResult(err), nil
	}

	return formatScanResult(outcome.Result()), nil
}

func handleCodeSecurityScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return handleAuthenticatedScan(ctx, request, types.SecurityScanTypes())
}

func handleSASTScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return handleAuthenticatedScan(ctx, request, []string{string(types.DetectionTypeSAST)})
}

func handleSecretsScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return handleAuthenticatedScan(ctx, request, []string{string(types.DetectionTypeSecrets)})
}

func handleGenerateSBOM(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	event := telemetry.OperationEvent{
		Operation:  "generate_sbom",
		StartedAt:  time.Now(),
		AuthMethod: detectAuthMethod(),
		ScanType:   string(types.DetectionTypeSBOM),
	}
	defer func() { trackMCPEvent(ctx, event) }()

	fail := func(err error) (*mcp.CallToolResult, error) {
		event.Failure = err
		return errorResult(err), nil
	}

	argsMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return fail(fmt.Errorf(constants.ErrInvalidArguments))
	}

	args, err := parseSBOMArgs(argsMap)
	if err != nil {
		return fail(err)
	}

	generator := sbom.NewGenerator()
	result, err := generator.Generate(ctx, args)
	if err != nil {
		return fail(err)
	}

	findingsCount := result.Summary.TotalComponents
	event.FindingsCount = &findingsCount
	if result.Notice != nil {
		event.Notice = result.Notice.Message
	}
	// A non-nil result.Error means generation failed even though Generate
	// returned a nil Go error. Record it as a telemetry failure so these runs
	// aren't counted as successful. The raw text is only used by the telemetry
	// layer to pick a categorized kind; it never reaches the wire. The tool
	// response is unchanged — formatSBOMResult still surfaces the error.
	if result.Error != nil {
		event.Failure = errors.New(result.Error.Error)
	}
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

// parseLibraryArgs extracts and validates the libraries array from an MCP request.
func parseLibraryArgs(argsMap map[string]any) ([]libraryscan.Library, error) {
	librariesRaw, ok := argsMap["libraries"].([]any)
	if !ok || len(librariesRaw) == 0 {
		return nil, fmt.Errorf("libraries is required and must be a non-empty array")
	}

	libs := make([]libraryscan.Library, 0, len(librariesRaw))
	for _, raw := range librariesRaw {
		libMap, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("each library must be an object with at least a 'purl' field")
		}
		purl, ok := libMap["purl"].(string)
		if !ok || purl == "" {
			return nil, fmt.Errorf("each library must have a non-empty 'purl' field")
		}
		if err := libraryscan.ValidatePURL(purl); err != nil {
			return nil, err
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
	return libs, nil
}

// handleLibraryVulnerabilityScan scans specific libraries for vulnerabilities via the Datadog API.
func handleLibraryVulnerabilityScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	event := telemetry.OperationEvent{
		Operation:  "library_scan",
		StartedAt:  time.Now(),
		AuthMethod: detectAuthMethod(),
	}
	defer func() { trackMCPEvent(ctx, event) }()

	fail := func(err error) (*mcp.CallToolResult, error) {
		event.Failure = err
		return errorResult(err), nil
	}

	argsMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return fail(fmt.Errorf(constants.ErrInvalidArguments))
	}

	libs, err := parseLibraryArgs(argsMap)
	if err != nil {
		return fail(err)
	}

	// Require credentials — this scan always calls the Datadog cloud API
	if err := setAuthCredentials(ctx); err != nil {
		return fail(fmt.Errorf("%s: %v\n\n%s\n\n%s",
			constants.ErrAuthRequired, err,
			constants.AuthInstructionDDAuth,
			constants.AuthInstructionAPIKey))
	}

	apiKey := os.Getenv(constants.EnvAPIKey)
	appKey := os.Getenv(constants.EnvAPPKey)
	// DD_SITE was validated by LoadConfig at startup (whitelist + domain regex).
	// Re-reading from env here since setAuthCredentials may have updated it.
	site := os.Getenv(constants.EnvSite)

	// Both keys are required for the library scan cloud API (unlike SAST which only
	// needs DD_API_KEY locally). This check is a safeguard in case setAuthCredentials
	// partially configured the environment.
	if apiKey == "" || appKey == "" {
		return fail(fmt.Errorf("%s.\n\n%s\n\n%s",
			constants.ErrAPIKeyRequired,
			constants.AuthInstructionDDAuth,
			constants.AuthInstructionAPIKey))
	}

	workingDir := constants.DefaultWorkingDir
	if wd, ok := argsMap[constants.ArgWorkingDir].(string); ok && wd != "" {
		workingDir = filepath.Clean(wd)
	}

	// Library count is known once the run reaches the cloud API; recorded here so
	// both the failure and success events carry it (auth failures above do not).
	libraryCount := len(libs)
	event.LibrariesCount = &libraryCount
	result, totalVulns, err := libraryscan.Run(ctx, apiKey, appKey, site, workingDir, libs)
	if err != nil {
		return fail(fmt.Errorf("library scan failed: %w", err))
	}

	event.FindingsCount = &totalVulns
	return formatLibraryScanResult(result), nil
}
