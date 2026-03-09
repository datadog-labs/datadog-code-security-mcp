package main

import (
	"context"
	"fmt"
	"os"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/constants"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/sbom"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/scan"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

// Generic handler that eliminates duplication across SAST/Secrets handlers
func handleAuthenticatedScan(ctx context.Context, request mcp.CallToolRequest, scanTypes []string) (*mcp.CallToolResult, error) {
	argsMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return errorResult(fmt.Errorf(constants.ErrInvalidArguments)), nil
	}

	args, err := parseScanArgs(argsMap)
	if err != nil {
		return errorResult(err), nil
	}

	// Authenticate
	if err := setAuthCredentials(ctx); err != nil {
		return errorResult(fmt.Errorf("%s: %v\n\n%s\n\n%s",
			constants.ErrAuthRequired, err,
			constants.AuthInstructionDDAuth,
			constants.AuthInstructionAPIKey)), nil
	}

	if os.Getenv(constants.EnvAPIKey) == "" {
		return errorResult(fmt.Errorf("%s.\n\n%s\n\n%s",
			constants.ErrAPIKeyRequired,
			constants.AuthInstructionDDAuth,
			constants.AuthInstructionAPIKey)), nil
	}

	// Execute scan
	args.ScanTypes = scanTypes
	result, err := scan.ExecuteScan(ctx, args)
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
	argsMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return errorResult(fmt.Errorf(constants.ErrInvalidArguments)), nil
	}

	args, err := parseSBOMArgs(argsMap)
	if err != nil {
		return errorResult(err), nil
	}

	generator := sbom.NewGenerator()
	result, err := generator.Generate(ctx, args)
	if err != nil {
		return errorResult(err), nil
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
