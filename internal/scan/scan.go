package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

// ExecuteScan runs security scans on the specified files using the new modular architecture
func ExecuteScan(ctx context.Context, args ScanArgs) (*ScanResult, error) {
	// Validate inputs
	if err := validateScanArgs(args); err != nil {
		return nil, err
	}

	// Resolve working directory
	workingDir := args.WorkingDir
	if workingDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current working directory: %w", err)
		}
		workingDir = cwd
	}

	// Make working directory absolute
	absWorkingDir, err := filepath.Abs(workingDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve working directory: %w", err)
	}

	// Validate working directory exists
	if _, err := os.Stat(absWorkingDir); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("working directory does not exist: %s", absWorkingDir)
		}
		return nil, fmt.Errorf("failed to access working directory: %w", err)
	}

	// Parse, validate, and normalize scan types
	scanTypes, err := parseScanTypes(args.ScanTypes)
	if err != nil {
		return nil, err
	}

	// Default to all scan types if none specified
	if len(scanTypes) == 0 {
		scanTypes = []string{
			string(types.DetectionTypeSAST),
			string(types.DetectionTypeSecrets),
			string(types.DetectionTypeSCA),
			string(types.DetectionTypeIaC),
		}
	}

	// Validate file paths
	validatedPaths, err := validateFilePaths(args.FilePaths, absWorkingDir)
	if err != nil {
		return nil, err
	}

	// Update args with validated values
	args.WorkingDir = absWorkingDir
	args.FilePaths = validatedPaths
	args.ScanTypes = scanTypes

	// Validate all required binaries upfront
	if err := binary.ValidateScanBinaries(ctx, scanTypes); err != nil {
		return nil, fmt.Errorf("binary validation failed:\n\n%w", err)
	}

	// Execute parallel scans
	binMgr := binary.NewBinaryManager()
	result, err := ExecuteParallelScans(ctx, args, binMgr)
	if err != nil {
		return nil, fmt.Errorf("scan execution failed: %w\n\nTroubleshooting:\n- Ensure datadog-static-analyzer is installed and in PATH\n- Run 'datadog-static-analyzer --version' to verify installation\n- Check file paths are correct and accessible", err)
	}

	// If all scans failed and there are no findings, return the error
	if len(result.Errors) > 0 && result.Summary.Total == 0 && !result.PartialResult {
		return nil, fmt.Errorf("all scans failed:\n%s", formatErrors(result.Errors))
	}

	return result, nil
}

// formatErrors formats multiple scan errors into a single string
func formatErrors(errors []ScanError) string {
	var msgs []string
	for _, err := range errors {
		msg := fmt.Sprintf("- %s: %s", err.DetectionType, err.Error)
		if err.Hint != "" {
			msg += fmt.Sprintf("\n  Hint: %s", err.Hint)
		}
		msgs = append(msgs, msg)
	}
	return strings.Join(msgs, "\n")
}

// validateScanArgs validates the scan arguments
func validateScanArgs(args ScanArgs) error {
	if len(args.FilePaths) == 0 {
		return fmt.Errorf("file_paths is required and must not be empty")
	}

	// Validate file paths are not empty strings
	for i, path := range args.FilePaths {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("file_paths[%d] is empty", i)
		}
	}

	return nil
}

// parseScanTypes validates, normalizes, and deduplicates scan type strings.
func parseScanTypes(scanTypes []string) ([]string, error) {
	if len(scanTypes) == 0 {
		return nil, nil
	}

	var validated []string
	seen := make(map[string]bool)

	for _, st := range scanTypes {
		st = strings.ToLower(strings.TrimSpace(st))

		switch st {
		case "sast", "secrets", "sca", "iac":
			// valid
		default:
			return nil, fmt.Errorf("invalid scan_type: %s (valid options: sast, secrets, sca, iac)", st)
		}

		if !seen[st] {
			validated = append(validated, st)
			seen[st] = true
		}
	}

	return validated, nil
}

// validateFilePaths validates and resolves file paths relative to working directory
func validateFilePaths(filePaths []string, workingDir string) ([]string, error) {
	var validated []string

	for _, path := range filePaths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}

		// Make path absolute if it's relative
		var absPath string
		if filepath.IsAbs(path) {
			absPath = path
		} else {
			absPath = filepath.Join(workingDir, path)
		}

		// Clean path
		absPath = filepath.Clean(absPath)

		// Check if path exists
		_, err := os.Stat(absPath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("path does not exist: %s (resolved to: %s)", path, absPath)
			}
			return nil, fmt.Errorf("failed to access path %s: %w", path, err)
		}

		// Verify path is within or equal to working directory (security check)
		relPath, err := filepath.Rel(workingDir, absPath)
		if err != nil || strings.HasPrefix(relPath, "..") {
			return nil, fmt.Errorf("path %s is outside working directory %s", path, workingDir)
		}

		validated = append(validated, relPath)
	}

	if len(validated) == 0 {
		return nil, fmt.Errorf("no valid file paths provided")
	}

	return validated, nil
}
