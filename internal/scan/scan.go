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
func ExecuteScan(ctx context.Context, args ScanArgs) *ScanOutcome {
	// Normalize requested types before any other fallible work so even
	// pre-execution failures retain the invocation's canonical scan set.
	scanTypes, err := parseScanTypes(args.ScanTypes)
	if err != nil {
		return NewFailedOutcome(args.ScanTypes, err)
	}
	if len(scanTypes) == 0 {
		scanTypes = types.SecurityScanTypes()
	}
	args.ScanTypes = scanTypes

	minSeverity, err := normalizeMinSeverity(args.MinSeverity)
	if err != nil {
		return NewFailedOutcome(scanTypes, err)
	}
	args.MinSeverity = minSeverity

	// Validate inputs
	if err := validateScanArgs(args); err != nil {
		return NewFailedOutcome(scanTypes, err)
	}

	// Resolve working directory
	workingDir := args.WorkingDir
	if workingDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return NewFailedOutcome(scanTypes, fmt.Errorf("failed to get current working directory: %w", err))
		}
		workingDir = cwd
	}

	// Make working directory absolute
	absWorkingDir, err := filepath.Abs(workingDir)
	if err != nil {
		return NewFailedOutcome(scanTypes, fmt.Errorf("failed to resolve working directory: %w", err))
	}

	// Validate working directory exists
	if _, err := os.Stat(absWorkingDir); err != nil {
		if os.IsNotExist(err) {
			return NewFailedOutcome(scanTypes, fmt.Errorf("working directory does not exist: %s", absWorkingDir))
		}
		return NewFailedOutcome(scanTypes, fmt.Errorf("failed to access working directory: %w", err))
	}

	// Validate file paths
	validatedPaths, err := validateFilePaths(args.FilePaths, absWorkingDir)
	if err != nil {
		return NewFailedOutcome(scanTypes, err)
	}

	// Update args with validated values
	args.WorkingDir = absWorkingDir
	args.FilePaths = validatedPaths

	// Validate all required binaries upfront
	if err := binary.ValidateScanBinaries(ctx, scanTypes); err != nil {
		return NewFailedOutcome(scanTypes, fmt.Errorf("binary validation failed:\n\n%w", err))
	}

	// Execute parallel scans
	binMgr := binary.NewBinaryManager()
	return ExecuteParallelScans(ctx, args, binMgr)
}

func allScansFailedError(errors []ScanError) error {
	var msgs []string
	for _, err := range errors {
		msg := fmt.Sprintf("- %s: %s", err.DetectionType, err.Error)
		if err.Hint != "" {
			msg += fmt.Sprintf("\n  Hint: %s", err.Hint)
		}
		msgs = append(msgs, msg)
	}
	return fmt.Errorf("all scans failed:\n%s", strings.Join(msgs, "\n"))
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

func normalizeMinSeverity(value string) (string, error) {
	severity := strings.ToUpper(strings.TrimSpace(value))
	if severity == "" {
		return types.SeverityLow, nil
	}
	if _, ok := types.SeverityOrder[severity]; !ok {
		return "", fmt.Errorf("invalid min_severity: %s (valid options: LOW, MEDIUM, HIGH, CRITICAL)", value)
	}
	return severity, nil
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
