package scan

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/processing"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

const iacSARIFOutputFile = "datadog-iac-scanner-result.sarif"

// KICS-based exit codes used by datadog-iac-scanner:
//
//	0  = no findings
//	40 = LOW severity findings
//	50 = MEDIUM severity findings
//	60 = HIGH or CRITICAL severity findings
const (
	iacExitCodeLow    = 40
	iacExitCodeMedium = 50
	iacExitCodeHigh   = 60
)

type IaCScanner struct {
	binaryMgr *binary.BinaryManager
}

func NewIaCScanner(binMgr *binary.BinaryManager) *IaCScanner {
	return &IaCScanner{
		binaryMgr: binMgr,
	}
}

// Execute runs the IaC scan on the specified paths.
func (s *IaCScanner) Execute(ctx context.Context, args ScanArgs) ([]types.Violation, error) {
	scannerPath, err := s.binaryMgr.GetBinaryPath(ctx)
	if err != nil {
		return nil, err
	}

	// Create temp directory for SARIF output
	tempDir, err := os.MkdirTemp("", "iac-scan-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Build command arguments: datadog-iac-scanner scan -p <path> [-p <path>...] -o <outputdir>
	cmdArgs := []string{"scan"}
	for _, p := range args.FilePaths {
		var absPath string
		if filepath.IsAbs(p) {
			absPath = p
		} else {
			absPath = filepath.Join(args.WorkingDir, p)
		}
		cmdArgs = append(cmdArgs, "-p", absPath)
	}
	cmdArgs = append(cmdArgs, "-o", tempDir)

	// Execute the binary
	// no-dd-sa:go-security/command-injection - scannerPath is validated via exec.LookPath in GetBinaryPath(), not user-controlled
	cmd := exec.CommandContext(ctx, scannerPath, cmdArgs...)
	cmd.Dir = args.WorkingDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		// KICS-based scanner uses exit codes 40/50/60 for findings by severity
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			if exitCode == iacExitCodeLow || exitCode == iacExitCodeMedium || exitCode == iacExitCodeHigh {
				// Findings exist - continue to parse output
			} else {
				return nil, fmt.Errorf("iac scanner execution failed: %w\nOutput: %s", err, string(output))
			}
		} else {
			return nil, fmt.Errorf("iac scanner execution failed: %w\nOutput: %s", err, string(output))
		}
	}

	// Read the SARIF output file
	sarifPath := filepath.Join(tempDir, iacSARIFOutputFile)
	sarifData, err := os.ReadFile(sarifPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read IaC scanner SARIF output: %w", err)
	}

	// Parse SARIF using the shared parser
	violations, err := processing.ParseSARIF(sarifData, args.WorkingDir, types.DetectionTypeIaC)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IaC SARIF output: %w", err)
	}

	return violations, nil
}
