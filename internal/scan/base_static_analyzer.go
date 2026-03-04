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

// StaticAnalyzerConfig defines behavior differences between SAST and Secrets scanners
type StaticAnalyzerConfig struct {
	ScanType         string              // "sast" or "secrets" - scan type identifier
	TempDirPrefix    string              // Prefix for temp directory (e.g., "sast-scan-" or "secrets-scan-")
	EnableSAST       bool                // Whether to enable static analysis detection
	EnableSecrets    bool                // Whether to enable secrets detection
	DefaultDetection types.DetectionType // Default detection type for parsed findings
}

// BaseStaticAnalyzerScanner implements common logic for SAST and Secrets scanning
// Both scan types use the same datadog-static-analyzer binary but with different flags
type BaseStaticAnalyzerScanner struct {
	binaryMgr *binary.BinaryManager
	config    StaticAnalyzerConfig
}

// Execute runs detection (common workflow for both SAST and Secrets)
// This method implements the template method pattern:
// 1. Run detection (binary execution)
// 2. Parse SARIF output
// Subclass-specific behavior (like filtering) is handled by the calling scanner.
// Working directory resolution is handled by ExecuteScan before this is called.
func (s *BaseStaticAnalyzerScanner) Execute(ctx context.Context, args ScanArgs) ([]types.Violation, error) {
	rawSARIF, err := s.runDetection(ctx, args.FilePaths, args.WorkingDir)
	if err != nil {
		return nil, fmt.Errorf("detection failed: %w", err)
	}

	findings, err := s.parseSARIF(rawSARIF, args.WorkingDir)
	if err != nil {
		return nil, fmt.Errorf("parsing failed: %w", err)
	}

	return findings, nil
}

// runDetection calls the datadog-static-analyzer binary with config-specific flags
// The binary is shared between SAST and Secrets, but different flags control which analysis runs
func (s *BaseStaticAnalyzerScanner) runDetection(ctx context.Context, filePaths []string, workingDir string) ([]byte, error) {
	// Get binary path
	analyzerPath, err := s.binaryMgr.GetBinaryPath(ctx)
	if err != nil {
		return nil, err
	}

	// Create temp directory for output (mode 0700 - only owner can access)
	tempDir, err := os.MkdirTemp("", s.config.TempDirPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	outputPath := filepath.Join(tempDir, "output.sarif")

	// Build command arguments with config-driven flags
	args := []string{
		"-i", workingDir,
		"-f", "sarif",
		"--output", outputPath,
		"--enable-static-analysis", boolToString(s.config.EnableSAST),
		"--enable-secrets", boolToString(s.config.EnableSecrets),
	}

	// Add subdirectory flags for each file path
	for _, path := range filePaths {
		args = append(args, "-u", path)
	}

	// Execute command
	cmd := exec.CommandContext(ctx, analyzerPath, args...)
	cmd.Dir = workingDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it's just a non-zero exit (which happens when findings exist)
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit status 1 is normal (findings exist)
			if exitErr.ExitCode() == 1 {
				// Try to read the output file
				if data, readErr := os.ReadFile(outputPath); readErr == nil {
					return data, nil
				}
			}
		}
		return nil, fmt.Errorf("scanner execution failed: %w\nstderr: %s", err, output)
	}

	// Read the output file
	return os.ReadFile(outputPath)
}

// parseSARIF converts SARIF to violations using the shared parser
func (s *BaseStaticAnalyzerScanner) parseSARIF(rawSARIF []byte, workingDir string) ([]types.Violation, error) {
	return processing.ParseSARIF(rawSARIF, workingDir, s.config.DefaultDetection)
}

// boolToString converts boolean to "true"/"false" string for command-line flags
func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
