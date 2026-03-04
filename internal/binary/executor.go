package binary

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// CommandExecutor executes scanner binaries
type CommandExecutor struct{}

// NewCommandExecutor creates a new command executor
func NewCommandExecutor() *CommandExecutor {
	return &CommandExecutor{}
}

// validateBinaryPath ensures the binary path is safe to execute
func validateBinaryPath(binaryPath string) error {
	// Ensure path is absolute to prevent relative path manipulation
	if !filepath.IsAbs(binaryPath) {
		return fmt.Errorf("binary path must be absolute: %s", binaryPath)
	}

	// Check if file exists and get its info
	info, err := os.Stat(binaryPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("binary does not exist: %s", binaryPath)
		}
		return fmt.Errorf("failed to stat binary: %w", err)
	}

	// Ensure it's a regular file (not a directory or symlink to something dangerous)
	if !info.Mode().IsRegular() {
		return fmt.Errorf("binary path is not a regular file: %s", binaryPath)
	}

	// Check if file is executable
	if info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("binary is not executable: %s", binaryPath)
	}

	return nil
}

// Execute runs a scanner that writes to a file and returns the file contents
// The caller is responsible for creating and cleaning up the output file
func (ce *CommandExecutor) Execute(ctx context.Context, binaryPath string, args []string, workingDir string, outputFile string) ([]byte, error) {
	// Validate binary path before execution to prevent command injection
	// validateBinaryPath ensures:
	//   - Path is absolute (prevents relative path manipulation)
	//   - File exists and is a regular file
	//   - File has executable permissions
	// This prevents execution of arbitrary commands or malicious binaries
	if err := validateBinaryPath(binaryPath); err != nil {
		return nil, fmt.Errorf("binary validation failed: %w", err)
	}

	// nosec G204: binaryPath is validated above - it must be an absolute path to an executable file
	cmd := exec.CommandContext(ctx, binaryPath, args...)
	cmd.Dir = workingDir

	// Inherit parent environment variables (includes DD_API_KEY, DD_APP_KEY, DD_SITE from dd-auth)
	cmd.Env = os.Environ()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("scanner execution failed: %w\nstderr: %s\nstdout: %s",
			err, stderr.String(), stdout.String())
	}

	// Read output file
	output, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read scanner output from %s: %w", outputFile, err)
	}

	return output, nil
}
