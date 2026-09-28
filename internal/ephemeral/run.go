package ephemeral

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
)

// ScanRequest is a local ephemeral scan. Directory is the repository root
// passed to datadog-static-analyzer -i. Paths, when set, are -u subdirectories.
type ScanRequest struct {
	Input
	Directory string
	Paths     []string
}

// Scan runs the analyzer with -r and -b. It does not fetch Datadog rules and
// does not require API keys. Findings is the scanner's JSON document.
type ScanResult struct {
	Findings json.RawMessage
}

// Scan builds the envelope in a temp directory and runs datadog-static-analyzer.
func Scan(ctx context.Context, req ScanRequest) (ScanResult, error) {
	rules, err := BuildRulesJSON(req.Input)
	if err != nil {
		return ScanResult{}, err
	}

	directory := req.Directory
	if directory == "" {
		directory, err = os.Getwd()
		if err != nil {
			return ScanResult{}, fmt.Errorf("working directory: %w", err)
		}
	}
	info, err := os.Stat(directory)
	if err != nil {
		return ScanResult{}, fmt.Errorf("directory: %w", err)
	}
	if !info.IsDir() {
		return ScanResult{}, fmt.Errorf("directory %s is not a directory", directory)
	}

	analyzer, err := binary.NewBinaryManager().GetBinaryPath(ctx)
	if err != nil {
		return ScanResult{}, err
	}

	tempDir, err := os.MkdirTemp("", "ephemeral-sast-")
	if err != nil {
		return ScanResult{}, fmt.Errorf("temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	rulesPath := filepath.Join(tempDir, "rules.json")
	if err := os.WriteFile(rulesPath, append(rules, '\n'), 0o600); err != nil {
		return ScanResult{}, fmt.Errorf("write rules: %w", err)
	}
	outputPath := filepath.Join(tempDir, "findings.json")

	args := []string{
		"-r", rulesPath,
		"-b",
		"-i", directory,
		"-f", "json",
		"--output", outputPath,
		"--enable-static-analysis", "true",
		"--enable-secrets", "false",
	}
	for _, path := range req.Paths {
		if path == "" {
			continue
		}
		args = append(args, "-u", path)
	}

	cmd := exec.CommandContext(ctx, analyzer, args...)
	cmd.Dir = directory
	output, runErr := cmd.CombinedOutput()

	data, readErr := os.ReadFile(outputPath)
	if readErr == nil && len(bytes.TrimSpace(data)) > 0 {
		if !json.Valid(data) {
			return ScanResult{}, fmt.Errorf("scanner wrote invalid JSON: %s", truncate(output))
		}
		return ScanResult{Findings: json.RawMessage(data)}, nil
	}
	if runErr != nil {
		return ScanResult{}, fmt.Errorf("scanner failed: %w\n%s", runErr, truncate(output))
	}
	if readErr != nil {
		return ScanResult{}, fmt.Errorf("read scanner output: %w", readErr)
	}
	return ScanResult{Findings: json.RawMessage("[]")}, nil
}

func truncate(b []byte) string {
	const max = 2000
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "…"
}
