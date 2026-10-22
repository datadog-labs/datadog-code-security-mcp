package ephemeral

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
)

// DefaultScanTimeout bounds one ephemeral analyzer run.
const DefaultScanTimeout = 10 * time.Minute

// analyzerWaitDelay bounds the wait for the analyzer's output after it exits
// or is canceled.
const analyzerWaitDelay = 5 * time.Second

// rulesWithConfigFlag makes -r run only the supplied rules when the repository
// has a local or remote SAST configuration. The configuration's paths, file
// size, gitignore, and ruleset-configs settings still apply.
const rulesWithConfigFlag = "--rules-with-config"

// minAnalyzerVersion is the first datadog-static-analyzer release with
// rulesWithConfigFlag. Support is detected from --help, not from this value.
const minAnalyzerVersion = "0.9.10"

// ScanRequest is a local ephemeral scan. Directory is the repository root
// passed to datadog-static-analyzer -i. Paths, when set, are -u subdirectories
// and must resolve inside Directory.
type ScanRequest struct {
	Input
	Directory string
	Paths     []string
}

// ScanResult holds the scanner's JSON findings document.
type ScanResult struct {
	Findings json.RawMessage
}

// Scan builds the ruleset in a temp directory and runs datadog-static-analyzer
// with -r, --rules-with-config, and -b. It does not fetch Datadog rules and
// does not require API keys.
func Scan(ctx context.Context, req ScanRequest) (ScanResult, error) {
	result, _, err := scan(ctx, req, false)
	return result, err
}

// scan runs the analyzer. With trackScanned it also returns the files the rule
// ran on, relative to the directory.
func scan(ctx context.Context, req ScanRequest, trackScanned bool) (ScanResult, map[string]bool, error) {
	rules, err := BuildRulesJSON(req.Input)
	if err != nil {
		return ScanResult{}, nil, err
	}

	directory, paths, err := resolveTargets(req.Directory, req.Paths)
	if err != nil {
		return ScanResult{}, nil, err
	}

	manager := binary.NewBinaryManager()
	analyzer, err := manager.GetBinaryPath(ctx)
	if err != nil {
		return ScanResult{}, nil, err
	}
	supported, err := manager.SupportsFlag(ctx, analyzer, rulesWithConfigFlag)
	if err != nil {
		return ScanResult{}, nil, err
	}
	if !supported {
		return ScanResult{}, nil, manager.UpgradeRequiredError(rulesWithConfigFlag + " (added in " + minAnalyzerVersion + ", required for ephemeral SAST scans)")
	}

	tempDir, err := os.MkdirTemp("", "ephemeral-sast-")
	if err != nil {
		return ScanResult{}, nil, fmt.Errorf("temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	rulesPath := filepath.Join(tempDir, "rules.json")
	if err := os.WriteFile(rulesPath, append(rules, '\n'), 0o600); err != nil {
		return ScanResult{}, nil, fmt.Errorf("write rules: %w", err)
	}
	outputPath := filepath.Join(tempDir, "findings.json")

	ctx, cancel := context.WithTimeout(ctx, DefaultScanTimeout)
	defer cancel()

	// no-dd-sa:go-security/command-injection - analyzer comes from exec.LookPath and every path argument is resolved above
	cmd := exec.CommandContext(ctx, analyzer, analyzerArgs(rulesPath, directory, outputPath, paths)...)
	cmd.Dir = directory
	// Output goes to a Go writer, so Wait also waits for the pipes to close.
	// Bound that wait in case a child of the analyzer keeps them open.
	cmd.WaitDelay = analyzerWaitDelay
	log := newAnalyzerLog(ruleID(req.Input))
	if trackScanned {
		log.scanned = map[string]bool{}
	}
	cmd.Stdout = log
	cmd.Stderr = log
	runErr := cmd.Run()
	log.finish()
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return ScanResult{}, nil, fmt.Errorf("ephemeral scan timed out: %w", err)
		}
		return ScanResult{}, nil, fmt.Errorf("ephemeral scan canceled: %w", err)
	}

	data, readErr := os.ReadFile(outputPath)
	hasFindings := readErr == nil && len(bytes.TrimSpace(data)) > 0
	if hasFindings && !json.Valid(data) {
		return ScanResult{}, nil, &ScannerError{Err: errors.New("scanner wrote invalid JSON"), Log: log.String()}
	}
	if err := log.failure(); err != nil {
		return ScanResult{}, nil, err
	}
	if hasFindings {
		return ScanResult{Findings: json.RawMessage(data)}, log.scanned, nil
	}
	if runErr != nil {
		return ScanResult{}, nil, &ScannerError{Err: runErr, Log: log.String()}
	}
	if readErr != nil {
		return ScanResult{}, nil, &ScannerError{Err: fmt.Errorf("read scanner output: %w", readErr), Log: log.String()}
	}
	return ScanResult{Findings: json.RawMessage("[]")}, log.scanned, nil
}

// ScannerError means the analyzer exited with an error and wrote no findings.
// Log is the end of its output, which can quote the rule or the query.
type ScannerError struct {
	Err error
	Log string
}

func (e *ScannerError) Error() string {
	return fmt.Sprintf("scanner failed: %v\n%s", e.Err, e.Log)
}

func (e *ScannerError) Unwrap() error { return e.Err }

func analyzerArgs(rulesPath, directory, outputPath string, paths []string) []string {
	args := []string{
		"-r", rulesPath,
		rulesWithConfigFlag,
		"-b",
		"-i", directory,
		"-f", "json",
		"--output", outputPath,
		"--enable-static-analysis", "true",
		"--enable-secrets", "false",
	}
	args = append(args, debugFlag...)
	for _, path := range paths {
		args = append(args, "-u", path)
	}
	return args
}

// resolveTargets returns the absolute scan directory and each path relative to
// it. Empty directory means the current directory. A path that does not exist
// or resolves outside the directory is rejected.
func resolveTargets(directory string, paths []string) (string, []string, error) {
	if strings.TrimSpace(directory) == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", nil, fmt.Errorf("working directory: %w", err)
		}
		directory = cwd
	}
	root, err := filepath.Abs(filepath.Clean(directory))
	if err != nil {
		return "", nil, InvalidInput("invalid scan directory", "directory: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return "", nil, InvalidInput("invalid scan directory", "directory: %w", err)
	}
	if !info.IsDir() {
		return "", nil, InvalidInput("scan directory is not a directory", "directory %s is not a directory", root)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", nil, InvalidInput("invalid scan directory", "directory: %w", err)
	}

	var relative []string
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		target := path
		if !filepath.IsAbs(target) {
			target = filepath.Join(root, target)
		}
		// Check and pass the resolved target, so a symlink cannot point the
		// scan outside the directory. The same directory can also be spelled
		// two ways, such as /var and /private/var.
		target = filepath.Clean(target)
		resolved, err := filepath.EvalSymlinks(target)
		if err != nil {
			if _, ok := within(root, target); !ok {
				return "", nil, InvalidInput("path outside scan directory", "path %s is outside directory %s", path, root)
			}
			return "", nil, InvalidInput("invalid scan path", "path %s: %w", path, err)
		}
		rel, ok := within(resolvedRoot, resolved)
		if !ok {
			return "", nil, InvalidInput("path outside scan directory", "path %s is outside directory %s", path, root)
		}
		relative = append(relative, rel)
	}
	return root, relative, nil
}

// within returns target relative to root, and false when it is outside root.
func within(root, target string) (string, bool) {
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}
