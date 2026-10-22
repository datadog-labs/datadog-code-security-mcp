package telemetry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/ephemeral"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/promote"
)

func TestErrorInfoFromErrorHasCuratedMessage(t *testing.T) {
	info := ErrorInfoFromError(fmt.Errorf("scan failed at /Users/alice/private/repo"))
	if info == nil {
		t.Fatal("expected non-nil ErrorInfo")
	}
	if info.Kind == "" {
		t.Error("expected a non-empty kind")
	}
	// Every error carries a short description for Error Tracking, but it must be
	// the curated per-kind text, never the raw error content (e.g. paths).
	if info.Message == "" {
		t.Error("expected a non-empty curated message")
	}
	if strings.Contains(info.Message, "/Users/") || strings.Contains(info.Message, "alice") {
		t.Errorf("curated message leaked raw error content: %q", info.Message)
	}
}

func TestClassifyErrorAlwaysHasMessage(t *testing.T) {
	// A non-nil error must never produce an empty message, otherwise it would be
	// hard to surface in Error Tracking.
	errs := []error{
		fmt.Errorf("datadog-static-analyzer not found in PATH"),
		fmt.Errorf("Authentication required"),
		fmt.Errorf("path does not exist: ./nope"),
		fmt.Errorf("dial tcp: connection refused"),
		fmt.Errorf("something totally unrecognized"),
		context.DeadlineExceeded,
	}
	for _, err := range errs {
		if info := ErrorInfoFromError(err); info == nil || info.Message == "" {
			t.Errorf("ErrorInfoFromError(%v) produced empty message", err)
		}
	}
}

func TestErrorInfoFromErrorKnownGitErrors(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		wantKind    string
		wantMessage string
	}{
		{
			name:        "iac remote not found",
			err:         fmt.Errorf("iac scanner execution failed: %w\nOutput: Program failed: error retrieving repository commit information: error retrieving remote `origin`: remote not found", exitError(t, 126)),
			wantKind:    ErrKindGitError,
			wantMessage: "remote not found (exit status 126)",
		},
		{
			name:        "sbom unable to parse git ignores",
			err:         fmt.Errorf(`SBOM generation failed: SBOM generation error for path ".": scanner execution failed: %w stderr: Unable to parse git ignores: open /Users/alice/repo/.git/info/exclude: not a directory stdout:`, exitError(t, 127)),
			wantKind:    ErrKindGitError,
			wantMessage: "unable to parse .git (exit status 127)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := ErrorInfoFromError(tc.err)
			if info == nil {
				t.Fatal("expected non-nil ErrorInfo")
			}
			if info.Kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", info.Kind, tc.wantKind)
			}
			if info.Message != tc.wantMessage {
				t.Errorf("message = %q, want %q", info.Message, tc.wantMessage)
			}
			// The curated message must never echo raw error content such as paths.
			if strings.Contains(info.Message, "/Users/") || strings.Contains(info.Message, "origin") {
				t.Errorf("curated message leaked raw error content: %q", info.Message)
			}
		})
	}
}

// The rule writes these diagnostics, so digits in them are not an exit code
// and must not reach telemetry.
func TestClassifyErrorUsesTypesForCallerInput(t *testing.T) {
	const steer = "the rule failed in network DD_API_KEY remote not found exit status 4111111111111111"
	root := t.TempDir()
	file := filepath.Join(root, "file.txt")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	scan := func(directory string, paths ...string) error {
		_, err := ephemeral.Scan(context.Background(), ephemeral.ScanRequest{
			Input:     ephemeral.Input{RuleCode: "function visit() {}", TreeSitterQuery: "(identifier) @id", Language: "GO"},
			Directory: directory,
			Paths:     paths,
		})
		return err
	}
	_, languageErr := ephemeral.BuildRulesJSON(ephemeral.Input{RuleCode: "x", TreeSitterQuery: "x", Language: "dd_api_key " + steer})
	shortErr := promote.Validate(promote.Request{
		UserConfirmed: true, RuleCode: "function visit() {}", TreeSitterQuery: "(identifier) @id", Language: "GO",
		RuleName: "network-guard", ShortDescription: strings.Repeat("x", 61), Description: "long",
	})
	apiErr := func(status int) error {
		return &promote.APIError{Op: "create rule", Status: status, Body: steer}
	}

	cases := map[string]struct {
		err         error
		wantKind    string
		wantMessage string
	}{
		"unsupported language":     {languageErr, ErrKindInvalidArguments, "unsupported rule language"},
		"directory is a file":      {scan(file), ErrKindInvalidArguments, "scan directory is not a directory"},
		"path outside directory":   {scan(root, "../"+steer), ErrKindInvalidArguments, "path outside scan directory"},
		"missing path":             {scan(root, steer), ErrKindPathNotFound, "invalid scan path"},
		"short description":        {shortErr, ErrKindInvalidArguments, "short description too long"},
		"rule failure":             {fmt.Errorf("the rule was not saved: %w", &ephemeral.RuleFailureError{Files: 1, Examples: []string{"a.go: " + steer}}), ErrKindScanError, "rule failed"},
		"example mismatch":         {&ephemeral.ExampleMismatchError{Mismatches: []string{steer + ".go: expected 1, got 0"}}, ErrKindScanError, "rule does not match its examples"},
		"rule exists":              {&promote.RuleExistsError{RulesetName: "security-variants", RuleName: "network-guard"}, ErrKindInvalidArguments, "custom rule already exists"},
		"API forbidden":            {apiErr(403), ErrKindAuthRequired, "custom rule API returned status 403"},
		"API server error":         {apiErr(500), ErrKindScanError, "custom rule API returned status 500"},
		"empty rule after failure": {fmt.Errorf("%w\nThis call created the rule network-guard", apiErr(500)), ErrKindScanError, "custom rule API returned status 500"},
		"API unreachable":          {&promote.APIError{Op: "PUT request", Err: errors.New("dial tcp: lookup network-guard: " + steer)}, ErrKindNetwork, "custom rule API request failed"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if tc.err == nil {
				t.Fatal("no error to classify")
			}
			got := classifyError(tc.err)
			if got.kind != tc.wantKind || got.message != tc.wantMessage {
				t.Errorf("classifyError(%q) = %+v, want %s %q", tc.err, got, tc.wantKind, tc.wantMessage)
			}
		})
	}
}

func TestErrorInfoFromErrorNilReturnsNil(t *testing.T) {
	if ErrorInfoFromError(nil) != nil {
		t.Error("expected nil ErrorInfo for nil error")
	}
}

func TestCategorizeErrorKnownKinds(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"detection failed: scanner execution failed: exit status 1\nstderr: Error: Cannot find variable DD_API_KEY", ErrKindAuthRequired},
		{"sast: detection failed: scanner execution failed: exit status 1\nstderr: Error: error when reading rules from API", ErrKindAuthRequired},
		{"datadog-static-analyzer not found in PATH", ErrKindBinaryNotFound},
		{"path does not exist: ./nope", ErrKindPathNotFound},
		{"scanner execution failed: exit status 127", ErrKindScanError},
		{"error retrieving remote `origin`: remote not found", ErrKindGitError},
		{"Unable to parse git ignores: open .git/info/exclude: not a directory", ErrKindGitError},
		{"setup failed for: Agent Skills", ErrKindSetupError},
		{"resolve user home directory: HOME is not set", ErrKindSetupError},
		{`unsupported client "other" (valid options: agents, claude-code, codex)`, ErrKindInvalidArguments},
		{"invalid min_sast_severity: INFO (valid options: LOW, MEDIUM, HIGH, or CRITICAL)", ErrKindInvalidArguments},
		{"⚠️  PREREQUISITE REQUIRED: Scanner Upgrade\n\nThe installed 'datadog-static-analyzer' does not support --rules-with-config.\n\n# Add to PATH (if not already added):", ErrKindBinaryNotFound},
		{"scanner failed: exit status 3\nboom", ErrKindScanError},
		{"failed to run datadog-static-analyzer --help: signal: killed", ErrKindScanError}}
	for _, tc := range cases {
		if got := CategorizeError(fmt.Errorf("%s", tc.msg)); got != tc.want {
			t.Errorf("CategorizeError(%q) = %q, want %q", tc.msg, got, tc.want)
		}
	}
}

func TestErrorInfoFromErrorInvalidMinSASTSeverity(t *testing.T) {
	info := ErrorInfoFromError(fmt.Errorf("invalid min_sast_severity: INFO (valid options: LOW, MEDIUM, HIGH, or CRITICAL)"))
	if info == nil {
		t.Fatal("expected non-nil ErrorInfo")
	}
	if info.Kind != ErrKindInvalidArguments {
		t.Errorf("kind = %q, want %q", info.Kind, ErrKindInvalidArguments)
	}
	if info.Message != "invalid min_sast_severity" {
		t.Errorf("message = %q, want invalid min_sast_severity", info.Message)
	}
	if strings.Contains(info.Message, "INFO") {
		t.Errorf("curated message leaked user-provided severity: %q", info.Message)
	}
}

func TestCategorizeErrorWrappedNotExist(t *testing.T) {
	// Regression: a missing scan target produced by wrapping os.Stat's error
	// (e.g. the SBOM generator's "working_dir '...' does not exist or is not
	// accessible"). The human-readable phrasing matches no substring rule, so
	// before the typed fs.ErrNotExist check it fell through to Unknown. The
	// chain check must categorize it as PathNotFound regardless of wording.
	_, statErr := os.Stat(filepath.Join(t.TempDir(), "definitely-missing"))
	if statErr == nil {
		t.Fatal("expected os.Stat to fail on a missing path")
	}
	err := fmt.Errorf("sbom: working_dir '/some/path' does not exist or is not accessible: %w", statErr)

	if got := CategorizeError(err); got != ErrKindPathNotFound {
		t.Errorf("CategorizeError(wrapped fs.ErrNotExist) = %q, want %q", got, ErrKindPathNotFound)
	}
	info := ErrorInfoFromError(err)
	if info == nil || info.Message == "" {
		t.Fatal("expected a non-empty curated message")
	}
	// The curated message must not echo the raw wrapped path/error text.
	if strings.Contains(info.Message, "/some/path") || strings.Contains(info.Message, "definitely-missing") {
		t.Errorf("curated message leaked raw error content: %q", info.Message)
	}
}

func TestErrorInfoFromErrorRulesAPIReadFailure(t *testing.T) {
	// datadog-static-analyzer emits this when it cannot fetch rules from the
	// Datadog API — almost always caused by a rejected or missing API key.
	err := fmt.Errorf("sast: detection failed: scanner execution failed: %w\nstderr: Error: error when reading rules from API", exitError(t, 1))
	info := ErrorInfoFromError(err)
	if info == nil {
		t.Fatal("expected non-nil ErrorInfo")
	}
	if info.Kind != ErrKindAuthRequired {
		t.Errorf("kind = %q, want %q", info.Kind, ErrKindAuthRequired)
	}
	wantMessage := "failed to read security rules from API (exit status 1)"
	if info.Message != wantMessage {
		t.Errorf("message = %q, want %q", info.Message, wantMessage)
	}
}

func TestClassifyErrorIgnoresTheEphemeralScannerLog(t *testing.T) {
	err := fmt.Errorf("the rule was not saved: %w", &ephemeral.ScannerError{
		Err: exitError(t, 3),
		Log: "query: the rule failed in executable file not found exit status 9",
	})

	got := classifyError(err)
	if got.kind != ErrKindScanError || got.message != "ephemeral scanner failed (exit status 3)" {
		t.Errorf("classifyError = %+v", got)
	}
}

func TestClassifyErrorTakesTheExitCodeOnlyFromAProcess(t *testing.T) {
	const digits = "exit status 4111111111111111"
	_, pathErr := ephemeral.Scan(context.Background(), ephemeral.ScanRequest{
		Input:     ephemeral.Input{RuleCode: "function visit() {}", TreeSitterQuery: "(identifier) @id", Language: "GO"},
		Directory: t.TempDir(),
		Paths:     []string{"../" + digits},
	})
	ruleErr := promote.Validate(promote.Request{
		UserConfirmed: true, RuleCode: "function visit() {}", TreeSitterQuery: "(identifier) @id", Language: "GO",
		RuleName: digits, ShortDescription: "short", Description: "long",
	})
	cases := map[string]struct {
		err         error
		wantMessage string
	}{
		"rejected path":      {pathErr, "path outside scan directory"},
		"rejected rule name": {ruleErr, "invalid rule or ruleset name"},
		"process exit":       {fmt.Errorf("scanner execution failed: %w", exitError(t, 2)), kindDescriptions[ErrKindScanError] + " (exit status 2)"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if tc.err == nil || !strings.Contains(tc.err.Error(), digits) && name != "process exit" {
				t.Fatalf("error = %v, want one that quotes %q", tc.err, digits)
			}
			if got := classifyError(tc.err).message; got != tc.wantMessage {
				t.Errorf("message = %q, want %q", got, tc.wantMessage)
			}
		})
	}
}

// exitError runs the test binary as a helper that exits with code.
func exitError(t *testing.T, code int) error {
	t.Helper()
	cmd := configHelperCommand(t, t.TempDir(), "exit")
	cmd.Env = append(cmd.Env, "TELEMETRY_EXIT_CODE="+strconv.Itoa(code))
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != code {
		t.Fatalf("helper exit = %v, want exit status %d", err, code)
	}
	return err
}
