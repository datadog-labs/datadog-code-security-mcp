package ephemeral

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestScanReportsRuleFailures(t *testing.T) {
	installFakeAnalyzer(t, "--rules-with-config", `[{"filename":"src/ok.go","violations":[{"message":"real finding"}]}]`, "0")
	t.Setenv("DEBUG_LINES", strings.Join([]string{
		"use debug                 : true",
		"rule:file security-variants/ephemeral:src/b.go TIMED OUT (1999 ms)",
		"rule:file security-variants/ephemeral:src/a.go execution error, message: Uncaught TypeError: boom",
		"rule:file security-variants/ephemeral:src/a.go execution error, message: Uncaught TypeError: boom",
		"rule:file other/rule:src/c.go execution error, message: not this rule",
	}, "\n"))

	_, err := Scan(context.Background(), ScanRequest{Input: validInput(), Directory: t.TempDir()})
	var failure *RuleFailureError
	if !errors.As(err, &failure) {
		t.Fatalf("error = %v, want RuleFailureError", err)
	}
	want := []string{"src/a.go: TypeError: boom", "src/b.go: timed out (1999 ms)"}
	if failure.Files != 2 || strings.Join(failure.Examples, "|") != strings.Join(want, "|") {
		t.Errorf("failure = %+v, want 2 files %v", failure, want)
	}
}

func TestScanMatchesTheConfiguredRuleName(t *testing.T) {
	installFakeAnalyzer(t, "--rules-with-config", `[]`, "0")
	t.Setenv("DEBUG_LINES", "rule:file team:x/missing-guard:src/a.go execution error, message: SyntaxError: Unexpected token")

	input := validInput()
	input.RulesetName = "team:x"
	input.RuleName = "missing-guard"
	_, err := Scan(context.Background(), ScanRequest{Input: input, Directory: t.TempDir()})
	var failure *RuleFailureError
	if !errors.As(err, &failure) || failure.Examples[0] != "src/a.go: SyntaxError: Unexpected token" {
		t.Fatalf("error = %v, want the failure of team:x/missing-guard", err)
	}
}

func TestScanWithoutFailuresKeepsFindings(t *testing.T) {
	installFakeAnalyzer(t, "--rules-with-config", `[{"rule":"ephemeral"}]`, "0")
	t.Setenv("DEBUG_LINES", "Apply rule security-variants/ephemeral file src/a.go")

	result, err := Scan(context.Background(), ScanRequest{Input: validInput(), Directory: t.TempDir()})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if string(result.Findings) != `[{"rule":"ephemeral"}]` {
		t.Errorf("findings = %s", result.Findings)
	}
}

func TestAnalyzerLogParsesLinesAcrossWrites(t *testing.T) {
	log := newAnalyzerLog("security-variants/ephemeral")
	for _, chunk := range []string{
		"Apply rule security-variants/ephemeral file a.go\nrule:file security-vari",
		"ants/ephemeral:src/a.go execution error, message: Uncaught TypeError: boom\r\n",
		"rule:file security-variants/ephemeral:src/b.go TIMED OUT (1999 ms)",
	} {
		if _, err := log.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	log.flush()

	var failure *RuleFailureError
	if !errors.As(log.failure(), &failure) {
		t.Fatalf("failure = %v", log.failure())
	}
	want := "src/a.go: TypeError: boom|src/b.go: timed out (1999 ms)"
	if got := strings.Join(failure.Examples, "|"); got != want {
		t.Errorf("examples = %q, want %q", got, want)
	}
}

func TestAnalyzerLogBoundsMemory(t *testing.T) {
	log := newAnalyzerLog("security-variants/ephemeral")
	_, _ = log.Write([]byte(strings.Repeat("x", 2*maxLogLine)))
	_, _ = log.Write([]byte("\n" + strings.Repeat("é", maxLogTail) + "end"))
	log.flush()

	if len(log.line) != 0 || cap(log.line) > 2*maxLogLine {
		t.Errorf("line buffer len %d cap %d", len(log.line), cap(log.line))
	}
	tail := log.String()
	if !strings.HasPrefix(tail, "…") || !strings.HasSuffix(tail, "end") || !utf8.ValidString(tail) || len(tail) > maxLogTail+len("…") {
		t.Errorf("tail is %d bytes, valid UTF-8 %v", len(tail), utf8.ValidString(tail))
	}
	if log.failure() != nil {
		t.Errorf("failure = %v, want nil", log.failure())
	}
}

// TestRealAnalyzerReportsRuleFailures runs the installed analyzer when it
// supports --rules-with-config. CI covers the same cases in the E2E script.
func TestRealAnalyzerReportsRuleFailures(t *testing.T) {
	analyzer, err := exec.LookPath("datadog-static-analyzer")
	if err != nil {
		t.Skip("datadog-static-analyzer is not installed")
	}
	help, _ := exec.Command(analyzer, "--help").CombinedOutput()
	if !strings.Contains(string(help), rulesWithConfigFlag) {
		t.Skip("datadog-static-analyzer lacks " + rulesWithConfigFlag)
	}
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "main.go"), []byte("package main\n\nfunc main() { runUnchecked(\"x\") }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct{ code, reason string }{
		"throwing visitor": {`function visit(captures) { captures.get("call").missing.boom(); }`, "TypeError"},
		"state on this": {`function beforeAll() { this.calls = 0; }
function visit(captures) {}`, "TypeError"},
		"throwing initializer": {`const settings = undefined.limits;
function visit(captures) {}`, "TypeError"},
		"syntax error": {`function visit(captures) {`, "SyntaxError"},
		"no visit":     {`const settings = {};`, "ReferenceError"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			input := Input{
				RuleCode:        tc.code,
				TreeSitterQuery: `(call_expression function: (identifier) @callee (#eq? @callee "runUnchecked")) @call`,
				Language:        "GO",
			}
			_, err := Scan(context.Background(), ScanRequest{Input: input, Directory: repo})
			var failure *RuleFailureError
			if !errors.As(err, &failure) {
				t.Fatalf("error = %v, want RuleFailureError", err)
			}
			if failure.Files != 1 || !strings.HasPrefix(failure.Examples[0], "main.go: ") || !strings.Contains(failure.Examples[0], tc.reason) {
				t.Errorf("failure = %+v, want main.go with %s", failure, tc.reason)
			}
		})
	}
}

func TestRealAnalyzerChecksOnlyScannedExamples(t *testing.T) {
	analyzer, err := exec.LookPath("datadog-static-analyzer")
	if err != nil {
		t.Skip("datadog-static-analyzer is not installed")
	}
	help, _ := exec.Command(analyzer, "--help").CombinedOutput()
	if !strings.Contains(string(help), rulesWithConfigFlag) {
		t.Skip("datadog-static-analyzer lacks " + rulesWithConfigFlag)
	}
	input := Input{
		RuleCode: `function visit(captures) {
  const call = captures.get("call");
  addError(buildError(call.start.line, call.start.col, call.end.line, call.end.col, "unchecked"));
}`,
		TreeSitterQuery: `(call_expression function: (identifier) @callee (#eq? @callee "runUnchecked")) @call`,
		Language:        "GO",
	}
	examples := func(compliantName string) []Example {
		return []Example{
			{Filename: compliantName, Code: "package a\n\nfunc f() { runUnchecked(\"x\") }\n", AnnotationCount: 0},
			{Filename: "noncompliant.go", Code: "package a\n\nfunc f() { runUnchecked(\"x\") }\n", AnnotationCount: 1},
		}
	}

	err = CheckExamples(context.Background(), input, examples("compliant.go"))
	if err == nil || !strings.Contains(err.Error(), "compliant.go: expected 0, got 1") {
		t.Fatalf("scanned example: error = %v, want a count mismatch", err)
	}
	err = CheckExamples(context.Background(), input, examples("compliant.ts"))
	if err == nil || !strings.Contains(err.Error(), "compliant.ts: not scanned") {
		t.Fatalf("skipped example: error = %v, want not scanned", err)
	}
}
