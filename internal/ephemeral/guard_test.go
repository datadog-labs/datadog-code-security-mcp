package ephemeral

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanReportsRuleExceptions(t *testing.T) {
	findings := `[
  {"filename":"src/ok.go","violations":[{"message":"real finding"}]},
  {"filename":"src/a.go","violations":[{"message":"` + exceptionMarker + `TypeError: boom"}]},
  {"filename":"src/b.go","violations":[{"message":"` + exceptionMarker + `TypeError: boom"},{"message":"` + exceptionMarker + `TypeError: again"}]}
]`
	installFakeAnalyzer(t, "--rules-with-config", findings, "0")

	_, err := Scan(context.Background(), ScanRequest{Input: validInput(), Directory: t.TempDir()})
	var exception *RuleExceptionError
	if !errors.As(err, &exception) {
		t.Fatalf("error = %v, want RuleExceptionError", err)
	}
	if exception.Files != 2 {
		t.Errorf("Files = %d, want 2", exception.Files)
	}
	if want := "src/a.go: TypeError: boom"; len(exception.Examples) == 0 || exception.Examples[0] != want {
		t.Errorf("Examples = %v, want first %q", exception.Examples, want)
	}
}

func TestGuardRuleCodeKeepsTheRuleSource(t *testing.T) {
	source := "function visit(captures) { addError(1); }"
	guarded := guardRuleCode(source)
	for _, want := range []string{source, "var visit", "var beforeAll", "var afterAll", exceptionMarker} {
		if !strings.Contains(guarded, want) {
			t.Errorf("guarded rule is missing %q", want)
		}
	}
}

// TestRealAnalyzerReportsThrowingVisitor runs the installed analyzer when it
// supports --rules-with-config. CI covers the same case in the E2E script.
func TestRealAnalyzerReportsThrowingVisitor(t *testing.T) {
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
	input := Input{
		RuleCode:        `function visit(captures) { captures.get("call").missing.boom(); }`,
		TreeSitterQuery: `(call_expression function: (identifier) @callee (#eq? @callee "runUnchecked")) @call`,
		Language:        "GO",
	}

	_, err = Scan(context.Background(), ScanRequest{Input: input, Directory: repo})
	var exception *RuleExceptionError
	if !errors.As(err, &exception) {
		t.Fatalf("error = %v, want RuleExceptionError", err)
	}
	if exception.Files != 1 || !strings.Contains(exception.Examples[0], "main.go: TypeError") {
		t.Errorf("exception = %+v", exception)
	}
}
