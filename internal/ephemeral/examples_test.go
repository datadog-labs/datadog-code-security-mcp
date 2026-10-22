package ephemeral

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func sampleExamples() []Example {
	return []Example{
		{Filename: "compliant.go", Code: "package a\n", AnnotationCount: 0},
		{Filename: "noncompliant.go", Code: "package a\n", AnnotationCount: 1},
	}
}

// applyLines are the --debug lines the analyzer prints for the files it scans.
func applyLines(files ...string) string {
	lines := make([]string, len(files))
	for i, file := range files {
		lines[i] = "Apply rule security-variants/ephemeral file " + file
	}
	return strings.Join(lines, "\n")
}

func scanBothExamples(t *testing.T) {
	t.Setenv("DEBUG_LINES", applyLines("example-1/compliant.go", "example-2/noncompliant.go"))
}

func TestCheckExamplesAcceptsMatchingCounts(t *testing.T) {
	installFakeAnalyzer(t, "--rules-with-config",
		`[{"filename":"example-2/noncompliant.go","violations":[{"message":"found"}]}]`, "0")
	scanBothExamples(t)

	if err := CheckExamples(context.Background(), validInput(), sampleExamples()); err != nil {
		t.Fatalf("CheckExamples: %v", err)
	}
}

func TestCheckExamplesRejectsARuleThatFindsNothing(t *testing.T) {
	installFakeAnalyzer(t, "--rules-with-config", `[]`, "0")
	scanBothExamples(t)

	err := CheckExamples(context.Background(), validInput(), sampleExamples())
	var mismatch *ExampleMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("error = %v, want ExampleMismatchError", err)
	}
	if len(mismatch.Mismatches) != 1 || mismatch.Mismatches[0] != "noncompliant.go: expected 1, got 0" {
		t.Errorf("Mismatches = %v", mismatch.Mismatches)
	}
}

func TestCheckExamplesRejectsAFindingInTheCompliantExample(t *testing.T) {
	installFakeAnalyzer(t, "--rules-with-config", `[
  {"filename":"example-1/compliant.go","violations":[{"message":"found"}]},
  {"filename":"example-2/noncompliant.go","violations":[{"message":"found"}]}
]`, "0")
	scanBothExamples(t)

	err := CheckExamples(context.Background(), validInput(), sampleExamples())
	if err == nil || !strings.Contains(err.Error(), "compliant.go: expected 0, got 1") {
		t.Fatalf("error = %v, want the compliant mismatch", err)
	}
}

func TestCheckExamplesReportsAFailingRuleAsNotSaved(t *testing.T) {
	installFakeAnalyzer(t, "--rules-with-config", `[]`, "0")
	t.Setenv("DEBUG_LINES", "rule:file security-variants/ephemeral:example-2/noncompliant.go execution error, message: Uncaught TypeError: boom")

	err := CheckExamples(context.Background(), validInput(), sampleExamples())
	var failure *RuleFailureError
	if !errors.As(err, &failure) {
		t.Fatalf("error = %v, want RuleFailureError", err)
	}
	if !strings.HasPrefix(err.Error(), "the rule was not saved: ") || failure.Examples[0] != "noncompliant.go: TypeError: boom" {
		t.Errorf("error = %v", err)
	}
}

func TestCheckExamplesWithoutExamplesDoesNotScan(t *testing.T) {
	fake := installFakeAnalyzer(t, "--rules-with-config", `[]`, "0")

	if err := CheckExamples(context.Background(), validInput(), nil); err != nil {
		t.Fatalf("CheckExamples: %v", err)
	}
	if _, err := os.Stat(fake.argsFile); err == nil {
		t.Error("analyzer ran without examples")
	}
}

func TestCheckExamplesRejectsAPathAsFilename(t *testing.T) {
	installFakeAnalyzer(t, "--rules-with-config", `[]`, "0")

	examples := []Example{{Filename: "../escape.go", Code: "package a\n", AnnotationCount: 1}}
	err := CheckExamples(context.Background(), validInput(), examples)
	if err == nil || !strings.Contains(err.Error(), "must be a file name") {
		t.Fatalf("error = %v, want a file name error", err)
	}
}

func TestCheckExamplesRejectsAnExampleTheAnalyzerSkipped(t *testing.T) {
	installFakeAnalyzer(t, "--rules-with-config",
		`[{"filename":"example-2/noncompliant.go","violations":[{"message":"found"}]}]`, "0")
	t.Setenv("DEBUG_LINES", applyLines("example-2/noncompliant.go"))

	examples := sampleExamples()
	examples[0].Filename = "compliant.ts"
	err := CheckExamples(context.Background(), validInput(), examples)
	var mismatch *ExampleMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("error = %v, want ExampleMismatchError", err)
	}
	if len(mismatch.Mismatches) != 1 || !strings.HasPrefix(mismatch.Mismatches[0], "compliant.ts: not scanned") {
		t.Errorf("Mismatches = %v", mismatch.Mismatches)
	}
}

func TestCheckExamplesRejectsAFilenameWithSurroundingSpace(t *testing.T) {
	installFakeAnalyzer(t, "--rules-with-config", `[]`, "0")

	examples := sampleExamples()
	examples[0].Filename = "compliant.go "
	err := CheckExamples(context.Background(), validInput(), examples)
	if err == nil || !strings.Contains(err.Error(), "must be a file name") {
		t.Fatalf("error = %v, want a file name error", err)
	}
}
