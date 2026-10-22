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

func TestCheckExamplesAcceptsMatchingCounts(t *testing.T) {
	installFakeAnalyzer(t, "--rules-with-config",
		`[{"filename":"example-2/noncompliant.go","violations":[{"message":"found"}]}]`, "0")

	if err := CheckExamples(context.Background(), validInput(), sampleExamples()); err != nil {
		t.Fatalf("CheckExamples: %v", err)
	}
}

func TestCheckExamplesRejectsARuleThatFindsNothing(t *testing.T) {
	installFakeAnalyzer(t, "--rules-with-config", `[]`, "0")

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
	if err == nil || !strings.Contains(err.Error(), "single path segment") {
		t.Fatalf("error = %v, want single path segment", err)
	}
}
