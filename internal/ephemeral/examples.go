package ephemeral

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Example is a file the rule must report exactly AnnotationCount times.
type Example struct {
	Filename        string
	Code            string
	AnnotationCount int
}

// ExampleMismatchError means the rule did not report the expected number of
// findings in at least one example.
type ExampleMismatchError struct {
	// Mismatches lists "file: expected N, got M" entries.
	Mismatches []string
}

func (e *ExampleMismatchError) Error() string {
	return "the rule does not match its examples, so it was not saved:\n" + strings.Join(e.Mismatches, "\n")
}

// CheckExamples scans each example with the rule and returns an
// ExampleMismatchError when a count differs from its AnnotationCount.
func CheckExamples(ctx context.Context, in Input, examples []Example) error {
	if len(examples) == 0 {
		return nil
	}
	dir, err := os.MkdirTemp("", "ephemeral-examples-")
	if err != nil {
		return fmt.Errorf("temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	paths := make([]string, len(examples))
	for i, example := range examples {
		name := filepath.Base(example.Filename)
		if name != example.Filename || name != strings.TrimSpace(name) || name == "." || name == ".." {
			return fmt.Errorf("example filename %q must be a file name without directories or surrounding spaces", example.Filename)
		}
		// Each example gets its own directory, so two examples may share a name.
		sub := fmt.Sprintf("example-%d", i+1)
		if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
			return fmt.Errorf("example directory: %w", err)
		}
		paths[i] = filepath.ToSlash(filepath.Join(sub, name))
		if err := os.WriteFile(filepath.Join(dir, sub, name), []byte(example.Code), 0o600); err != nil {
			return fmt.Errorf("write example: %w", err)
		}
	}

	result, scanned, err := scan(ctx, ScanRequest{Input: in, Directory: dir}, true)
	var failure *RuleFailureError
	if errors.As(err, &failure) {
		for i, entry := range failure.Examples {
			if cut := strings.IndexAny(entry, `/\`); cut >= 0 {
				failure.Examples[i] = entry[cut+1:]
			}
		}
		return fmt.Errorf("the rule was not saved: %w", failure)
	}
	if err != nil {
		return err
	}
	counts, err := countsByFile(result.Findings)
	if err != nil {
		return err
	}

	report := &ExampleMismatchError{}
	for i, example := range examples {
		// The analyzer skips files whose extension is not the rule's language,
		// and generated or minified files. Those would otherwise count as 0.
		if !scanned[paths[i]] {
			report.Mismatches = append(report.Mismatches,
				fmt.Sprintf("%s: not scanned; use a file extension for %s and code that is not generated or minified",
					example.Filename, strings.ToUpper(strings.TrimSpace(in.Language))))
			continue
		}
		if got := counts[paths[i]]; got != example.AnnotationCount {
			report.Mismatches = append(report.Mismatches,
				fmt.Sprintf("%s: expected %d, got %d", example.Filename, example.AnnotationCount, got))
		}
	}
	if len(report.Mismatches) > 0 {
		return report
	}
	return nil
}

func countsByFile(findings json.RawMessage) (map[string]int, error) {
	var results []struct {
		Filename   string            `json:"filename"`
		Violations []json.RawMessage `json:"violations"`
	}
	if err := json.Unmarshal(findings, &results); err != nil {
		return nil, fmt.Errorf("read scanner findings: %w", err)
	}
	counts := map[string]int{}
	for _, result := range results {
		counts[filepath.ToSlash(result.Filename)] += len(result.Violations)
	}
	return counts, nil
}
