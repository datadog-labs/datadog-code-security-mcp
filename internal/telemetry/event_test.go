package telemetry

import (
	"context"
	"fmt"
	"strings"
	"testing"
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
		raw         string
		wantKind    string
		wantMessage string
	}{
		{
			name:        "iac remote not found",
			raw:         "iac scanner execution failed: exit status 126 Output: Program failed: error retrieving repository commit information: error retrieving remote `origin`: remote not found",
			wantKind:    ErrKindGitError,
			wantMessage: "remote not found (exit status 126)",
		},
		{
			name:        "sbom unable to parse git ignores",
			raw:         `SBOM generation failed: SBOM generation error for path ".": scanner execution failed: exit status 127 stderr: Unable to parse git ignores: open /Users/alice/repo/.git/info/exclude: not a directory stdout:`,
			wantKind:    ErrKindGitError,
			wantMessage: "unable to parse .git (exit status 127)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := ErrorInfoFromError(fmt.Errorf("%s", tc.raw))
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
	}
	for _, tc := range cases {
		if got := CategorizeError(fmt.Errorf("%s", tc.msg)); got != tc.want {
			t.Errorf("CategorizeError(%q) = %q, want %q", tc.msg, got, tc.want)
		}
	}
}

func TestErrorInfoFromErrorRulesAPIReadFailure(t *testing.T) {
	// datadog-static-analyzer emits this when it cannot fetch rules from the
	// Datadog API — almost always caused by a rejected or missing API key.
	raw := "sast: detection failed: scanner execution failed: exit status 1\nstderr: Error: error when reading rules from API"
	info := ErrorInfoFromError(fmt.Errorf("%s", raw))
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
