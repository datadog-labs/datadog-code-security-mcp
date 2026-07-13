package telemetry

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestSanitizeErrorMessage_CollapsesAbsolutePaths verifies that absolute Unix
// and Windows paths are collapsed to ".../<basename>" so usernames, repo paths,
// and directory structure do not leak, while the surrounding message survives.
func TestSanitizeErrorMessage_CollapsesAbsolutePaths(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "unix path with trailing message",
			in:   "open /Users/alice/go/src/github.com/acme/repo/.git/info/exclude: not a directory",
			want: "open .../exclude: not a directory",
		},
		{
			name: "windows backslash path",
			in:   `cannot read C:\Users\alice\project\.git\config: access denied`,
			want: "cannot read .../config: access denied",
		},
		{
			name: "no path is unchanged",
			in:   "error retrieving remote `origin`: remote not found",
			want: "error retrieving remote `origin`: remote not found",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeErrorMessage(tc.in)
			if got != tc.want {
				t.Errorf("sanitizeErrorMessage(%q)\n  got  %q\n  want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestSanitizeErrorMessage_FlattensMultiline verifies that multi-line scanner
// dumps (stderr/stdout) are flattened to a single readable line and that the
// real failure reason on a later line survives (first-line-only would lose it).
func TestSanitizeErrorMessage_FlattensMultiline(t *testing.T) {
	in := "SBOM generation failed: scanner execution failed: exit status 127\nstderr: Unable to parse git ignores\nstdout: "
	got := sanitizeErrorMessage(in)

	if strings.ContainsAny(got, "\n\r\t") {
		t.Errorf("expected no raw whitespace control chars, got %q", got)
	}
	if !strings.Contains(got, "exit status 127") {
		t.Errorf("expected exit code to survive, got %q", got)
	}
	if !strings.Contains(got, "Unable to parse git ignores") {
		t.Errorf("expected the real reason from a later line to survive, got %q", got)
	}
}

// TestSanitizeErrorMessage_CapsLength verifies the message is capped and an
// ellipsis marker is appended when truncated.
func TestSanitizeErrorMessage_CapsLength(t *testing.T) {
	long := strings.Repeat("a", maxErrorMessageLen+50)
	got := sanitizeErrorMessage(long)

	runes := []rune(got)
	// maxErrorMessageLen runes + the single ellipsis rune.
	if len(runes) != maxErrorMessageLen+1 {
		t.Errorf("capped length = %d runes, want %d", len(runes), maxErrorMessageLen+1)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("expected truncation ellipsis suffix, got %q", got)
	}
}

// TestSanitizeErrorMessage_ScrubsHomeDir verifies the home directory is scrubbed
// even when a path is not in the standard absolute form the regex collapses
// (safety-net behaviour).
func TestSanitizeErrorMessage_ScrubsHomeDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("cannot determine home dir")
	}
	// Embed the home dir with no separators that would trigger path collapse
	// (append directly to a token) to exercise scrubPaths as the safety net.
	in := "config error near " + home
	got := sanitizeErrorMessage(in)

	if strings.Contains(got, home) {
		t.Errorf("home dir leaked: %q", got)
	}
}

// TestErrorInfoFromError_IncludesSanitizedMessage verifies the ErrorInfo built
// for an error carries a non-empty, sanitized message alongside the kind.
func TestErrorInfoFromError_IncludesSanitizedMessage(t *testing.T) {
	err := fmt.Errorf("iac scanner execution failed: exit status 126")
	info := ErrorInfoFromError(err)
	if info == nil {
		t.Fatal("expected non-nil ErrorInfo")
	}
	if info.Kind == "" {
		t.Error("expected a non-empty kind")
	}
	if info.Message == "" {
		t.Error("expected a non-empty sanitized message")
	}
	if !strings.Contains(info.Message, "exit status 126") {
		t.Errorf("expected message to retain the failure detail, got %q", info.Message)
	}
}

// TestErrorInfoFromError_NilReturnsNil guards the nil path.
func TestErrorInfoFromError_NilReturnsNil(t *testing.T) {
	if ErrorInfoFromError(nil) != nil {
		t.Error("expected nil ErrorInfo for nil error")
	}
}

// TestCategorizeError_KnownKinds verifies representative categorisation cases,
// including the auth error from the reported scan-all run.
func TestCategorizeError_KnownKinds(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"detection failed: scanner execution failed: exit status 1\nstderr: Error: Cannot find variable DD_API_KEY", ErrKindAuthRequired},
		{"datadog-static-analyzer not found in PATH", ErrKindBinaryNotFound},
		{"path does not exist: ./nope", ErrKindPathNotFound},
		{"scanner execution failed: exit status 127", ErrKindScanError},
	}
	for _, tc := range cases {
		got := CategorizeError(fmt.Errorf("%s", tc.msg))
		if got != tc.want {
			t.Errorf("CategorizeError(%q) = %q, want %q", tc.msg, got, tc.want)
		}
	}
}
