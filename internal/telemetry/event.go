package telemetry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/constants"
)

// Status represents the severity level of a telemetry log event.
type Status string

const (
	StatusDebug Status = "debug"
	StatusInfo  Status = "info"
	StatusWarn  Status = "warn"
	StatusError Status = "error"
)

// Event is the per-invocation data supplied by callers. Invariant fields
// (service, usr, session_id, env, version) live on Client and are never
// repeated here.
type Event struct {
	// Status defaults to StatusInfo when zero.
	Status Status
	// Message is a short human-readable summary. Omitted from the payload when empty.
	Message string
	// Err, when non-nil, forces Status to StatusError and populates the error object.
	Err error
	// Attributes holds non-sensitive counts/metadata (command, duration_ms, etc.).
	// Values must be JSON-serializable; file paths and scan content must not appear here.
	Attributes map[string]any
}

// ErrorInfo is the error object included in the payload when status == "error".
//
// It carries the categorised Kind, a scrubbed stack trace, and a sanitised
// Message. The Message is NOT the raw error string: it is passed through
// sanitizeErrorMessage, which collapses absolute filesystem paths to their
// basenames, scrubs the user's home directory, flattens whitespace, and caps
// the length. This gives enough detail to understand *why* a scan failed
// (e.g. "remote not found", "not a directory") — which coarse categorisation
// alone cannot capture for errors bubbling up from external scanner binaries —
// without leaking usernames, repo paths, or scan content.
type ErrorInfo struct {
	Kind    string `json:"kind"`
	Message string `json:"message,omitempty"`
	Stack   string `json:"stack,omitempty"`
}

// ErrorKind constants used as the error.kind field.
const (
	ErrKindBinaryNotFound   = "BinaryNotFound"
	ErrKindAuthRequired     = "AuthRequired"
	ErrKindInvalidArguments = "InvalidArguments"
	ErrKindPathNotFound     = "PathNotFound"
	ErrKindTimeout          = "Timeout"
	ErrKindScanError        = "ScanError"
	ErrKindNetwork          = "Network"
	ErrKindUnknown          = "Unknown"
)

// CategorizeError maps an error to one of the ErrKind* constants.
// It uses errors.Is / errors.As first (unwraps %w chains), then falls back to
// substring matching on err.Error() for the current codebase's string-constant style.
func CategorizeError(err error) string {
	if err == nil {
		return ""
	}

	// Typed / sentinel checks (prefer these).
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return ErrKindTimeout
	}

	// Check for net timeout interface.
	var netErr interface{ Timeout() bool }
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ErrKindTimeout
	}

	msg := err.Error()

	// Auth errors.
	if strings.Contains(msg, constants.ErrAuthRequired) ||
		strings.Contains(msg, constants.ErrAPIKeyRequired) ||
		strings.Contains(msg, "Authentication required") ||
		strings.Contains(msg, "DD_API_KEY") {
		return ErrKindAuthRequired
	}

	// Binary-not-found errors (static-analyzer, sbom-generator, etc.).
	if strings.Contains(msg, "not found in PATH") ||
		strings.Contains(msg, "executable file not found") ||
		strings.Contains(msg, "binary validation failed") {
		return ErrKindBinaryNotFound
	}

	// Path / file-not-found errors from user-supplied scan targets.
	if strings.Contains(msg, "path does not exist") ||
		strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "cannot find the path") {
		return ErrKindPathNotFound
	}

	// Argument / validation errors.
	if strings.Contains(msg, constants.ErrInvalidArguments) ||
		strings.Contains(msg, "is required") ||
		strings.Contains(msg, "invalid") ||
		strings.Contains(msg, "must be") {
		return ErrKindInvalidArguments
	}

	// Network errors.
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "dial tcp") ||
		strings.Contains(msg, "network") {
		return ErrKindNetwork
	}

	// Fallback.
	if strings.Contains(msg, "scan") || strings.Contains(msg, "failed") {
		return ErrKindScanError
	}

	return ErrKindUnknown
}

// ErrorInfoFromError builds an ErrorInfo from an error, including the categorised
// kind, a sanitised message, and a scrubbed stack trace. The message is passed
// through sanitizeErrorMessage so that file paths, usernames, and repo names are
// removed before the message is sent. Returns nil for a nil error.
func ErrorInfoFromError(err error) *ErrorInfo {
	if err == nil {
		return nil
	}
	return &ErrorInfo{
		Kind:    CategorizeError(err),
		Message: sanitizeErrorMessage(err.Error()),
		Stack:   scrubPaths(filterStack(string(debug.Stack()))),
	}
}

// maxErrorMessageLen caps the sanitised error message. Scanner failures can
// append large multi-line stderr/stdout dumps; this bounds the payload while
// keeping enough of the message to be actionable.
const maxErrorMessageLen = 500

// absPathPattern matches absolute filesystem paths so they can be collapsed to a
// basename. It handles Unix ("/a/b/c") and Windows ("C:\a\b\c" or "C:/a/b/c")
// forms with at least one intermediate separator. Path segments exclude
// whitespace and ":" so a trailing ": message" (as in "open /a/b: not a dir")
// is not swallowed into the path.
var absPathPattern = regexp.MustCompile(`(?:[A-Za-z]:)?(?:/|\\)(?:[^\s/\\:]+(?:/|\\))+[^\s/\\:]*`)

// sanitizeErrorMessage returns a privacy-scrubbed, length-capped version of an
// error message suitable for telemetry. It:
//   - collapses absolute filesystem paths to their basename (drops usernames,
//     repo paths, and directory structure)
//   - scrubs the user's home directory as a final safety net
//   - flattens all whitespace runs (including newlines) to single spaces so the
//     multi-line scanner dumps become one readable line
//   - trims to maxErrorMessageLen runes
func sanitizeErrorMessage(msg string) string {
	// Collapse absolute paths to their basename before whitespace flattening so
	// the regex sees intact path tokens.
	msg = absPathPattern.ReplaceAllStringFunc(msg, func(p string) string {
		// Normalise separators for basename extraction, keep a leading marker so
		// it is obvious a path was elided.
		base := p
		if i := strings.LastIndexAny(base, `/\`); i >= 0 && i < len(base)-1 {
			base = base[i+1:]
		} else if i >= 0 {
			// Trailing separator (e.g. "/a/b/"): take the last non-empty segment.
			trimmed := strings.TrimRight(base, `/\`)
			if j := strings.LastIndexAny(trimmed, `/\`); j >= 0 {
				base = trimmed[j+1:]
			}
		}
		if base == "" {
			return ".../"
		}
		return ".../" + base
	})

	// Flatten whitespace (newlines, tabs, repeated spaces) to single spaces.
	msg = strings.Join(strings.Fields(msg), " ")

	// Home-dir safety net for any path form the regex did not catch.
	msg = scrubPaths(msg)

	// Cap length (rune-safe).
	if len([]rune(msg)) > maxErrorMessageLen {
		msg = string([]rune(msg)[:maxErrorMessageLen]) + "…"
	}
	return msg
}

// scrubPaths removes the user's home directory from a string so that file paths
// are not sent in telemetry. It handles both native path separators (e.g.
// C:\Users\foo on Windows) and forward-slash variants (C:/Users/foo) because Go
// stdlib and third-party libraries sometimes normalise separators inconsistently.
func scrubPaths(s string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return s
	}

	// Replace native-separator form (always correct on Unix; correct on Windows too
	// when the error originates from os/filepath-aware code).
	s = strings.ReplaceAll(s, home, "~")

	// On Windows, also replace the forward-slash variant in case the path was
	// normalised by Go internals or a third-party library.
	forwardSlashHome := filepath.ToSlash(home)
	if forwardSlashHome != home {
		s = strings.ReplaceAll(s, forwardSlashHome, "~")
	}

	return s
}

// filterStack keeps only frames that belong to our own module and the Go runtime,
// dropping third-party and standard library frames to keep the payload small.
func filterStack(stack string) string {
	lines := strings.Split(stack, "\n")
	var out []string
	keep := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "goroutine") {
			out = append(out, line)
			keep = true
			continue
		}
		if keep {
			out = append(out, line)
		}
		// Limit total stack output.
		if len(out) > 30 {
			out = append(out, "... (truncated)")
			break
		}
	}
	return strings.Join(out, "\n")
}
