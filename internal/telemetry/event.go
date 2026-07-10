package telemetry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
// Raw error messages are intentionally excluded to prevent file paths or other
// user-specific data from leaking into telemetry. Only the categorised kind
// and a scrubbed stack trace are sent.
type ErrorInfo struct {
	Kind  string `json:"kind"`
	Stack string `json:"stack,omitempty"`
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

// ErrorInfoFromError builds an ErrorInfo from an error, including a scrubbed stack trace.
// The raw error message is intentionally omitted to prevent file paths or other
// user-specific data from appearing in telemetry. Returns nil for a nil error.
func ErrorInfoFromError(err error) *ErrorInfo {
	if err == nil {
		return nil
	}
	return &ErrorInfo{
		Kind:  CategorizeError(err),
		Stack: scrubPaths(filterStack(string(debug.Stack()))),
	}
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
