package telemetry

import (
	"context"
	"errors"
	"fmt"
	"regexp"
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
// Kind is always a categorized constant. Message is a short, hardcoded
// description so the error can be grouped in Datadog Error Tracking: a per-kind
// default, or a more specific curated string for known sub-cases (optionally
// suffixed with the process exit code). The raw error text is never emitted.
type ErrorInfo struct {
	Kind    string `json:"kind"`
	Message string `json:"message,omitempty"`
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
	ErrKindGitError         = "GitError"
	ErrKindUnknown          = "Unknown"
)

// kindDescriptions is the default, path-free error.message emitted for each
// kind so every error is groupable in Error Tracking. Rules may override it
// with a more specific curated string for known sub-cases.
var kindDescriptions = map[string]string{
	ErrKindBinaryNotFound:   "scanner binary not found",
	ErrKindAuthRequired:     "authentication required",
	ErrKindInvalidArguments: "invalid arguments",
	ErrKindPathNotFound:     "path not found",
	ErrKindTimeout:          "operation timed out",
	ErrKindScanError:        "scan execution failed",
	ErrKindNetwork:          "network error",
	ErrKindGitError:         "git error",
	ErrKindUnknown:          "unknown error",
}

// errorRule maps required substrings in the raw error text to a safe
// classification. A rule matches when every substring in contains is present.
// message, when set, overrides the per-kind default with a curated constant
// safe to emit as error.message.
type errorRule struct {
	kind     string
	contains []string
	message  string
}

func (r errorRule) matches(msg string) bool {
	for _, sub := range r.contains {
		if !strings.Contains(msg, sub) {
			return false
		}
	}
	return len(r.contains) > 0
}

// errorRules is evaluated in order; the first matching rule wins. More specific
// rules (e.g. Git failures surfaced by scanner subprocesses) come first so they
// are not swallowed by the broader ScanError fallback.
var errorRules = []errorRule{
	{kind: ErrKindGitError, contains: []string{"remote not found"}, message: "remote not found"},
	{kind: ErrKindGitError, contains: []string{"Unable to parse git ignores"}, message: "unable to parse .git"},

	{kind: ErrKindAuthRequired, contains: []string{constants.ErrAuthRequired}},
	{kind: ErrKindAuthRequired, contains: []string{constants.ErrAPIKeyRequired}},
	{kind: ErrKindAuthRequired, contains: []string{"Authentication required"}},
	{kind: ErrKindAuthRequired, contains: []string{"DD_API_KEY"}},
	// datadog-static-analyzer surfaces this when it cannot fetch rules from the
	// Datadog API — in practice almost always a rejected/missing API key.
	{kind: ErrKindAuthRequired, contains: []string{"error when reading rules from API"}, message: "failed to read security rules from API"},

	{kind: ErrKindBinaryNotFound, contains: []string{"not found in PATH"}},
	{kind: ErrKindBinaryNotFound, contains: []string{"executable file not found"}},
	{kind: ErrKindBinaryNotFound, contains: []string{"binary validation failed"}},

	{kind: ErrKindPathNotFound, contains: []string{"path does not exist"}},
	{kind: ErrKindPathNotFound, contains: []string{"no such file or directory"}},
	{kind: ErrKindPathNotFound, contains: []string{"cannot find the path"}},

	{kind: ErrKindInvalidArguments, contains: []string{constants.ErrInvalidArguments}},
	{kind: ErrKindInvalidArguments, contains: []string{"is required"}},
	{kind: ErrKindInvalidArguments, contains: []string{"invalid"}},
	{kind: ErrKindInvalidArguments, contains: []string{"must be"}},

	{kind: ErrKindNetwork, contains: []string{"connection refused"}},
	{kind: ErrKindNetwork, contains: []string{"no such host"}},
	{kind: ErrKindNetwork, contains: []string{"dial tcp"}},
	{kind: ErrKindNetwork, contains: []string{"network"}},

	// SCA scans generate an SBOM as their first step; when the generator finds
	// no dependency manifests it reports this via result.Error rather than a Go
	// error, but the SCA scanner re-wraps it into one (see internal/scan/sca.go).
	{kind: ErrKindScanError, contains: []string{"No components detected by datadog-sbom-generator"}, message: "no components detected by SBOM generator"},

	{kind: ErrKindScanError, contains: []string{"scan"}},
	{kind: ErrKindScanError, contains: []string{"failed"}},
}

var exitStatusRe = regexp.MustCompile(`exit status (\d+)`)

// errorClassification is the privacy-preserving projection of an error:
// a categorized kind and, for known errors, a curated safe message.
type errorClassification struct {
	kind    string
	message string
}

func classifyError(err error) errorClassification {
	if err == nil {
		return errorClassification{}
	}

	kind, override := matchErrorRule(err)
	message := override
	if message == "" {
		message = kindDescriptions[kind]
	}
	return errorClassification{kind: kind, message: decorateMessage(message, err.Error())}
}

// matchErrorRule resolves the error kind and any rule-specific message override.
func matchErrorRule(err error) (kind, message string) {
	// Typed / sentinel checks (prefer these).
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return ErrKindTimeout, ""
	}
	var netErr interface{ Timeout() bool }
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ErrKindTimeout, ""
	}

	msg := err.Error()
	for _, rule := range errorRules {
		if rule.matches(msg) {
			return rule.kind, rule.message
		}
	}
	return ErrKindUnknown, ""
}

// decorateMessage appends the process exit code to a curated message when the
// raw error carries one. It only ever combines constants we control with a
// numeric exit code, so no raw error text leaks into telemetry.
func decorateMessage(message, raw string) string {
	if message == "" {
		return ""
	}
	if m := exitStatusRe.FindStringSubmatch(raw); m != nil {
		return fmt.Sprintf("%s (exit status %s)", message, m[1])
	}
	return message
}

// CategorizeError maps an error to one of the ErrKind* constants.
func CategorizeError(err error) string {
	return classifyError(err).kind
}

// ErrorInfoFromError builds the telemetry error object: a categorized kind and
// a short curated description, so every error is groupable in Error Tracking.
func ErrorInfoFromError(err error) *ErrorInfo {
	if err == nil {
		return nil
	}
	c := classifyError(err)
	return &ErrorInfo{
		Kind:    c.kind,
		Message: c.message,
	}
}
