// Package telemetry provides anonymous usage telemetry for the
// datadog-code-security-mcp CLI and MCP server. It sends one log event per
// scan type executed to the Datadog browser-http-intake using a
// publicly-embeddable client token injected at build time. A single-type
// invocation emits one event; a multi-type invocation (e.g. "scan all")
// emits one per-scan event per type plus an additional aggregate event
// summarizing the whole run — see docs/TELEMETRY.md for the full event model.
//
// Privacy guarantees:
//   - No source code, scan findings, secrets, or user identifiers.
//   - Error telemetry contains a categorized kind only; messages are never sent.
//   - Anonymous install_id (random UUID, stable per installation).
//   - Opt-out via --no-telemetry flag, DD_CODE_SECURITY_TELEMETRY_DISABLED=1,
//     DO_NOT_TRACK=1, or config file telemetry_enabled=false.
//   - Fire-and-forget: errors are swallowed and never affect scan results.
//   - Never writes to stdout (would corrupt MCP STDIO protocol).
package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/constants"
)

const (
	// intakeBaseURL is the Datadog browser-http-intake endpoint. The client token is
	// compiled in for a single org, so the site is always datadoghq.com.
	intakeBaseURL = "https://browser-http-intake.logs.datadoghq.com/api/v2/logs"

	// httpTimeout caps each individual HTTP POST. 2 s gives enough headroom
	// for DNS + TLS establishment on a cold connection to the intake endpoint
	// (a full TLS handshake can take 300–800 ms across a transatlantic link).
	httpTimeout = 2 * time.Second

	// flushTimeout is the maximum time Flush() will wait for an in-flight POST
	// to complete before giving up. Must exceed httpTimeout so that a timed-out
	// HTTP request always calls wg.Done() before Flush() abandons the wait.
	flushTimeout = 3 * time.Second
)

// Client holds all invariant telemetry fields resolved once at construction.
// Callers never re-pass usr/service/session_id/env/version.
//
// All Track* methods are non-blocking: the POST is dispatched in a goroutine.
// Call Flush() before process exit (CLI) to drain any in-flight POST.
type Client struct {
	enabled    bool
	firstRun   bool // true when this is the very first invocation on this machine
	token      string
	service    string
	installID  string
	sessionID  string // non-empty only in MCP mode
	env        string
	version    string
	baseURL    string // overridable for tests
	httpClient *http.Client
	wg         sync.WaitGroup
	noticeOnce sync.Once
}

// Options configures a Client at construction time.
type Options struct {
	// CompiledToken is the client token injected via ldflags at build time.
	CompiledToken string
	// Env is the deployment environment ("development" or "production"),
	// injected via ldflags at build time.
	Env string
	// Version is the CLI version string, injected via ldflags at build time.
	Version string
	// NoTelemetry reflects the --no-telemetry CLI flag.
	NoTelemetry bool
	// SessionID is set for MCP server mode (stable UUID for the server lifetime).
	// Leave empty for CLI mode.
	SessionID string
	// BaseURL overrides the intake URL (used in tests only).
	BaseURL string
}

// New constructs a Client, loading the persisted config (install_id, opt-out state)
// and resolving the token. All env reads happen here; Track* never re-reads env.
//
// If any config I/O errors occurred (e.g. permission denied writing config.json),
// a single warn event is emitted after construction so the team can track how
// many installs have broken config paths. Even on a clean (error-free) load, a
// telemetry_config_rename_contended signal is still emitted when the config write
// succeeded only after more than one atomic-rename attempt (write contention);
// a truly clean, uncontended load emits nothing.
func New(opts Options) *Client {
	result := loadOrCreateConfig()

	enabled := isEnabled(opts, result.config)
	token := resolveToken(opts.CompiledToken)

	baseURL := opts.BaseURL
	if baseURL == "" {
		baseURL = intakeBaseURL
	}

	c := &Client{
		enabled:    enabled && token != "",
		firstRun:   !result.config.FirstRunNoticeShown,
		token:      token,
		service:    constants.TelemetryService,
		installID:  result.config.InstallID,
		sessionID:  opts.SessionID,
		env:        opts.Env,
		version:    opts.Version,
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: httpTimeout},
	}

	// Surface config persistence problems (and Windows write contention) so the
	// team can track how many installs have broken or contended config paths.
	// Uses context.Background() since no caller context is available at construction.
	c.emitConfigResult(context.Background(), "telemetry_init_with_errors", result.errors, result.renameAttempts,
		map[string]any{"id_ephemeral": result.idEphemeral})

	return c
}

// iface returns the invocation interface for this client: MCP when a session ID
// is present (server mode), CLI otherwise.
func (c *Client) iface() Interface {
	if c.sessionID != "" {
		return InterfaceMCP
	}
	return InterfaceCLI
}

// emitConfigResult is the single reporting path for a config-persistence
// operation. When the operation carried categorized errors it emits one warn
// event (operation, config_errors, and — under contention — the rename-attempt
// count, plus any caller-specific extra attrs); when it succeeded it instead
// emits only the rename-contention signal, if any. Both New() and
// MaybeShowFirstRunNotice() funnel through here so the emission shape lives in
// one place. Attributes are counts/OS/kinds only — never paths or raw errors.
func (c *Client) emitConfigResult(ctx context.Context, operation string, errs []string, renameAttempts int, extra map[string]any) {
	if len(errs) == 0 {
		c.trackRenameContention(ctx, renameAttempts)
		return
	}
	attrs := CommonAttrs()
	attrs["operation"] = operation
	attrs["interface"] = string(c.iface())
	attrs["config_errors"] = errs
	if renameAttempts > 0 {
		attrs["config_rename_attempts"] = renameAttempts
	}
	for k, v := range extra {
		attrs[k] = v
	}
	c.Track(ctx, Event{Status: StatusWarn, Attributes: attrs})
}

// trackRenameContention emits a warn event when an atomic config write succeeded
// but needed more than one rename attempt. This is the leading indicator for
// cross-process write races (seen almost exclusively on Windows): the retry loop
// recovers, so no error is surfaced, and without this signal production telemetry
// would look silent even under heavy contention. Nothing is emitted for a clean,
// single-attempt write. Attributes are counts/OS only — no paths or raw errors.
func (c *Client) trackRenameContention(ctx context.Context, attempts int) {
	if attempts <= 1 {
		return
	}
	attrs := CommonAttrs()
	attrs["operation"] = "telemetry_config_rename_contended"
	attrs["interface"] = string(c.iface())
	attrs["config_rename_attempts"] = attempts
	c.Track(ctx, Event{Status: StatusWarn, Attributes: attrs})
}

// newWithBaseURL creates a Client with an explicit base URL for tests.
func newWithBaseURL(opts Options, baseURL string) *Client {
	opts.BaseURL = baseURL
	return New(opts)
}

// Enabled reports whether telemetry is active (token present + not opted out).
// A nil client is treated as disabled.
func (c *Client) Enabled() bool {
	return c != nil && c.enabled
}

// InstallID returns the persistent anonymous install identifier.
func (c *Client) InstallID() string {
	if c == nil {
		return ""
	}
	return c.installID
}

// IsFirstRun reports whether this is the first time the tool has been invoked
// on this machine (i.e. the first-run notice had not yet been shown when New()
// was called). The value is snapshotted at construction, before MaybeShowFirstRunNotice
// flips the persisted flag, so it reliably reflects the pre-invocation state.
func (c *Client) IsFirstRun() bool {
	return c != nil && c.firstRun
}

// Track sends a structured telemetry event. It is fully non-blocking: the HTTP
// POST runs in a goroutine so callers are never delayed. Call Flush() before
// process exit to drain the in-flight POST (see CLI wiring in main.go).
//
// A nil client is a no-op, so callers never need to nil-check before tracking.
func (c *Client) Track(ctx context.Context, e Event) {
	if c == nil || !c.enabled {
		return
	}
	obj := c.buildLogObject(e)
	postCtx := context.WithoutCancel(ctx)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		// Request cancellation must not discard an event after the handler
		// returns. The HTTP client's timeout still bounds delivery.
		_ = c.post(postCtx, obj) // errors intentionally discarded
	}()
}

// Flush waits for any in-flight telemetry POST to finish, up to flushTimeout.
// Call this before process exit so the process does not terminate mid-POST.
// In MCP server mode it typically returns immediately, because events emitted
// during the long-lived session have already completed by shutdown, but it
// still drains any final in-flight event. A nil client is a no-op.
func (c *Client) Flush() {
	if c == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(flushTimeout):
	}
}

// TrackInfo is a convenience wrapper for successful, informational events.
func (c *Client) TrackInfo(ctx context.Context, message string, attrs map[string]any) {
	c.Track(ctx, Event{
		Status:     StatusInfo,
		Message:    message,
		Attributes: attrs,
	})
}

// TrackError is a convenience wrapper for categorized error events.
func (c *Client) TrackError(ctx context.Context, err error, message string, attrs map[string]any) {
	c.Track(ctx, Event{
		Status:     StatusError,
		Message:    message,
		Err:        err,
		Attributes: attrs,
	})
}

// buildLogObject merges the client's invariant fields with the per-call event.
func (c *Client) buildLogObject(e Event) map[string]any {
	status := e.Status
	if status == "" {
		status = StatusInfo
	}

	var errInfo *ErrorInfo
	if e.Err != nil {
		status = StatusError
		errInfo = ErrorInfoFromError(e.Err)
	}

	obj := map[string]any{
		"service": c.service,
		"status":  string(status),
		"usr":     map[string]any{"id": c.installID},
	}

	if e.Message != "" {
		obj["message"] = e.Message
	}

	if errInfo != nil {
		obj["error"] = errInfo
	}

	if c.sessionID != "" {
		obj["session_id"] = c.sessionID
	}

	// Merge caller-supplied attributes without allowing them to override or
	// synthesize canonical envelope fields such as the structured error object.
	for k, v := range e.Attributes {
		if isReservedEventField(k) {
			continue
		}
		obj[k] = v
	}

	return obj
}

func isReservedEventField(key string) bool {
	if strings.HasPrefix(key, "error.") {
		return true
	}
	switch key {
	case "service", "status", "usr", "message", "error", "session_id":
		return true
	default:
		return false
	}
}

// post serialises obj as a one-element JSON array and POSTs it to the intake.
func (c *Client) post(ctx context.Context, obj map[string]any) error {
	body, err := json.Marshal([]map[string]any{obj})
	if err != nil {
		return fmt.Errorf("telemetry marshal: %w", err)
	}

	reqURL := c.buildURL()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telemetry new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("telemetry post: %w", err)
	}
	// Drain the (small, empty) intake response before closing so the transport
	// can reuse the keep-alive connection for subsequent events (matters most in
	// long-lived MCP mode). The client's Timeout still bounds the read.
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	return nil
}

// buildURL assembles the intake URL with required query parameters.
func (c *Client) buildURL() string {
	u, _ := url.Parse(c.baseURL)
	q := u.Query()
	q.Set("ddsource", constants.TelemetryDDSource)
	q.Set("dd-api-key", c.token)
	q.Set("ddtags", buildDDTags(c.version, c.env))
	u.RawQuery = q.Encode()
	return u.String()
}

// buildDDTags returns a comma-separated key:value tag string for the ddtags query param.
func buildDDTags(version, env string) string {
	var parts []string
	if version != "" {
		parts = append(parts, "version:"+version)
	}
	if env != "" {
		parts = append(parts, "env:"+env)
	}
	return strings.Join(parts, ",")
}

// resolveToken returns the compiled-in token if non-empty, otherwise falls back
// to the DD_CODE_SECURITY_TELEMETRY_TOKEN environment variable (dev/test use only).
func resolveToken(compiledToken string) string {
	if compiledToken != "" {
		return compiledToken
	}
	return os.Getenv(constants.EnvTelemetryToken)
}

// isEnabled determines whether telemetry should be active, checking all opt-out
// signals in priority order. All env reads happen here (called once at construction).
func isEnabled(opts Options, cfg persistedConfig) bool {
	// Flag takes highest precedence.
	if opts.NoTelemetry {
		return false
	}

	// Respect DO_NOT_TRACK standard (https://consoledonottrack.com/).
	if isTruthy(os.Getenv(constants.EnvDoNotTrack)) {
		return false
	}

	// Datadog-specific opt-out env var.
	if isTruthy(os.Getenv(constants.EnvTelemetryDisabled)) {
		return false
	}

	// Config file opt-out.
	if cfg.TelemetryEnabled != nil && !*cfg.TelemetryEnabled {
		return false
	}

	return true
}

// isTruthy returns true for "1", "true", "yes" (case-insensitive).
func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// CommonAttrs returns attributes that are the same for every event:
// OS, arch, Go version, and CI detection. Callers should merge additional
// per-invocation attributes into the returned map before passing to Track*.
func CommonAttrs() map[string]any {
	attrs := map[string]any{
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
		"go_version": runtime.Version(),
	}
	if os.Getenv(constants.EnvCI) != "" {
		attrs["ci"] = true
	}
	return attrs
}
