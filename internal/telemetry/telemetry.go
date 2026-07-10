// Package telemetry provides anonymous usage telemetry for the
// datadog-code-security-mcp CLI and MCP server. It sends one log event per
// command/tool invocation to the Datadog browser-http-intake using a
// publicly-embeddable client token injected at build time.
//
// Privacy guarantees:
//   - No source code, file paths, scan findings, secrets, or user identifiers.
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
	token      string
	service    string
	installID  string
	sessionID  string // non-empty only in MCP mode
	env        string
	version    string
	baseURL    string // overridable for tests
	httpClient *http.Client
	wg         sync.WaitGroup
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
// many installs have broken config paths. No event is sent when config loads cleanly.
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
		token:      token,
		service:    constants.TelemetryService,
		installID:  result.config.InstallID,
		sessionID:  opts.SessionID,
		env:        opts.Env,
		version:    opts.Version,
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: httpTimeout},
	}

	// Emit a single warn event only when config errors were accumulated.
	// Uses context.Background() since no caller context is available at construction.
	if len(result.errors) > 0 {
		c.Track(context.Background(), Event{
			Status: StatusWarn,
			Attributes: map[string]any{
				"operation":     "telemetry_init_with_errors",
				"interface":     "cli",
				"config_errors": result.errors,
				"id_ephemeral":  result.idEphemeral,
			},
		})
	}

	return c
}

// newWithBaseURL creates a Client with an explicit base URL for tests.
func newWithBaseURL(opts Options, baseURL string) *Client {
	opts.BaseURL = baseURL
	return New(opts)
}

// Enabled reports whether telemetry is active (token present + not opted out).
func (c *Client) Enabled() bool {
	return c.enabled
}

// InstallID returns the persistent anonymous install identifier.
func (c *Client) InstallID() string {
	return c.installID
}

// Track sends a structured telemetry event. It is fully non-blocking: the HTTP
// POST runs in a goroutine so callers are never delayed. Call Flush() before
// process exit to drain the in-flight POST (see CLI wiring in main.go).
func (c *Client) Track(ctx context.Context, e Event) {
	if !c.enabled {
		return
	}
	obj := c.buildLogObject(e)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		_ = c.post(ctx, obj) // errors intentionally discarded
	}()
}

// Flush waits for any in-flight telemetry POST to finish, up to flushTimeout.
// Call this at CLI exit so the process does not terminate before the POST
// completes. In MCP server mode the server is long-lived, so Flush is a no-op.
func (c *Client) Flush() {
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

// TrackError is a convenience wrapper for error events. The err is categorized
// and its message + a stack trace are included in the error object.
func (c *Client) TrackError(ctx context.Context, err error, message string, attrs map[string]any) {
	c.Track(ctx, Event{
		Status:     StatusError,
		Message:    message,
		Err:        err,
		Attributes: attrs,
	})
}

// TrackRaw sends an event with a preassembled attributes blob (json.RawMessage).
// The blob is validated; if invalid it is silently dropped. Prefer the typed API.
func (c *Client) TrackRaw(ctx context.Context, status Status, message string, rawAttrs json.RawMessage) {
	if !c.enabled {
		return
	}
	if rawAttrs != nil && !json.Valid(rawAttrs) {
		fmt.Fprintf(os.Stderr, "[telemetry] TrackRaw: invalid JSON attributes, dropping event\n")
		return
	}

	var attrs map[string]any
	if rawAttrs != nil {
		if err := json.Unmarshal(rawAttrs, &attrs); err != nil {
			return
		}
	}

	c.Track(ctx, Event{
		Status:     status,
		Message:    message,
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

	// Merge caller-supplied attributes. These must not contain sensitive data.
	for k, v := range e.Attributes {
		if _, reserved := obj[k]; !reserved {
			obj[k] = v
		}
	}

	return obj
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
	defer func() { _ = resp.Body.Close() }()

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
	if os.Getenv("CI") != "" {
		attrs["ci"] = true
	}
	return attrs
}
