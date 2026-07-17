package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// captureServer returns a test HTTP server and a channel that receives the
// decoded JSON body of each request (one map per POST).
func captureServer(t *testing.T) (*httptest.Server, <-chan []map[string]any) {
	t.Helper()
	withTempHome(t)
	ch := make(chan []map[string]any, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var items []map[string]any
		if err := json.Unmarshal(body, &items); err != nil {
			t.Errorf("unmarshal body %q: %v", body, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ch <- items
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	return srv, ch
}

// newTestClient creates a Client pointing at srv with a known token.
func newTestClient(t *testing.T, srv *httptest.Server, extraOpts ...func(*Options)) *Client {
	t.Helper()
	opts := Options{
		CompiledToken: "test-token",
		Env:           "test",
		Version:       "0.0.0-test",
		BaseURL:       srv.URL,
	}
	for _, fn := range extraOpts {
		fn(&opts)
	}
	return newWithBaseURL(opts, srv.URL)
}

// waitEvent reads one item set from ch with a short timeout.
func waitEvent(t *testing.T, ch <-chan []map[string]any) []map[string]any {
	t.Helper()
	select {
	case items := <-ch:
		return items
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for telemetry event")
		return nil
	}
}

// TestTrackInfo_PayloadShape verifies the payload is a JSON array with required fields.
func TestTrackInfo_PayloadShape(t *testing.T) {
	srv, ch := captureServer(t)
	c := newTestClient(t, srv)

	c.TrackInfo(context.Background(), "hello", map[string]any{"operation": "sast_scan"})

	items := waitEvent(t, ch)
	if len(items) != 1 {
		t.Fatalf("expected 1 log item, got %d", len(items))
	}
	item := items[0]

	// Required fields.
	if item["service"] == nil {
		t.Error("missing service")
	}
	if item["status"] == nil {
		t.Error("missing status")
	}
	usr, ok := item["usr"].(map[string]any)
	if !ok || usr["id"] == "" {
		t.Error("missing usr.id")
	}
	if item["message"] != "hello" {
		t.Errorf("message = %v, want hello", item["message"])
	}
	// error must not be present on info events.
	if item["error"] != nil {
		t.Errorf("error field must be absent for info status, got %v", item["error"])
	}
}

func TestTrack_DetachesRequestCancellation(t *testing.T) {
	srv, ch := captureServer(t)
	c := newTestClient(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.TrackInfo(ctx, "request completed", map[string]any{"operation": "sast_scan"})
	c.Flush()

	items := waitEvent(t, ch)
	if len(items) != 1 || items[0]["message"] != "request completed" {
		t.Fatalf("event was lost after request cancellation: %v", items)
	}
}

func TestFirstRunSnapshotSurvivesNoticePersistence(t *testing.T) {
	srv, _ := captureServer(t)

	first := newTestClient(t, srv)
	if !first.IsFirstRun() {
		t.Fatal("first client should snapshot first-run state")
	}
	first.MaybeShowFirstRunNotice()
	if !first.IsFirstRun() {
		t.Fatal("persisting the notice must not mutate the current process snapshot")
	}

	second := newTestClient(t, srv)
	if second.IsFirstRun() {
		t.Fatal("subsequent process should observe persisted notice state")
	}
}

// TestTrackError_ErrorObject verifies the error object is present and correct.
func TestTrackError_ErrorObject(t *testing.T) {
	srv, ch := captureServer(t)
	c := newTestClient(t, srv)

	testErr := fmt.Errorf("scan failed: unexpected EOF")
	c.TrackError(context.Background(), testErr, "sast_scan failed", nil)

	items := waitEvent(t, ch)
	item := items[0]

	if item["status"] != "error" {
		t.Errorf("status = %v, want error", item["status"])
	}
	errObj, ok := item["error"].(map[string]any)
	if !ok {
		t.Fatal("error field missing or wrong type")
	}
	if errObj["kind"] == "" {
		t.Error("error.kind is empty")
	}
	// A curated, path-free description is emitted for Error Tracking, but the
	// raw error text must never appear.
	message, _ := errObj["message"].(string)
	if message == "" {
		t.Error("error.message should carry a curated description")
	}
	if strings.Contains(message, "unexpected EOF") {
		t.Errorf("error.message must not include raw error text, got %q", message)
	}
	if _, present := errObj["stack"]; present {
		t.Error("error.stack must not be included in telemetry")
	}
}

// TestTrackError_NoErrorOnInfo verifies the error field is absent for non-error events.
func TestTrackError_NoErrorOnInfo(t *testing.T) {
	srv, ch := captureServer(t)
	c := newTestClient(t, srv)

	c.TrackInfo(context.Background(), "ok", nil)

	items := waitEvent(t, ch)
	if items[0]["error"] != nil {
		t.Error("error field must be absent for info event")
	}
}

func TestTrackInfoCannotInjectErrorObject(t *testing.T) {
	srv, ch := captureServer(t)
	c := newTestClient(t, srv)

	c.TrackInfo(context.Background(), "ok", map[string]any{
		"error": map[string]any{
			"kind":    "Injected",
			"message": "/Users/alice/private/repo",
		},
		"error.kind":    "Injected",
		"error.message": "/Users/alice/private/repo",
	})

	items := waitEvent(t, ch)
	if _, present := items[0]["error"]; present {
		t.Error("caller-supplied error object must be discarded")
	}
	if _, present := items[0]["error.kind"]; present {
		t.Error("caller-supplied error.kind must be discarded")
	}
	if _, present := items[0]["error.message"]; present {
		t.Error("caller-supplied error.message must be discarded")
	}
}

// TestOptOut_NoTelemetryFlag verifies that --no-telemetry suppresses sends.
func TestOptOut_NoTelemetryFlag(t *testing.T) {
	srv, ch := captureServer(t)
	c := newTestClient(t, srv, func(o *Options) { o.NoTelemetry = true })

	c.TrackInfo(context.Background(), "should not send", nil)

	select {
	case <-ch:
		t.Error("telemetry was sent despite NoTelemetry=true")
	case <-time.After(200 * time.Millisecond):
		// correct: nothing sent
	}
}

// TestOptOut_DoNotTrack verifies the DO_NOT_TRACK env var is respected.
func TestOptOut_DoNotTrack(t *testing.T) {
	t.Setenv("DO_NOT_TRACK", "1")

	srv, ch := captureServer(t)
	c := newTestClient(t, srv)

	c.TrackInfo(context.Background(), "should not send", nil)

	select {
	case <-ch:
		t.Error("telemetry was sent despite DO_NOT_TRACK=1")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestOptOut_EnvDisabled verifies DD_CODE_SECURITY_TELEMETRY_DISABLED is respected.
func TestOptOut_EnvDisabled(t *testing.T) {
	t.Setenv("DD_CODE_SECURITY_TELEMETRY_DISABLED", "true")

	srv, ch := captureServer(t)
	c := newTestClient(t, srv)

	c.TrackInfo(context.Background(), "should not send", nil)

	select {
	case <-ch:
		t.Error("telemetry was sent despite DD_CODE_SECURITY_TELEMETRY_DISABLED=true")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestNoSensitiveFields verifies raw error messages never enter the payload.
func TestNoSensitiveFields(t *testing.T) {
	srv, ch := captureServer(t)
	c := newTestClient(t, srv)

	sensitiveMsg := "failed at /Users/alice/private/project/main.go"
	c.TrackError(context.Background(), fmt.Errorf("%s", sensitiveMsg), "", nil)

	items := waitEvent(t, ch)
	raw, _ := json.Marshal(items[0])
	rawStr := string(raw)

	if contains(rawStr, sensitiveMsg) || contains(rawStr, "/Users/alice") {
		t.Errorf("raw error message leaked into payload: %s", rawStr)
	}
}

// TestURLQueryParams verifies the intake URL contains required query parameters.
func TestURLQueryParams(t *testing.T) {
	withTempHome(t)
	urlCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlCh <- r.URL.String()
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	c := newWithBaseURL(Options{
		CompiledToken: "mytoken",
		Env:           "production",
		Version:       "1.2.3",
	}, srv.URL)

	c.TrackInfo(context.Background(), "url test", nil)

	var capturedURL string
	select {
	case capturedURL = <-urlCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for telemetry request")
	}

	if !contains(capturedURL, "dd-api-key=mytoken") {
		t.Errorf("dd-api-key missing from URL: %s", capturedURL)
	}
	if !contains(capturedURL, "ddsource=browser") {
		t.Errorf("ddsource missing from URL: %s", capturedURL)
	}
	if !contains(capturedURL, "team%3Ak9-iac") ||
		!contains(capturedURL, "version%3A1.2.3") ||
		!contains(capturedURL, "env%3Aproduction") {
		t.Errorf("ddtags missing or wrong in URL: %s", capturedURL)
	}
}

// TestSessionID_PresentInMCPMode verifies session_id appears when set.
func TestSessionID_PresentInMCPMode(t *testing.T) {
	srv, ch := captureServer(t)
	c := newTestClient(t, srv, func(o *Options) { o.SessionID = "test-session-123" })

	c.TrackInfo(context.Background(), "mcp event", nil)

	items := waitEvent(t, ch)
	if items[0]["session_id"] != "test-session-123" {
		t.Errorf("session_id missing or wrong: %v", items[0]["session_id"])
	}
}

// TestSessionID_AbsentInCLIMode verifies session_id is absent when not set.
func TestSessionID_AbsentInCLIMode(t *testing.T) {
	srv, ch := captureServer(t)
	c := newTestClient(t, srv) // no SessionID

	c.TrackInfo(context.Background(), "cli event", nil)

	items := waitEvent(t, ch)
	if _, ok := items[0]["session_id"]; ok {
		t.Error("session_id should be absent in CLI mode")
	}
}

// TestMessageOmittedWhenEmpty verifies message is absent when empty string.
func TestMessageOmittedWhenEmpty(t *testing.T) {
	srv, ch := captureServer(t)
	c := newTestClient(t, srv)

	c.Track(context.Background(), Event{Status: StatusInfo})

	items := waitEvent(t, ch)
	if _, ok := items[0]["message"]; ok {
		t.Error("message field should be omitted when empty")
	}
}

// TestTrackInfo_OperationFieldInPayload verifies that the "operation" attribute
// survives the round-trip to the intake (attrs are forwarded as top-level fields).
func TestTrackInfo_OperationFieldInPayload(t *testing.T) {
	srv, ch := captureServer(t)
	c := newTestClient(t, srv)

	c.TrackInfo(context.Background(), "scan done", map[string]any{"operation": "sast_scan"})

	items := waitEvent(t, ch)
	if items[0]["operation"] != "sast_scan" {
		t.Errorf("operation field = %v, want sast_scan", items[0]["operation"])
	}
}

// TestTrackOperation_NoticeAttr verifies that a curated notice on an operation
// event (e.g. a zero-component generate_sbom) is forwarded to the intake, and
// that it is omitted when empty.
func TestTrackOperation_NoticeAttr(t *testing.T) {
	srv, ch := captureServer(t)
	c := newTestClient(t, srv)

	c.TrackOperation(context.Background(), OperationEvent{
		Operation: "generate_sbom",
		Interface: InterfaceCLI,
		StartedAt: time.Now(),
		Notice:    "no components detected",
	})

	items := waitEvent(t, ch)
	if got := items[0]["notice"]; got != "no components detected" {
		t.Errorf("notice = %v, want %q", got, "no components detected")
	}

	c.TrackOperation(context.Background(), OperationEvent{
		Operation: "generate_sbom",
		Interface: InterfaceCLI,
		StartedAt: time.Now(),
	})

	items = waitEvent(t, ch)
	if _, ok := items[0]["notice"]; ok {
		t.Error("notice field should be omitted when empty")
	}
}

// TestTrackOperation_UsedBinaryVersions verifies that generate_sbom carries a
// used_binary_versions attribute scoped to only the SBOM generator, not the
// full binary_versions inventory.
func TestTrackOperation_UsedBinaryVersions(t *testing.T) {
	srv, ch := captureServer(t)
	c := newTestClient(t, srv)

	c.TrackOperation(context.Background(), OperationEvent{
		Operation: "generate_sbom",
		Interface: InterfaceCLI,
		StartedAt: time.Now(),
		ScanType:  "sbom",
		BinaryVersions: map[string]string{
			"sbom_generator":  "1.17.3",
			"static_analyzer": "0.8.9",
			"security_cli":    "0.0.10",
		},
	})

	items := waitEvent(t, ch)
	scoped, ok := items[0]["used_binary_versions"].(map[string]any)
	if !ok {
		t.Fatalf("used_binary_versions missing or wrong type: %v", items[0]["used_binary_versions"])
	}
	if len(scoped) != 1 || scoped["sbom_generator"] != "1.17.3" {
		t.Errorf("used_binary_versions = %v, want {sbom_generator: 1.17.3}", scoped)
	}
}

// TestTrackRenameContention_Emitted verifies that a contended-but-recovered
// config write (rename needed more than one attempt) produces a warn event
// carrying the attempt count and the OS dimension, so Windows write races are
// observable even when the retry loop recovers.
func TestTrackRenameContention_Emitted(t *testing.T) {
	srv, ch := captureServer(t)
	c := newTestClient(t, srv)

	c.trackRenameContention(context.Background(), 3)

	items := waitEvent(t, ch)
	if got := items[0]["operation"]; got != "telemetry_config_rename_contended" {
		t.Errorf("operation = %v, want telemetry_config_rename_contended", got)
	}
	if got := items[0]["config_rename_attempts"]; got != float64(3) {
		t.Errorf("config_rename_attempts = %v, want 3", got)
	}
	if items[0]["os"] == nil {
		t.Error("expected os attribute for Windows segmentation")
	}
	if items[0]["status"] != "warn" {
		t.Errorf("status = %v, want warn", items[0]["status"])
	}
}

// TestTrackRenameContention_NotEmittedOnCleanWrite verifies that a clean,
// single-attempt write produces no telemetry (no noise on the common path).
func TestTrackRenameContention_NotEmittedOnCleanWrite(t *testing.T) {
	srv, ch := captureServer(t)
	c := newTestClient(t, srv)

	c.trackRenameContention(context.Background(), 1)
	c.Flush()

	select {
	case items := <-ch:
		t.Fatalf("unexpected telemetry for a clean write: %v", items)
	case <-time.After(200 * time.Millisecond):
	}
}

func contains(s, sub string) bool {
	return strings.Contains(s, sub)
}

// compile-time check: ensure fmt is used (via fmt.Errorf in tests above).
var _ = fmt.Sprintf
