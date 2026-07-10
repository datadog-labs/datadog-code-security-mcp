package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/scan"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/telemetry"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

// captureCmdServer starts an httptest server and returns a channel that receives
// the first decoded log item from each POST body.
func captureCmdServer(t *testing.T) (*httptest.Server, <-chan map[string]any) {
	t.Helper()
	ch := make(chan map[string]any, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var items []map[string]any
		if err := json.Unmarshal(body, &items); err != nil || len(items) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ch <- items[0]
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	return srv, ch
}

// newCmdTestTelemetryClient creates an enabled telemetry.Client that posts to srv.
// It clears opt-out env vars so the client is reliably enabled.
func newCmdTestTelemetryClient(t *testing.T, srv *httptest.Server) *telemetry.Client {
	t.Helper()
	t.Setenv("DO_NOT_TRACK", "")
	t.Setenv("DD_CODE_SECURITY_TELEMETRY_DISABLED", "")
	return telemetry.New(telemetry.Options{
		CompiledToken: "test-token",
		Env:           "test",
		Version:       "0.0.0-test",
		BaseURL:       srv.URL,
	})
}

// waitCmdEvent reads one event from ch with a short timeout.
func waitCmdEvent(t *testing.T, ch <-chan map[string]any) map[string]any {
	t.Helper()
	select {
	case item := <-ch:
		return item
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for telemetry event")
		return nil
	}
}

// ── operationFromScanTypes ────────────────────────────────────────────────────

// TestOperationFromScanTypes verifies that stable, dashboard-friendly operation
// names are derived from the scan-types slice without brittle joining.
func TestOperationFromScanTypes(t *testing.T) {
	cases := []struct {
		scanTypes []string
		want      string
	}{
		{[]string{"sast"}, "sast_scan"},
		{[]string{"secrets"}, "secrets_scan"},
		{[]string{"sca"}, "sca_scan"},
		{[]string{"iac"}, "iac_scan"},
		// All four types → full code-security operation (matches CLI "scan all").
		{[]string{"sast", "secrets", "sca", "iac"}, "code_security_scan"},
		// Any multi-type slice → code_security_scan, regardless of count.
		{[]string{"sast", "secrets"}, "code_security_scan"},
	}
	for _, tc := range cases {
		got := operationFromScanTypes(tc.scanTypes)
		if got != tc.want {
			t.Errorf("operationFromScanTypes(%v) = %q, want %q", tc.scanTypes, got, tc.want)
		}
	}
}

// ── trackCLIScan ─────────────────────────────────────────────────────────────

// TestTrackCLIScan_OperationAll verifies that the "all" scan type is normalised
// to "code_security_scan", matching the MCP handler's operation name.
func TestTrackCLIScan_OperationAll(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	trackCLIScan(context.Background(), "all", nil, time.Now(), 3, false, nil)

	item := waitCmdEvent(t, ch)
	if item["operation"] != "code_security_scan" {
		t.Errorf("operation = %v, want code_security_scan", item["operation"])
	}
	if item["interface"] != "cli" {
		t.Errorf("interface = %v, want cli", item["interface"])
	}
	if v, _ := item["paths_count"].(float64); int(v) != 3 {
		t.Errorf("paths_count = %v, want 3", item["paths_count"])
	}
}

// TestTrackCLIScan_OperationSingle verifies single scan types map to "<type>_scan".
func TestTrackCLIScan_OperationSingle(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	trackCLIScan(context.Background(), "sast", nil, time.Now(), 1, false, nil)

	item := waitCmdEvent(t, ch)
	if item["operation"] != "sast_scan" {
		t.Errorf("operation = %v, want sast_scan", item["operation"])
	}
}

// TestTrackCLIScan_OutputFormat verifies output_format reflects the --json flag.
func TestTrackCLIScan_OutputFormat(t *testing.T) {
	cases := []struct {
		outputJSON bool
		want       string
	}{
		{false, "human"},
		{true, "json"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			srv, ch := captureCmdServer(t)
			telemetryClient = newCmdTestTelemetryClient(t, srv)
			t.Cleanup(func() { telemetryClient = nil })

			trackCLIScan(context.Background(), "sast", nil, time.Now(), 0, tc.outputJSON, nil)

			item := waitCmdEvent(t, ch)
			if item["output_format"] != tc.want {
				t.Errorf("output_format = %v, want %v", item["output_format"], tc.want)
			}
		})
	}
}

// TestTrackCLIScan_ResultFields verifies that findings_count, severity_breakdown,
// scan_types_breakdown, and partial_errors_count are populated from ScanResult.
func TestTrackCLIScan_ResultFields(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	result := &scan.ScanResult{
		Summary: types.ScanSummary{
			Total:           5,
			BySeverity:      map[string]int{"HIGH": 3, "MEDIUM": 2},
			ByDetectionType: map[string]int{"sast": 5},
		},
		Errors: []types.ScanError{{DetectionType: "sca", Error: "binary not found"}},
	}
	trackCLIScan(context.Background(), "all", result, time.Now(), 2, false, nil)

	item := waitCmdEvent(t, ch)
	if v, _ := item["findings_count"].(float64); int(v) != 5 {
		t.Errorf("findings_count = %v, want 5", item["findings_count"])
	}
	if item["severity_breakdown"] == nil {
		t.Error("severity_breakdown must be present when result is non-nil")
	}
	if item["scan_types_breakdown"] == nil {
		t.Error("scan_types_breakdown must be present when result is non-nil")
	}
	if v, _ := item["partial_errors_count"].(float64); int(v) != 1 {
		t.Errorf("partial_errors_count = %v, want 1", item["partial_errors_count"])
	}
}

// ── trackMCPScan ─────────────────────────────────────────────────────────────

// TestTrackMCPScan_OperationAndFields verifies that the MCP scan tracking emits
// operation, interface, paths_count, severity_breakdown, scan_types_breakdown,
// and partial_errors_count.
func TestTrackMCPScan_OperationAndFields(t *testing.T) {
	srv, ch := captureCmdServer(t)
	mcpTelemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { mcpTelemetryClient = nil })

	result := &scan.ScanResult{
		Summary: types.ScanSummary{
			Total:           2,
			BySeverity:      map[string]int{"HIGH": 2},
			ByDetectionType: map[string]int{"secrets": 2},
		},
	}
	trackMCPScan(context.Background(), "secrets_scan", []string{"secrets"}, result, time.Now(), 4, nil)

	item := waitCmdEvent(t, ch)
	if item["operation"] != "secrets_scan" {
		t.Errorf("operation = %v, want secrets_scan", item["operation"])
	}
	if item["interface"] != "mcp" {
		t.Errorf("interface = %v, want mcp", item["interface"])
	}
	if v, _ := item["paths_count"].(float64); int(v) != 4 {
		t.Errorf("paths_count = %v, want 4", item["paths_count"])
	}
	if item["severity_breakdown"] == nil {
		t.Error("severity_breakdown must be present")
	}
	if item["scan_types_breakdown"] == nil {
		t.Error("scan_types_breakdown must be present")
	}
	// No errors in result → partial_errors_count should be 0.
	if v, _ := item["partial_errors_count"].(float64); int(v) != 0 {
		t.Errorf("partial_errors_count = %v, want 0", item["partial_errors_count"])
	}
}

// TestTrackMCPScan_NilResult verifies that omitting the result does not panic
// and that result-dependent fields are absent from the payload.
func TestTrackMCPScan_NilResult(t *testing.T) {
	srv, ch := captureCmdServer(t)
	mcpTelemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { mcpTelemetryClient = nil })

	trackMCPScan(context.Background(), "sast_scan", []string{"sast"}, nil, time.Now(), 0, nil)

	item := waitCmdEvent(t, ch)
	if item["severity_breakdown"] != nil {
		t.Error("severity_breakdown should be absent when result is nil")
	}
	if item["scan_types_breakdown"] != nil {
		t.Error("scan_types_breakdown should be absent when result is nil")
	}
}
