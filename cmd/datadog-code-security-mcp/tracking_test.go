package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/scan"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/telemetry"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

// captureCmdServer starts an httptest server and returns a channel that receives
// the first decoded log item from each POST body.
func captureCmdServer(t *testing.T) (*httptest.Server, <-chan map[string]any) {
	t.Helper()
	ch := make(chan map[string]any, 16)
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

// waitNEvents reads exactly n events from ch within 5 s.
func waitNEvents(t *testing.T, ch <-chan map[string]any, n int) []map[string]any {
	t.Helper()
	events := make([]map[string]any, 0, n)
	deadline := time.After(5 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case item := <-ch:
			events = append(events, item)
		case <-deadline:
			t.Fatalf("timed out waiting for telemetry events: got %d/%d", len(events), n)
			return events
		}
	}
	return events
}

// eventByOperation returns the first event whose "operation" field matches, or nil.
func eventByOperation(events []map[string]any, op string) map[string]any {
	for _, e := range events {
		if e["operation"] == op {
			return e
		}
	}
	return nil
}

func testScanOutcome(result *scan.ScanResult, durations map[string]int64, scanTypes ...string) *scan.ScanOutcome {
	errorsByType := make(map[string]error)
	noticesByType := make(map[string]scan.ScanNotice)
	if result != nil {
		for _, scanErr := range result.Errors {
			errorsByType[scanErr.DetectionType] = errors.New(scanErr.Error)
		}
		for _, notice := range result.Notices {
			noticesByType[notice.DetectionType] = notice
		}
	}
	executions := make([]scan.ScanExecution, 0, len(scanTypes))
	for _, scanType := range scanTypes {
		var findings []types.Violation
		if result != nil {
			findings = result.Results[types.DetectionType(scanType)]
		}
		var notice *scan.ScanNotice
		if n, ok := noticesByType[scanType]; ok {
			notice = &n
		}
		executions = append(executions, scan.ScanExecution{
			DetectionType: types.DetectionType(scanType),
			Findings:      findings,
			Duration:      time.Duration(durations[scanType]) * time.Millisecond,
			Err:           errorsByType[scanType],
			Notice:        notice,
		})
	}
	return scan.NewCompletedOutcome(executions)
}

func testTrackCLIScan(ctx context.Context, scanType string, outcome *scan.ScanOutcome, start time.Time, pathsCount int, outputJSON bool, workingDir, authMethod string, err error) {
	scanTypes := []string{scanType}
	if scanType == "all" {
		scanTypes = types.SecurityScanTypes()
	}
	outputFormat := telemetry.OutputFormatHuman
	if outputJSON {
		outputFormat = telemetry.OutputFormatJSON
	}
	if outcome == nil {
		outcome = scan.NewFailedOutcome(scanTypes, err)
	}
	trackCLIScan(ctx, telemetry.ScanEvent{
		Outcome:      outcome,
		StartedAt:    start,
		PathsCount:   pathsCount,
		OutputFormat: outputFormat,
		WorkingDir:   workingDir,
		AuthMethod:   authMethod,
	})
}

func testTrackMCPScan(ctx context.Context, _ string, scanTypes []string, outcome *scan.ScanOutcome, start time.Time, pathsCount int, workingDir, authMethod string, err error) {
	if outcome == nil {
		outcome = scan.NewFailedOutcome(scanTypes, err)
	}
	trackMCPScan(ctx, telemetry.ScanEvent{
		Outcome:    outcome,
		StartedAt:  start,
		PathsCount: pathsCount,
		WorkingDir: workingDir,
		AuthMethod: authMethod,
	})
}

// ── trackCLIScan ─────────────────────────────────────────────────────────────

// TestTrackCLIScan_OperationAll verifies that the "all" scan type is normalised
// to "code_security_scan", matching the MCP handler's operation name.
func TestTrackCLIScan_OperationAll(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	testTrackCLIScan(context.Background(), "all", nil, time.Now(), 3, false, "", "none", nil)

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

	testTrackCLIScan(context.Background(), "sast", nil, time.Now(), 1, false, "", "none", nil)

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

			testTrackCLIScan(context.Background(), "sast", nil, time.Now(), 0, tc.outputJSON, "", "none", nil)

			item := waitCmdEvent(t, ch)
			if item["output_format"] != tc.want {
				t.Errorf("output_format = %v, want %v", item["output_format"], tc.want)
			}
		})
	}
}

// TestTrackCLIScan_ResultFields verifies that the aggregate event carries
// findings_count, severity_breakdown, scan_types_breakdown, and partial_errors_count.
// The result has one successful scan (sast) and one failed (sca), so the
// invocation emits an aggregate plus both per-scan events.
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
		Results: map[types.DetectionType][]types.Violation{
			types.DetectionTypeSAST: {
				{Severity: "HIGH", DetectionType: types.DetectionTypeSAST},
				{Severity: "HIGH", DetectionType: types.DetectionTypeSAST},
				{Severity: "HIGH", DetectionType: types.DetectionTypeSAST},
				{Severity: "MEDIUM", DetectionType: types.DetectionTypeSAST},
				{Severity: "MEDIUM", DetectionType: types.DetectionTypeSAST},
			},
		},
		Errors: []types.ScanError{{DetectionType: "sca", Error: "binary not found"}},
	}
	outcome := testScanOutcome(result, nil, "sast", "sca")
	testTrackCLIScan(context.Background(), "all", outcome, time.Now(), 2, false, "", "none", nil)
	flushTelemetry()

	events := waitNEvents(t, ch, 3)

	item := eventByOperation(events, "code_security_scan")
	if item == nil {
		t.Fatal("expected aggregate code_security_scan event")
	}
	if v, _ := item["findings_count"].(float64); int(v) != 5 {
		t.Errorf("findings_count = %v, want 5", item["findings_count"])
	}
	if item["severity_breakdown"] == nil {
		t.Error("severity_breakdown must be present on aggregate when result is non-nil")
	}
	if item["scan_types_breakdown"] == nil {
		t.Error("scan_types_breakdown must be present on aggregate when result is non-nil")
	}
	if v, _ := item["partial_errors_count"].(float64); int(v) != 1 {
		t.Errorf("partial_errors_count = %v, want 1", item["partial_errors_count"])
	}
}

// TestTrackCLIScan_ErrorDeliveredAfterFlush verifies that when RunE returns an
// error (and Cobra therefore skips PersistentPostRun), calling flushTelemetry()
// in main()'s error path still delivers the event. This is a regression guard
// for the bug where os.Exit(1) was called before the telemetry goroutine had a
// chance to complete.
func TestTrackCLIScan_ErrorDeliveredAfterFlush(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	scanErr := errors.New("path does not exist: ./testdata/vulnerabilities/sast")
	start := time.Now().Add(-50 * time.Millisecond)
	testTrackCLIScan(context.Background(), "sast", nil, start, 1, false, "", "none", scanErr)
	// Simulate what main() now does on error: flush before os.Exit(1).
	flushTelemetry()

	item := waitCmdEvent(t, ch)
	if item["success"] != false {
		t.Errorf("success = %v, want false", item["success"])
	}
	if item["operation"] != "sast_scan" {
		t.Errorf("operation = %v, want sast_scan", item["operation"])
	}
	if item["interface"] != "cli" {
		t.Errorf("interface = %v, want cli", item["interface"])
	}
	if duration, _ := item["duration_ms"].(float64); duration < 50 {
		t.Errorf("duration_ms = %v, want elapsed invocation time for pre-execution failure", item["duration_ms"])
	}
}

// ── trackMCPScan ─────────────────────────────────────────────────────────────

// TestTrackMCPScan_SingleTypeIsPerScanEvent verifies that a single-type MCP scan
// emits a per-scan event (not an aggregate): operation=<type>_scan, standalone=true,
// paths_count present, severity_breakdown from violations, and scan_types_breakdown
// absent (that field is aggregate-only).
func TestTrackMCPScan_SingleTypeIsPerScanEvent(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	result := &scan.ScanResult{
		Summary: types.ScanSummary{
			Total:           2,
			BySeverity:      map[string]int{"HIGH": 2},
			ByDetectionType: map[string]int{"secrets": 2},
		},
		Results: map[types.DetectionType][]types.Violation{
			types.DetectionTypeSecrets: {
				{Severity: "HIGH", DetectionType: types.DetectionTypeSecrets},
				{Severity: "HIGH", DetectionType: types.DetectionTypeSecrets},
			},
		},
	}
	outcome := testScanOutcome(result, nil, "secrets")
	testTrackMCPScan(context.Background(), "secrets_scan", []string{"secrets"}, outcome, time.Now(), 4, "", "none", nil)
	flushTelemetry()

	item := waitCmdEvent(t, ch)
	if item["operation"] != "secrets_scan" {
		t.Errorf("operation = %v, want secrets_scan", item["operation"])
	}
	if item["interface"] != "mcp" {
		t.Errorf("interface = %v, want mcp", item["interface"])
	}
	if item["standalone"] != true {
		t.Errorf("standalone = %v, want true (standalone single-type scan)", item["standalone"])
	}
	if v, _ := item["paths_count"].(float64); int(v) != 4 {
		t.Errorf("paths_count = %v, want 4", item["paths_count"])
	}
	if item["severity_breakdown"] == nil {
		t.Error("severity_breakdown must be present for a successful per-scan event with violations")
	}
	// scan_types_breakdown is aggregate-only — must be absent on per-scan events.
	if item["scan_types_breakdown"] != nil {
		t.Errorf("scan_types_breakdown must be absent on per-scan events, got %v", item["scan_types_breakdown"])
	}
}

// TestTrackMCPScan_SingleTypeCarriesDuration is a regression guard: a single-type
// MCP scan must report the per-type wall-clock duration recorded by the executor,
// not a hardcoded 0. Previously the MCP single-type path passed 0 while the CLI
// path looked the duration up, so the majority of MCP tool calls reported 0ms.
func TestTrackMCPScan_SingleTypeCarriesDuration(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	result := &scan.ScanResult{
		Summary: types.ScanSummary{
			Total:           1,
			BySeverity:      map[string]int{"HIGH": 1},
			ByDetectionType: map[string]int{"sast": 1},
		},
		Results: map[types.DetectionType][]types.Violation{
			types.DetectionTypeSAST: {{Severity: "HIGH", DetectionType: types.DetectionTypeSAST}},
		},
	}
	outcome := testScanOutcome(result, map[string]int64{"sast": 1234}, "sast")
	testTrackMCPScan(context.Background(), "sast_scan", []string{"sast"}, outcome, time.Now(), 1, "", "none", nil)
	flushTelemetry()

	item := waitCmdEvent(t, ch)
	if v, _ := item["duration_ms"].(float64); int64(v) != 1234 {
		t.Errorf("duration_ms = %v, want 1234 (per-scan duration from executor)", item["duration_ms"])
	}
}

func TestTrackMCPScan_SingleTypePreservesTypedError(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	outcome := scan.NewCompletedOutcome([]scan.ScanExecution{{
		DetectionType: types.DetectionTypeSAST,
		Duration:      25 * time.Millisecond,
		Err:           context.DeadlineExceeded,
	}})
	testTrackMCPScan(
		context.Background(),
		"sast_scan",
		[]string{"sast"},
		outcome,
		time.Now(),
		1,
		"",
		"none",
		errors.New("all scans failed"),
	)
	flushTelemetry()

	item := waitCmdEvent(t, ch)
	errorObject, ok := item["error"].(map[string]any)
	if !ok {
		t.Fatalf("error object missing: %v", item["error"])
	}
	if errorObject["kind"] != telemetry.ErrKindTimeout {
		t.Errorf("error.kind = %v, want typed execution kind %s", errorObject["kind"], telemetry.ErrKindTimeout)
	}
}

// TestTrackMCPScan_NilResult verifies that omitting the result does not panic
// and that result-dependent fields are absent from the per-scan event payload.
func TestTrackMCPScan_NilResult(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	testTrackMCPScan(context.Background(), "sast_scan", []string{"sast"}, nil, time.Now(), 0, "", "none", nil)
	flushTelemetry()

	item := waitCmdEvent(t, ch)
	// Per-scan event: result-dependent fields are absent when result is nil.
	if item["severity_breakdown"] != nil {
		t.Error("severity_breakdown should be absent when result is nil")
	}
	if item["scan_types_breakdown"] != nil {
		t.Error("scan_types_breakdown should be absent on per-scan events")
	}
}

// TestTrackMCPScan_ScanAllEmitsAggregateAndPerScanEvents verifies that a multi-type
// scan (scan all) emits the aggregate code_security_scan event plus one per-scan
// event per executed scan type, with standalone=false on per-scan events.
func TestTrackMCPScan_ScanAllEmitsAggregateAndPerScanEvents(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	result := &scan.ScanResult{
		Summary: types.ScanSummary{
			Total:           3,
			BySeverity:      map[string]int{"HIGH": 3},
			ByDetectionType: map[string]int{"sast": 3},
		},
		Results: map[types.DetectionType][]types.Violation{
			types.DetectionTypeSAST: {
				{Severity: "HIGH", DetectionType: types.DetectionTypeSAST},
				{Severity: "HIGH", DetectionType: types.DetectionTypeSAST},
				{Severity: "HIGH", DetectionType: types.DetectionTypeSAST},
			},
		},
		Errors: []types.ScanError{{DetectionType: "secrets", Error: "binary not found"}},
	}
	outcome := testScanOutcome(result, map[string]int64{"sast": 1200, "secrets": 50}, "sast", "secrets")
	testTrackMCPScan(context.Background(), "code_security_scan", []string{"sast", "secrets"}, outcome, time.Now(), 2, "", "none", nil)
	flushTelemetry()

	// Expect 3 events: aggregate + sast_scan + secrets_scan.
	events := waitNEvents(t, ch, 3)

	agg := eventByOperation(events, "code_security_scan")
	if agg == nil {
		t.Fatal("expected aggregate code_security_scan event")
	}
	if agg["interface"] != "mcp" {
		t.Errorf("aggregate interface = %v, want mcp", agg["interface"])
	}
	if agg["scan_types_breakdown"] == nil {
		t.Error("aggregate must have scan_types_breakdown")
	}
	if agg["severity_breakdown"] == nil {
		t.Error("aggregate must have severity_breakdown")
	}
	if agg["scan_durations_breakdown"] == nil {
		t.Error("aggregate must have scan_durations_breakdown when Durations are set")
	}
	if agg["partial_errors_breakdown"] == nil {
		t.Error("aggregate must have partial_errors_breakdown when there are errors")
	}

	sast := eventByOperation(events, "sast_scan")
	if sast == nil {
		t.Fatal("expected sast_scan per-scan event")
	}
	if sast["standalone"] != false {
		t.Errorf("sast_scan standalone = %v, want false (part of scan all)", sast["standalone"])
	}
	if sast["interface"] != "mcp" {
		t.Errorf("sast_scan interface = %v, want mcp", sast["interface"])
	}

	sec := eventByOperation(events, "secrets_scan")
	if sec == nil {
		t.Fatal("expected secrets_scan per-scan event")
	}
	if sec["standalone"] != false {
		t.Errorf("secrets_scan standalone = %v, want false (part of scan all)", sec["standalone"])
	}
	// secrets failed → success=false.
	if sec["success"] != false {
		t.Errorf("secrets_scan success = %v, want false (scan errored)", sec["success"])
	}
}

// TestTrackMCPScan_ScanDurationsBreakdown verifies that scan_durations_breakdown
// is included in the aggregate event when Durations are populated.
func TestTrackMCPScan_ScanDurationsBreakdown(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	result := &scan.ScanResult{
		Summary: types.ScanSummary{
			Total:           1,
			BySeverity:      map[string]int{"HIGH": 1},
			ByDetectionType: map[string]int{"sast": 1},
		},
		Results: map[types.DetectionType][]types.Violation{
			types.DetectionTypeSAST: {{Severity: "HIGH", DetectionType: types.DetectionTypeSAST}},
			// iac ran and found no violations.
			types.DetectionTypeIaC: {},
		},
	}
	outcome := testScanOutcome(result, map[string]int64{"sast": 2500, "iac": 300}, "sast", "iac")
	testTrackMCPScan(context.Background(), "code_security_scan", []string{"sast", "iac"}, outcome, time.Now(), 1, "", "none", nil)
	flushTelemetry()

	// aggregate + sast_scan + iac_scan
	events := waitNEvents(t, ch, 3)

	agg := eventByOperation(events, "code_security_scan")
	if agg == nil {
		t.Fatal("expected aggregate event")
	}
	bd, ok := agg["scan_durations_breakdown"].(map[string]any)
	if !ok || bd == nil {
		t.Fatalf("scan_durations_breakdown missing or wrong type: %v", agg["scan_durations_breakdown"])
	}
	if bd["sast"] == nil {
		t.Error("scan_durations_breakdown must include sast")
	}
	if bd["iac"] == nil {
		t.Error("scan_durations_breakdown must include iac")
	}
}

// TestTrackMCPScan_PartialErrorsBreakdown verifies that partial_errors_breakdown
// is included in the aggregate event when some scans failed.
func TestTrackMCPScan_PartialErrorsBreakdown(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	result := &scan.ScanResult{
		Summary: types.ScanSummary{
			Total:           2,
			BySeverity:      map[string]int{"HIGH": 2},
			ByDetectionType: map[string]int{"sast": 2},
		},
		Results: map[types.DetectionType][]types.Violation{
			types.DetectionTypeSAST: {
				{Severity: "HIGH", DetectionType: types.DetectionTypeSAST},
				{Severity: "HIGH", DetectionType: types.DetectionTypeSAST},
			},
		},
		Errors:        []types.ScanError{{DetectionType: "secrets", Error: "binary not found"}},
		PartialResult: true,
	}
	outcome := testScanOutcome(result, nil, "sast", "secrets")
	testTrackMCPScan(context.Background(), "code_security_scan", []string{"sast", "secrets"}, outcome, time.Now(), 1, "", "none", nil)
	flushTelemetry()

	// aggregate + sast_scan + secrets_scan
	events := waitNEvents(t, ch, 3)

	agg := eventByOperation(events, "code_security_scan")
	if agg == nil {
		t.Fatal("expected aggregate event")
	}
	bd, ok := agg["partial_errors_breakdown"].(map[string]any)
	if !ok || bd == nil {
		t.Fatalf("partial_errors_breakdown missing or wrong type: %v", agg["partial_errors_breakdown"])
	}
	if bd["secrets"] == nil {
		t.Error("partial_errors_breakdown must contain an entry for the failed scan type")
	}
}

// TestTrackMCPScan_NoticesBreakdown verifies that a non-fatal notice (e.g. no
// components detected during an SCA scan) shows up as notices_breakdown on
// the aggregate event and as a "notice" attribute on the per-scan event,
// without affecting success/failure status.
func TestTrackMCPScan_NoticesBreakdown(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	result := &scan.ScanResult{
		Summary: types.ScanSummary{
			Total:           1,
			BySeverity:      map[string]int{"HIGH": 1},
			ByDetectionType: map[string]int{"sast": 1},
		},
		Results: map[types.DetectionType][]types.Violation{
			types.DetectionTypeSAST: {{Severity: "HIGH", DetectionType: types.DetectionTypeSAST}},
			types.DetectionTypeSCA:  {},
		},
		Notices: []types.ScanNotice{{DetectionType: "sca", Message: types.NoComponentsDetectedMessage}},
	}
	outcome := testScanOutcome(result, nil, "sast", "sca")
	testTrackMCPScan(context.Background(), "code_security_scan", []string{"sast", "sca"}, outcome, time.Now(), 1, "", "none", nil)
	flushTelemetry()

	// aggregate + sast_scan + sca_scan
	events := waitNEvents(t, ch, 3)

	agg := eventByOperation(events, "code_security_scan")
	if agg == nil {
		t.Fatal("expected aggregate event")
	}
	if agg["success"] != true {
		t.Errorf("aggregate success = %v, want true (a notice is not a failure)", agg["success"])
	}
	bd, ok := agg["notices_breakdown"].(map[string]any)
	if !ok || bd == nil {
		t.Fatalf("notices_breakdown missing or wrong type: %v", agg["notices_breakdown"])
	}
	if bd["sca"] != types.NoComponentsDetectedMessage {
		t.Errorf("notices_breakdown[sca] = %v, want %q", bd["sca"], types.NoComponentsDetectedMessage)
	}

	sca := eventByOperation(events, "sca_scan")
	if sca == nil {
		t.Fatal("expected sca_scan per-scan event")
	}
	if sca["success"] != true {
		t.Errorf("sca_scan success = %v, want true (a notice is not a failure)", sca["success"])
	}
	if sca["notice"] != types.NoComponentsDetectedMessage {
		t.Errorf("sca_scan notice = %v, want %q", sca["notice"], types.NoComponentsDetectedMessage)
	}
}

// TestTrackCLIScan_ScanAllStandaloneFlag verifies that "scan all" emits
// the aggregate event and per-scan events with standalone=false, and that
// per-scan CLI events carry output_format.
func TestTrackCLIScan_ScanAllStandaloneFlag(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	result := &scan.ScanResult{
		Summary: types.ScanSummary{
			Total:           1,
			BySeverity:      map[string]int{"HIGH": 1},
			ByDetectionType: map[string]int{"sast": 1},
		},
		Results: map[types.DetectionType][]types.Violation{
			types.DetectionTypeSAST: {{Severity: "HIGH", DetectionType: types.DetectionTypeSAST}},
		},
	}
	outcome := testScanOutcome(result, map[string]int64{"sast": 800}, "sast", "secrets")
	testTrackCLIScan(context.Background(), "all", outcome, time.Now(), 1, false, "", "none", nil)
	flushTelemetry()

	// aggregate + both per-scan events
	events := waitNEvents(t, ch, 3)

	agg := eventByOperation(events, "code_security_scan")
	if agg == nil {
		t.Fatal("expected aggregate code_security_scan event")
	}

	sast := eventByOperation(events, "sast_scan")
	if sast == nil {
		t.Fatal("expected sast_scan per-scan event")
	}
	if sast["standalone"] != false {
		t.Errorf("sast_scan standalone = %v, want false", sast["standalone"])
	}
	if sast["output_format"] == nil {
		t.Error("output_format must be present on per-scan CLI events")
	}
}

// TestRunDirectScan_InvalidScanTypeUsesSentinel is the regression guard for the
// privacy bug where an unrecognized scan-type argument (args[0], arbitrary user
// input that could be a path or secret) was echoed verbatim into the telemetry
// operation/message. The fallback must instead report the fixed "invalid_scan"
// sentinel, yielding operation "invalid_scan_scan", and the raw argument must
// not appear anywhere on the wire. The human-facing error is unaffected and may
// still contain the raw value.
func TestRunDirectScan_InvalidScanTypeUsesSentinel(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	// A raw argument that could plausibly be a path or secret if the CLI's
	// positional args are misused. Already lowercase so it survives the
	// strings.ToLower normalization in runDirectScan unchanged.
	rawArg := "/tmp/super-secret-token-abc123"
	err := runDirectScan(rawArg, []string{"."}, "", false)
	if err == nil {
		t.Fatal("expected an error for an invalid scan type")
	}
	// The user-facing error is printed locally and is allowed to echo the raw value.
	if !strings.Contains(err.Error(), rawArg) {
		t.Errorf("user-facing error = %q, want it to contain the raw arg %q", err.Error(), rawArg)
	}
	flushTelemetry()

	item := waitCmdEvent(t, ch)
	if item["operation"] != "invalid_scan_scan" {
		t.Errorf("operation = %v, want invalid_scan_scan (fixed sentinel, not raw arg)", item["operation"])
	}
	if item["success"] != false {
		t.Errorf("success = %v, want false", item["success"])
	}

	// Privacy contract: the raw argument must not leak anywhere in the event
	// (operation, message, or error object).
	raw, marshalErr := json.Marshal(item)
	if marshalErr != nil {
		t.Fatalf("failed to marshal telemetry event: %v", marshalErr)
	}
	if strings.Contains(string(raw), rawArg) {
		t.Errorf("telemetry event leaked raw scan-type argument %q: %s", rawArg, raw)
	}
}

// TestRunGenerateSBOM_ResultErrorRecordedAsFailure is the regression guard for
// the bug where generator.Generate reporting a failure via result.Error (while
// returning a nil Go error, e.g. missing binary or exec/parse failure) was
// emitted as a successful telemetry event. Forcing the SBOM binary lookup to
// fail (empty PATH) makes Generate return a result carrying Error with a nil
// Go error; the emitted generate_sbom event must then report success=false.
func TestRunGenerateSBOM_ResultErrorRecordedAsFailure(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	// Deterministically force GetBinaryPath (exec.LookPath) to fail so Generate
	// takes the result.Error (nil Go error) branch regardless of what's
	// installed on the host running the tests.
	t.Setenv("PATH", "")

	// Human/JSON output is written to stdout (test noise only); we only care
	// about the emitted telemetry. Exit behavior is intentionally unchanged.
	_ = runGenerateSBOM(".", "", false)
	flushTelemetry()

	item := waitCmdEvent(t, ch)
	if item["operation"] != "generate_sbom" {
		t.Errorf("operation = %v, want generate_sbom", item["operation"])
	}
	if item["success"] != false {
		t.Errorf("success = %v, want false (result.Error must be recorded as a failure)", item["success"])
	}
}

// TestTrackCLIScan_StandaloneFlagSingleType verifies that single-type CLI scans
// emit a per-scan event with standalone=true.
func TestTrackCLIScan_StandaloneFlagSingleType(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	testTrackCLIScan(context.Background(), "sast", nil, time.Now(), 1, false, "", "none", nil)
	flushTelemetry()

	item := waitCmdEvent(t, ch)
	if item["standalone"] != true {
		t.Errorf("standalone = %v, want true (single-type standalone scan)", item["standalone"])
	}
	if item["operation"] != "sast_scan" {
		t.Errorf("operation = %v, want sast_scan", item["operation"])
	}
}

// TestTrackCLIScan_AllFailedWithResult verifies that when all scans fail (result
// non-nil with errors returned alongside err), per-scan error events are still
// emitted for each failed scan type.
func TestTrackCLIScan_AllFailedWithResult(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	result := &scan.ScanResult{
		Errors: []types.ScanError{
			{DetectionType: "sast", Error: "binary not found"},
			{DetectionType: "secrets", Error: "binary not found"},
		},
	}
	scanErr := errors.New("all scans failed")
	outcome := testScanOutcome(result, map[string]int64{"sast": 10}, "sast", "secrets")
	testTrackCLIScan(context.Background(), "all", outcome, time.Now(), 1, false, "", "none", scanErr)
	flushTelemetry()

	// aggregate (error) + both per-scan errors
	events := waitNEvents(t, ch, 3)

	agg := eventByOperation(events, "code_security_scan")
	if agg == nil {
		t.Fatal("expected aggregate event even when all scans fail")
	}
	if agg["success"] != false {
		t.Errorf("aggregate success = %v, want false", agg["success"])
	}

	sast := eventByOperation(events, "sast_scan")
	if sast == nil {
		t.Fatal("expected sast_scan per-scan error event when result is non-nil")
	}
	if sast["success"] != false {
		t.Errorf("sast_scan success = %v, want false", sast["success"])
	}
	if sast["standalone"] != false {
		t.Errorf("sast_scan standalone = %v, want false (part of scan all)", sast["standalone"])
	}
}

// TestTrackMCPScan_BatchIDSharedAcrossBatch verifies that all events emitted for
// a multi-type scan share the same batch_id, and that single-type scans do not
// carry a batch_id at all.
func TestTrackMCPScan_BatchIDSharedAcrossBatch(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	result := &scan.ScanResult{
		Summary: types.ScanSummary{
			Total:           1,
			BySeverity:      map[string]int{"HIGH": 1},
			ByDetectionType: map[string]int{"sast": 1},
		},
		Results: map[types.DetectionType][]types.Violation{
			types.DetectionTypeSAST: {{Severity: "HIGH", DetectionType: types.DetectionTypeSAST}},
		},
		Errors: []types.ScanError{{DetectionType: "secrets", Error: "binary not found"}},
	}
	outcome := testScanOutcome(result, map[string]int64{"sast": 500, "secrets": 10}, "sast", "secrets")
	testTrackMCPScan(context.Background(), "code_security_scan", []string{"sast", "secrets"}, outcome, time.Now(), 1, "", "none", nil)
	flushTelemetry()

	// aggregate + sast_scan + secrets_scan
	events := waitNEvents(t, ch, 3)

	agg := eventByOperation(events, "code_security_scan")
	if agg == nil {
		t.Fatal("expected aggregate event")
	}
	batchID, ok := agg["batch_id"].(string)
	if !ok || batchID == "" {
		t.Fatalf("aggregate batch_id missing or empty: %v", agg["batch_id"])
	}

	for _, op := range []string{"sast_scan", "secrets_scan"} {
		ev := eventByOperation(events, op)
		if ev == nil {
			t.Fatalf("expected %s event", op)
		}
		if ev["batch_id"] != batchID {
			t.Errorf("%s batch_id = %v, want %v (same as aggregate)", op, ev["batch_id"], batchID)
		}
	}
}

// TestTrackMCPScan_NoBatchIDForSingleType verifies that standalone single-type
// scans do not carry a batch_id (there is no batch to correlate).
func TestTrackMCPScan_NoBatchIDForSingleType(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	testTrackMCPScan(context.Background(), "sast_scan", []string{"sast"}, nil, time.Now(), 1, "", "none", nil)
	flushTelemetry()

	item := waitCmdEvent(t, ch)
	if item["batch_id"] != nil {
		t.Errorf("batch_id must be absent for standalone single-type scans, got %v", item["batch_id"])
	}
}

// TestTrackCLIScan_BatchIDSharedAcrossBatch verifies that the CLI "scan all"
// path also propagates the same batch_id to the aggregate and per-scan events.
func TestTrackCLIScan_BatchIDSharedAcrossBatch(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	result := &scan.ScanResult{
		Summary: types.ScanSummary{
			Total:           2,
			BySeverity:      map[string]int{"HIGH": 2},
			ByDetectionType: map[string]int{"sast": 2},
		},
		Results: map[types.DetectionType][]types.Violation{
			types.DetectionTypeSAST: {
				{Severity: "HIGH", DetectionType: types.DetectionTypeSAST},
				{Severity: "HIGH", DetectionType: types.DetectionTypeSAST},
			},
		},
		Errors: []types.ScanError{{DetectionType: "iac", Error: "binary not found"}},
	}
	outcome := testScanOutcome(result, map[string]int64{"sast": 600, "iac": 20}, "sast", "iac")
	testTrackCLIScan(context.Background(), "all", outcome, time.Now(), 1, false, "", "none", nil)
	flushTelemetry()

	// aggregate + sast_scan + iac_scan
	events := waitNEvents(t, ch, 3)

	agg := eventByOperation(events, "code_security_scan")
	if agg == nil {
		t.Fatal("expected aggregate event")
	}
	batchID, ok := agg["batch_id"].(string)
	if !ok || batchID == "" {
		t.Fatalf("aggregate batch_id missing or empty: %v", agg["batch_id"])
	}

	for _, op := range []string{"sast_scan", "iac_scan"} {
		ev := eventByOperation(events, op)
		if ev == nil {
			t.Fatalf("expected %s event", op)
		}
		if ev["batch_id"] != batchID {
			t.Errorf("%s batch_id = %v, want %v (same as aggregate)", op, ev["batch_id"], batchID)
		}
	}
}

// TestTrackCLIScan_NoBatchIDForSingleType verifies CLI single-type scans carry no batch_id.
func TestTrackCLIScan_NoBatchIDForSingleType(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	testTrackCLIScan(context.Background(), "iac", nil, time.Now(), 1, false, "", "none", nil)
	flushTelemetry()

	item := waitCmdEvent(t, ch)
	if item["batch_id"] != nil {
		t.Errorf("batch_id must be absent for standalone single-type CLI scans, got %v", item["batch_id"])
	}
}

// TestTrackCLIScan_WorkspaceAndAuthAttrs verifies that workspace attributes,
// auth_method, and binary_versions are present in the emitted telemetry event.
func TestTrackCLIScan_WorkspaceAndAuthAttrs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })
	scannerVersionCache = binary.NewBinaryVersionCache()
	scannerVersionCache.Refresh()
	t.Cleanup(func() {
		scannerVersionCache.Close()
		scannerVersionCache = nil
	})

	testTrackCLIScan(context.Background(), "sast", nil, time.Now(), 1, false, ".", "env_var", nil)
	flushTelemetry()

	item := waitCmdEvent(t, ch)

	if _, ok := item["is_git_repo"]; !ok {
		t.Error("is_git_repo must be present in event")
	}
	if _, ok := item["is_worktree"]; !ok {
		t.Error("is_worktree must be present in event")
	}
	if item["auth_method"] != "env_var" {
		t.Errorf("auth_method = %v, want env_var", item["auth_method"])
	}
	if item["binary_versions"] == nil {
		t.Error("binary_versions must be present in event")
	}
	versions, ok := item["binary_versions"].(map[string]any)
	if !ok {
		t.Errorf("binary_versions has wrong type: %T", item["binary_versions"])
	}
	for _, config := range binary.BinaryConfigs {
		if _, ok := versions[config.TelemetryKey]; !ok {
			t.Errorf("binary_versions missing %q: %v", config.TelemetryKey, versions)
		}
	}
}

// TestTrackScan_UsedBinaryVersionsScoped verifies that per-scan events carry a
// used_binary_versions map scoped to only the binaries that scan type uses,
// while the full binary_versions inventory remains present. This is what lets
// per-binary version distributions avoid double-counting.
func TestTrackScan_UsedBinaryVersionsScoped(t *testing.T) {
	tests := []struct {
		scanType string
		wantKeys []string
	}{
		{"sast", []string{"static_analyzer"}},
		{"secrets", []string{"static_analyzer"}},
		{"sca", []string{"sbom_generator", "security_cli"}},
		{"iac", []string{"iac_scanner"}},
	}
	for _, tc := range tests {
		t.Run(tc.scanType, func(t *testing.T) {
			srv, ch := captureCmdServer(t)
			telemetryClient = newCmdTestTelemetryClient(t, srv)
			t.Cleanup(func() { telemetryClient = nil })
			scannerVersionCache = binary.NewBinaryVersionCache()
			scannerVersionCache.Refresh()
			t.Cleanup(func() {
				scannerVersionCache.Close()
				scannerVersionCache = nil
			})

			testTrackCLIScan(context.Background(), tc.scanType, nil, time.Now(), 1, false, ".", "none", nil)
			flushTelemetry()

			item := waitCmdEvent(t, ch)
			scoped, ok := item["used_binary_versions"].(map[string]any)
			if !ok {
				t.Fatalf("used_binary_versions missing or wrong type: %T (%v)", item["used_binary_versions"], item["used_binary_versions"])
			}
			if len(scoped) != len(tc.wantKeys) {
				t.Errorf("used_binary_versions = %v, want exactly keys %v", scoped, tc.wantKeys)
			}
			for _, key := range tc.wantKeys {
				if _, ok := scoped[key]; !ok {
					t.Errorf("used_binary_versions missing %q: %v", key, scoped)
				}
			}
			// Full inventory is still present and a superset of the scoped map.
			if _, ok := item["binary_versions"].(map[string]any); !ok {
				t.Errorf("binary_versions must still be present alongside used_binary_versions")
			}
		})
	}
}
