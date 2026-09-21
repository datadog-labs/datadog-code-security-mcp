package main

import (
	"context"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/constants"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/telemetry"
)

// makeLibraryScanRequest builds a CallToolRequest with the given arguments map.
func makeLibraryScanRequest(args any) mcp.CallToolRequest {
	var req mcp.CallToolRequest
	req.Params.Arguments = args
	return req
}

func TestMCPCaller(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		args map[string]any
		want telemetry.Caller
	}{
		{name: "true", args: map[string]any{constants.ArgCalledBySkill: true}, want: telemetry.CallerSkill},
		{name: "false", args: map[string]any{constants.ArgCalledBySkill: false}, want: ""},
		{name: "omitted", args: map[string]any{"file_paths": []any{"src"}}, want: ""},
		{name: "wrong type", args: map[string]any{constants.ArgCalledBySkill: "true"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := mcpCaller(tc.args); got != tc.want {
				t.Errorf("mcpCaller() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHandleSASTScan_SkillCallerOnError(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	var req mcp.CallToolRequest
	req.Params.Arguments = map[string]any{
		constants.ArgCalledBySkill: true,
	}
	result, err := handleSASTScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for missing file_paths")
	}
	flushTelemetry()

	item := waitCmdEvent(t, ch)
	if item["interface"] != "mcp" {
		t.Errorf("interface = %v, want mcp", item["interface"])
	}
	if item["caller"] != "skill" {
		t.Errorf("caller = %v, want skill", item["caller"])
	}
	if item["success"] != false {
		t.Errorf("success = %v, want false", item["success"])
	}
}

func TestHandleSASTScan_OmitsCallerWhenArgAbsent(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	var req mcp.CallToolRequest
	req.Params.Arguments = map[string]any{}
	result, err := handleSASTScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for missing file_paths")
	}
	flushTelemetry()

	item := waitCmdEvent(t, ch)
	if _, ok := item["caller"]; ok {
		t.Errorf("caller must be omitted for MCP usage, got %v", item["caller"])
	}
	if item["success"] != false {
		t.Errorf("success = %v, want false", item["success"])
	}
}

func TestHandleSASTScan_OmitsCallerWhenFalse(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	var req mcp.CallToolRequest
	req.Params.Arguments = map[string]any{
		constants.ArgCalledBySkill: false,
	}
	result, err := handleSASTScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result for missing file_paths")
	}
	flushTelemetry()

	item := waitCmdEvent(t, ch)
	if _, ok := item["caller"]; ok {
		t.Errorf("caller must be omitted when called_by_skill is false, got %v", item["caller"])
	}
}

func TestHandleLibraryVulnerabilityScan_SkillCallerOnError(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })

	req := makeLibraryScanRequest(map[string]any{
		constants.ArgCalledBySkill: true,
	})
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error result when libraries is absent")
	}
	flushTelemetry()

	item := waitCmdEvent(t, ch)
	if item["operation"] != "library_scan" {
		t.Errorf("operation = %v, want library_scan", item["operation"])
	}
	if item["caller"] != "skill" {
		t.Errorf("caller = %v, want skill", item["caller"])
	}
	if item["success"] != false {
		t.Errorf("success = %v, want false", item["success"])
	}
}

func TestHandleGenerateSBOM_SkillCallerOnError(t *testing.T) {
	srv, ch := captureCmdServer(t)
	telemetryClient = newCmdTestTelemetryClient(t, srv)
	t.Cleanup(func() { telemetryClient = nil })
	t.Setenv("PATH", "")

	var req mcp.CallToolRequest
	req.Params.Arguments = map[string]any{
		constants.ArgCalledBySkill: true,
	}
	_, err := handleGenerateSBOM(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	flushTelemetry()

	item := waitCmdEvent(t, ch)
	if item["operation"] != "generate_sbom" {
		t.Errorf("operation = %v, want generate_sbom", item["operation"])
	}
	if item["caller"] != "skill" {
		t.Errorf("caller = %v, want skill", item["caller"])
	}
	if item["success"] != false {
		t.Errorf("success = %v, want false", item["success"])
	}
}

func TestParseScanArgs_MinSASTSeverity(t *testing.T) {
	args, err := parseScanArgs(map[string]any{
		"file_paths":        []any{"src"},
		"min_sast_severity": "HIGH",
	})
	if err != nil {
		t.Fatalf("parseScanArgs() error = %v", err)
	}
	if args.MinSASTSeverity != "HIGH" {
		t.Fatalf("MinSASTSeverity = %q, want HIGH", args.MinSASTSeverity)
	}
}

func TestParseScanArgs_RejectsNonStringMinSASTSeverity(t *testing.T) {
	for _, value := range []any{42, true, []any{"HIGH"}, map[string]any{"value": "HIGH"}} {
		_, err := parseScanArgs(map[string]any{
			"file_paths":        []any{"src"},
			"min_sast_severity": value,
		})
		if err == nil {
			t.Fatalf("parseScanArgs() accepted min_sast_severity value %#v", value)
		}
		if !strings.Contains(err.Error(), "min_sast_severity must be a string") {
			t.Fatalf("parseScanArgs() error = %q", err)
		}
	}
}

func TestHandleLibraryVulnerabilityScan_InvalidArguments(t *testing.T) {
	req := makeLibraryScanRequest("not-a-map")
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result for invalid arguments type")
	}
}

func TestHandleLibraryVulnerabilityScan_MissingLibraries(t *testing.T) {
	req := makeLibraryScanRequest(map[string]any{})
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result when 'libraries' key is absent")
	}
}

func TestHandleLibraryVulnerabilityScan_EmptyLibraries(t *testing.T) {
	req := makeLibraryScanRequest(map[string]any{
		"libraries": []any{},
	})
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result for empty libraries array")
	}
}

func TestHandleLibraryVulnerabilityScan_LibraryNotAnObject(t *testing.T) {
	req := makeLibraryScanRequest(map[string]any{
		"libraries": []any{"not-an-object"},
	})
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result when a library item is not an object")
	}
}

func TestHandleLibraryVulnerabilityScan_MissingPURL(t *testing.T) {
	req := makeLibraryScanRequest(map[string]any{
		"libraries": []any{
			map[string]any{"is_dev": true}, // no purl
		},
	})
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result when purl field is missing")
	}
}

func TestHandleLibraryVulnerabilityScan_InvalidPURL(t *testing.T) {
	req := makeLibraryScanRequest(map[string]any{
		"libraries": []any{
			map[string]any{"purl": "npm/lodash@4.17.21"}, // missing "pkg:" prefix
		},
	})
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result for PURL without 'pkg:' prefix")
	}
	if !containsText(result, "invalid purl") {
		t.Errorf("expected error message to mention 'invalid purl', got: %v", result.Content)
	}
}

func TestHandleLibraryVulnerabilityScan_AuthNotConfigured(t *testing.T) {
	// Ensure no credentials are present so auth fails
	t.Setenv("DD_API_KEY", "")
	t.Setenv("DD_APP_KEY", "")

	req := makeLibraryScanRequest(map[string]any{
		"libraries": []any{
			map[string]any{"purl": "pkg:npm/lodash@4.17.21"},
		},
	})
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result when auth is not configured")
	}
}

func TestHandleLibraryVulnerabilityScan_NonExistentWorkingDir(t *testing.T) {
	// Verify that a non-existent working_dir causes a git context miss (empty strings)
	// rather than a crash. The handler falls through to auth validation.
	t.Setenv("DD_API_KEY", "")
	t.Setenv("DD_APP_KEY", "")

	req := makeLibraryScanRequest(map[string]any{
		"libraries": []any{
			map[string]any{"purl": "pkg:npm/lodash@4.17.21"},
		},
		"working_dir": "/tmp/nonexistent",
	})
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	// We expect an auth error (not a panic or nil-deref)
	if !result.IsError {
		t.Error("expected error result (auth not configured)")
	}
}

// containsText checks whether any text content block in the result contains substr.
func containsText(result *mcp.CallToolResult, substr string) bool {
	for _, c := range result.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			if strings.Contains(tc.Text, substr) {
				return true
			}
		}
	}
	return false
}
