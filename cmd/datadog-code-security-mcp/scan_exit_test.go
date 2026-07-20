package main

import (
	"errors"
	"os"
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/libraryscan"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/scan"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

// withSuppressedStdout redirects os.Stdout to os.DevNull for the duration of fn
// so the renderers' output doesn't pollute test logs. We only care about the
// returned error (the exit decision), not the rendered bytes.
func withSuppressedStdout(t *testing.T, fn func()) {
	t.Helper()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open devnull: %v", err)
	}
	orig := os.Stdout
	os.Stdout = devnull
	defer func() {
		os.Stdout = orig
		_ = devnull.Close()
	}()
	fn()
}

// TestRenderScanResult_ExitConsistentAcrossFormats is the regression guard for
// the bug where `--json` scans always exited 0 even with findings (while human
// mode exited non-zero), giving CI gating a false pass. Both output formats must
// return errViolationsFound when findings exist, and nil when clean.
func TestRenderScanResult_ExitConsistentAcrossFormats(t *testing.T) {
	withFindings := &scan.ScanResult{
		Summary: types.ScanSummary{
			Total:      2,
			BySeverity: map[string]int{"HIGH": 2},
		},
		Results: map[types.DetectionType][]types.Violation{
			types.DetectionTypeSAST: {
				{Severity: "HIGH", DetectionType: types.DetectionTypeSAST},
				{Severity: "HIGH", DetectionType: types.DetectionTypeSAST},
			},
		},
	}
	clean := &scan.ScanResult{Summary: types.ScanSummary{Total: 0}}

	cases := []struct {
		name       string
		result     *scan.ScanResult
		outputJSON bool
		wantErr    bool
	}{
		{"findings_human", withFindings, false, true},
		{"findings_json", withFindings, true, true},
		{"clean_human", clean, false, false},
		{"clean_json", clean, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			withSuppressedStdout(t, func() {
				err = renderScanResult(tc.result, "sast", tc.outputJSON)
			})
			if tc.wantErr && !errors.Is(err, errViolationsFound) {
				t.Errorf("err = %v, want errViolationsFound", err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("err = %v, want nil", err)
			}
		})
	}
}

// TestRenderLibraryScanResult_ExitConsistentAcrossFormats is the same guard for
// the library-scan path, which had the identical early-return shape.
func TestRenderLibraryScanResult_ExitConsistentAcrossFormats(t *testing.T) {
	result := &libraryscan.ScanResult{}

	cases := []struct {
		name       string
		totalVulns int
		outputJSON bool
		wantErr    bool
	}{
		{"findings_human", 3, false, true},
		{"findings_json", 3, true, true},
		{"clean_human", 0, false, false},
		{"clean_json", 0, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			withSuppressedStdout(t, func() {
				err = renderLibraryScanResult(result, tc.totalVulns, tc.outputJSON)
			})
			if tc.wantErr && !errors.Is(err, errViolationsFound) {
				t.Errorf("err = %v, want errViolationsFound", err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("err = %v, want nil", err)
			}
		})
	}
}
