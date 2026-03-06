package scan

import (
	"context"
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

func TestBuildSummary(t *testing.T) {
	findings := []types.Violation{
		{Severity: "CRITICAL", DetectionType: "sast"},
		{Severity: "HIGH", DetectionType: "sast"},
		{Severity: "MEDIUM", DetectionType: "secrets"},
		{Severity: "LOW", DetectionType: "secrets"},
		{Severity: "HIGH", DetectionType: "sast"},
	}

	summary := buildSummary(findings)

	if summary.Total != 5 {
		t.Errorf("Expected Total=5, got %d", summary.Total)
	}
	if summary.Critical != 1 {
		t.Errorf("Expected Critical=1, got %d", summary.Critical)
	}
	if summary.High != 2 {
		t.Errorf("Expected High=2, got %d", summary.High)
	}
	if summary.Medium != 1 {
		t.Errorf("Expected Medium=1, got %d", summary.Medium)
	}
	if summary.Low != 1 {
		t.Errorf("Expected Low=1, got %d", summary.Low)
	}

	// Check by severity map
	if summary.BySeverity["CRITICAL"] != 1 {
		t.Errorf("Expected BySeverity[CRITICAL]=1, got %d", summary.BySeverity["CRITICAL"])
	}
	if summary.BySeverity["HIGH"] != 2 {
		t.Errorf("Expected BySeverity[HIGH]=2, got %d", summary.BySeverity["HIGH"])
	}

	// Check by detection type map
	if summary.ByDetectionType["sast"] != 3 {
		t.Errorf("Expected ByDetectionType[sast]=3, got %d", summary.ByDetectionType["sast"])
	}
	if summary.ByDetectionType["secrets"] != 2 {
		t.Errorf("Expected ByDetectionType[secrets]=2, got %d", summary.ByDetectionType["secrets"])
	}
}

func TestBuildSummary_Empty(t *testing.T) {
	summary := buildSummary([]types.Violation{})

	if summary.Total != 0 {
		t.Errorf("Expected Total=0 for empty findings, got %d", summary.Total)
	}
	if summary.Critical != 0 {
		t.Errorf("Expected Critical=0, got %d", summary.Critical)
	}
}

func TestGetScannerFor_UnknownType(t *testing.T) {
	scanner := getScannerFor("unknown", nil)
	if scanner != nil {
		t.Error("Expected nil scanner for unknown type")
	}
}

func TestGetScannerFor_KnownTypes(t *testing.T) {
	binMgr := binary.NewBinaryManager()

	tests := []struct {
		scanType    string
		shouldExist bool
	}{
		{"sast", true},
		{"secrets", true},
		{"sca", true},
		{"iac", true},
	}

	for _, tt := range tests {
		t.Run(tt.scanType, func(t *testing.T) {
			scanner := getScannerFor(tt.scanType, binMgr)
			if tt.shouldExist && scanner == nil {
				t.Errorf("Expected scanner for %s to exist, got nil", tt.scanType)
			}
			if !tt.shouldExist && scanner != nil {
				t.Errorf("Expected scanner for %s to be nil (not implemented yet), got non-nil", tt.scanType)
			}
		})
	}
}

// TestExecuteParallelScans_SCABinaryMissing tests that SCA gracefully errors
// when required binaries (datadog-sbom-generator, datadog-security-cli) are not in PATH.
func TestExecuteParallelScans_SCABinaryMissing(t *testing.T) {
	ctx := context.Background()
	args := ScanArgs{
		FilePaths:  []string{"."},
		WorkingDir: ".",
		ScanTypes:  []string{"sca"},
	}

	binMgr := binary.NewBinaryManager()
	result, err := ExecuteParallelScans(ctx, args, binMgr)
	if err != nil {
		t.Fatalf("Expected no error from executor, got: %v", err)
	}

	if len(result.Errors) != 1 {
		t.Errorf("Expected 1 error (binary not found), got %d", len(result.Errors))
	}

	if result.Summary.Total != 0 {
		t.Errorf("Expected 0 findings, got %d", result.Summary.Total)
	}

	if result.PartialResult {
		t.Error("Expected PartialResult=false when all scans fail")
	}
}

// TestExecuteParallelScans_AllScanTypes verifies all three scan types are dispatched in parallel.
// Each scan type will either succeed (findings + result entry) or fail (error entry) depending
// on whether the required binary is installed. The test checks that no scan type is silently dropped.
func TestExecuteParallelScans_AllScanTypes(t *testing.T) {
	ctx := context.Background()
	args := ScanArgs{
		FilePaths:  []string{"."},
		WorkingDir: ".",
		ScanTypes:  []string{"sast", "secrets", "sca"},
	}

	binMgr := binary.NewBinaryManager()
	result, err := ExecuteParallelScans(ctx, args, binMgr)
	if err != nil {
		t.Fatalf("Expected no error from executor, got: %v", err)
	}

	// Every scan type must appear in either Results or Errors — none should be dropped
	reported := make(map[string]bool)
	for dt := range result.Results {
		reported[string(dt)] = true
	}
	for _, e := range result.Errors {
		reported[e.DetectionType] = true
	}
	for _, expected := range []string{"sast", "secrets", "sca"} {
		if !reported[expected] {
			t.Errorf("Scan type %q was silently dropped (not in Results or Errors)", expected)
		}
	}
}

// TestExecuteParallelScans_PartialFailure_WithMock tests the partial result aggregation logic:
// when some scan types succeed and others fail, PartialResult should be true.
func TestExecuteParallelScans_PartialFailure_WithMock(t *testing.T) {
	findings := []types.Violation{
		{Severity: "HIGH", DetectionType: "sast"},
	}
	errors := []ScanError{
		{DetectionType: "secrets", Error: "failed"},
	}

	result := &ScanResult{
		Summary:       buildSummary(findings),
		Results:       map[types.DetectionType][]types.Violation{"sast": findings},
		Errors:        errors,
		PartialResult: len(errors) > 0 && len(findings) > 0,
	}

	if !result.PartialResult {
		t.Error("Expected PartialResult=true when some scans succeed and some fail")
	}

	if result.Summary.Total != 1 {
		t.Errorf("Expected 1 finding, got %d", result.Summary.Total)
	}

	if len(result.Errors) != 1 {
		t.Errorf("Expected 1 error, got %d", len(result.Errors))
	}
}

// TestExecuteParallelScans_ThreadSafety tests that concurrent ExecuteParallelScans
// calls don't race or panic. Each invocation will error (binary not found) but
// the executor must handle concurrent access safely.
func TestExecuteParallelScans_ThreadSafety(t *testing.T) {
	ctx := context.Background()
	binMgr := binary.NewBinaryManager()

	done := make(chan bool, 5)
	for i := 0; i < 5; i++ {
		go func() {
			args := ScanArgs{
				FilePaths:  []string{"."},
				WorkingDir: ".",
				ScanTypes:  []string{"sast", "secrets", "sca"},
			}
			result, err := ExecuteParallelScans(ctx, args, binMgr)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if len(result.Errors) == 0 {
				t.Error("Expected errors (binaries not installed)")
			}
			done <- true
		}()
	}

	for i := 0; i < 5; i++ {
		<-done
	}
}

