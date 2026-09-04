package scan

import (
	"context"
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

func TestSASTScanner_FilterBySeverity(t *testing.T) {
	binMgr := binary.NewBinaryManager()
	s := NewSASTScanner(binMgr)

	findings := []types.Violation{
		{Severity: "LOW", Rule: "test1"},
		{Severity: "MEDIUM", Rule: "test2"},
		{Severity: "HIGH", Rule: "test3"},
		{Severity: "CRITICAL", Rule: "test4"},
	}

	tests := []struct {
		name        string
		minSeverity string
		wantCount   int
	}{
		{
			name:        "filter LOW and below",
			minSeverity: "LOW",
			wantCount:   4, // All included
		},
		{
			name:        "filter MEDIUM and above",
			minSeverity: "MEDIUM",
			wantCount:   3, // LOW filtered out
		},
		{
			name:        "filter HIGH and above",
			minSeverity: "HIGH",
			wantCount:   2, // LOW and MEDIUM filtered out
		},
		{
			name:        "filter CRITICAL only",
			minSeverity: "CRITICAL",
			wantCount:   1, // Only CRITICAL
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := s.filterBySeverity(findings, tt.minSeverity)
			if len(filtered) != tt.wantCount {
				t.Errorf("Expected %d findings, got %d", tt.wantCount, len(filtered))
			}
		})
	}
}

func TestSASTScanner_FilterBySeverity_Empty(t *testing.T) {
	binMgr := binary.NewBinaryManager()
	s := NewSASTScanner(binMgr)

	findings := []types.Violation{}
	filtered := s.filterBySeverity(findings, "MEDIUM")

	if len(filtered) != 0 {
		t.Errorf("Expected 0 findings for empty input, got %d", len(filtered))
	}
}

func TestSASTScanner_FilterBySeverity_AllFiltered(t *testing.T) {
	binMgr := binary.NewBinaryManager()
	s := NewSASTScanner(binMgr)

	findings := []types.Violation{
		{Severity: "LOW", Rule: "test1"},
		{Severity: "LOW", Rule: "test2"},
	}

	filtered := s.filterBySeverity(findings, "MEDIUM")

	if len(filtered) != 0 {
		t.Errorf("Expected 0 findings (all LOW filtered), got %d", len(filtered))
	}
}

func TestSASTScannerEffectiveMinSeverity(t *testing.T) {
	s := NewSASTScanner(binary.NewBinaryManager())
	findings := []types.Violation{
		{Severity: types.SeverityLow, Rule: "low"},
		{Severity: types.SeverityMedium, Rule: "medium"},
		{Severity: types.SeverityHigh, Rule: "high"},
		{Severity: types.SeverityCritical, Rule: "critical"},
	}

	tests := []struct {
		name      string
		args      ScanArgs
		wantFloor string
		wantKept  int
	}{
		{
			name:      "omitted uses default LOW",
			wantFloor: types.SeverityLow,
			wantKept:  4,
		},
		{
			name:      "explicit LOW",
			args:      ScanArgs{MinSeverity: types.SeverityLow},
			wantFloor: types.SeverityLow,
			wantKept:  4,
		},
		{
			name:      "explicit HIGH",
			args:      ScanArgs{MinSeverity: types.SeverityHigh},
			wantFloor: types.SeverityHigh,
			wantKept:  2,
		},
		{
			name:      "explicit CRITICAL",
			args:      ScanArgs{MinSeverity: types.SeverityCritical},
			wantFloor: types.SeverityCritical,
			wantKept:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.effectiveMinSeverity(tt.args)
			if got != tt.wantFloor {
				t.Fatalf("effectiveMinSeverity() = %q, want %q", got, tt.wantFloor)
			}
			filtered := s.filterBySeverity(findings, got)
			if len(filtered) != tt.wantKept {
				t.Fatalf("filtered count = %d, want %d", len(filtered), tt.wantKept)
			}
		})
	}
}

func TestNewSASTScanner_DefaultConfig(t *testing.T) {
	binMgr := binary.NewBinaryManager()
	s := NewSASTScanner(binMgr)

	if s.filterConfig.MinSeverity != "LOW" {
		t.Errorf("Expected default MinSeverity=LOW, got %s", s.filterConfig.MinSeverity)
	}

	if !s.filterConfig.Enabled {
		t.Error("Expected filtering to be enabled by default")
	}
}

func TestSASTScanner_Execute_ContextCancellation(t *testing.T) {
	binMgr := binary.NewBinaryManager()
	s := NewSASTScanner(binMgr)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	args := ScanArgs{
		FilePaths:  []string{"."},
		WorkingDir: ".",
	}

	_, err := s.Execute(ctx, args)

	// Expect an error due to context cancellation
	// The exact error depends on whether the binary is found or not
	// If binary not found, we get that error first
	// If binary is found, we get context cancelled error
	if err == nil {
		t.Error("Expected an error due to context cancellation, got nil")
	}
}

// Integration test: TestSASTScanner_Execute_Integration
// This test would require the actual datadog-static-analyzer binary
// For unit testing, we test individual methods in isolation
// Real E2E testing is done via the CLI commands

func TestSASTScanner_FilteringWithDifferentSeverities(t *testing.T) {
	binMgr := binary.NewBinaryManager()
	s := NewSASTScanner(binMgr)

	findings := []types.Violation{
		{Severity: "CRITICAL", Rule: "crit1"},
		{Severity: "CRITICAL", Rule: "crit2"},
		{Severity: "HIGH", Rule: "high1"},
		{Severity: "HIGH", Rule: "high2"},
		{Severity: "HIGH", Rule: "high3"},
		{Severity: "MEDIUM", Rule: "med1"},
		{Severity: "MEDIUM", Rule: "med2"},
		{Severity: "LOW", Rule: "low1"},
		{Severity: "LOW", Rule: "low2"},
		{Severity: "LOW", Rule: "low3"},
		{Severity: "LOW", Rule: "low4"},
	}

	// Test default behavior (LOW and above)
	filtered := s.filterBySeverity(findings, s.filterConfig.MinSeverity)

	// All scanner severities are visible by default.
	expectedCount := len(findings)
	if len(filtered) != expectedCount {
		t.Errorf("Expected %d findings with default filter (LOW), got %d", expectedCount, len(filtered))
	}
}
