package scan

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

func TestExecuteScanEarlyFailureRetainsDefaultScanTypes(t *testing.T) {
	outcome := ExecuteScan(context.Background(), ScanArgs{})
	if outcome.Err() == nil {
		t.Fatal("expected missing file paths to fail")
	}
	if got, want := outcome.ScanTypes(), types.SecurityScanTypes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("scan types = %v, want %v", got, want)
	}
}

func TestNormalizeMinSASTSeverity(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "default", want: types.SeverityLow},
		{name: "lowercase", input: "medium", want: types.SeverityMedium},
		{name: "trimmed", input: " HIGH ", want: types.SeverityHigh},
		{name: "critical", input: types.SeverityCritical, want: types.SeverityCritical},
		{name: "invalid", input: "info", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeMinSASTSeverity(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected validation error")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeMinSASTSeverity() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("normalizeMinSASTSeverity() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExecuteScanRejectsInvalidMinSASTSeverityBeforeExecution(t *testing.T) {
	cases := []struct {
		name      string
		scanTypes []string
	}{
		{name: "sast only", scanTypes: []string{"sast"}},
		{name: "mixed including sast", scanTypes: []string{"secrets", "sast"}},
		{name: "default scan set", scanTypes: nil},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			outcome := ExecuteScan(context.Background(), ScanArgs{
				FilePaths:       []string{"."},
				ScanTypes:       tt.scanTypes,
				MinSASTSeverity: "INFO",
			})
			if outcome.Err() == nil {
				t.Fatal("expected invalid min SAST severity to fail")
			}
			if !strings.Contains(outcome.Err().Error(), "invalid min_sast_severity") {
				t.Fatalf("error = %q, want invalid min_sast_severity", outcome.Err())
			}
		})
	}
}

func TestExecuteScanIgnoresMinSASTSeverityWhenSASTNotSelected(t *testing.T) {
	for _, scanType := range []string{"secrets", "sca", "iac"} {
		t.Run(scanType, func(t *testing.T) {
			outcome := ExecuteScan(context.Background(), ScanArgs{
				FilePaths:       []string{"does-not-exist"},
				ScanTypes:       []string{scanType},
				MinSASTSeverity: "yolo",
			})
			if outcome.Err() == nil {
				t.Fatal("expected missing path to fail")
			}
			if strings.Contains(outcome.Err().Error(), "invalid min_sast_severity") {
				t.Fatalf("non-SAST scan rejected min_sast_severity: %v", outcome.Err())
			}
			if !strings.Contains(outcome.Err().Error(), "does not exist") {
				t.Fatalf("error = %q, want path does not exist", outcome.Err())
			}
		})
	}
}
