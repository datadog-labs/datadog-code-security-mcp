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

func TestNormalizeMinSeverity(t *testing.T) {
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
			got, err := normalizeMinSeverity(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected validation error")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeMinSeverity() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("normalizeMinSeverity() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExecuteScanRejectsInvalidMinSeverityBeforeExecution(t *testing.T) {
	outcome := ExecuteScan(context.Background(), ScanArgs{
		FilePaths:   []string{"."},
		ScanTypes:   []string{"sast"},
		MinSeverity: "INFO",
	})
	if outcome.Err() == nil {
		t.Fatal("expected invalid min severity to fail")
	}
	if !strings.Contains(outcome.Err().Error(), "invalid min_severity") {
		t.Fatalf("error = %q, want invalid min_severity", outcome.Err())
	}
}
