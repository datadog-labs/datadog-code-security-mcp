package scan

import (
	"context"
	"reflect"
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
