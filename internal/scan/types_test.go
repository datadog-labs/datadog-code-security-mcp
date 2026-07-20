package scan

import (
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

// TestNewCompletedOutcome_NoticeDeepCopiedAtIngest pins the single
// defensive-copy boundary: ingest deep-copies each execution (including the
// Notice pointee), so mutating the caller's original Notice after construction
// must never be observable through the outcome.
func TestNewCompletedOutcome_NoticeDeepCopiedAtIngest(t *testing.T) {
	original := &types.ScanNotice{
		DetectionType: types.DetectionTypeSCA,
		Message:       "original",
	}
	outcome := NewCompletedOutcome([]ScanExecution{
		{DetectionType: types.DetectionTypeSCA, Notice: original},
	})

	// Mutating the caller's slice/pointer after construction must not leak in.
	original.Message = "mutated by caller"

	execution, ok := outcome.Execution(string(types.DetectionTypeSCA))
	if !ok {
		t.Fatal("expected to find the sca execution")
	}
	if execution.Notice.Message != "original" {
		t.Errorf("ingest did not deep-copy Notice; got %q", execution.Notice.Message)
	}
}
