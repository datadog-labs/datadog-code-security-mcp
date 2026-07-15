package scan

import (
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

// TestCloneExecution_NoticeIsDeepCopied pins the defensive-copy contract of
// Execution(): mutating a Notice obtained from the accessor must never be
// observable through the outcome's internal state.
func TestCloneExecution_NoticeIsDeepCopied(t *testing.T) {
	outcome := NewCompletedOutcome([]ScanExecution{
		{
			DetectionType: types.DetectionTypeSCA,
			Notice: &types.ScanNotice{
				DetectionType: types.DetectionTypeSCA,
				Message:       "original",
			},
		},
	})

	execution, ok := outcome.Execution(string(types.DetectionTypeSCA))
	if !ok {
		t.Fatal("expected to find the sca execution")
	}
	execution.Notice.Message = "mutated via Execution"
	if got := outcome.executions[0].Notice.Message; got != "original" {
		t.Errorf("Execution() leaked a shared Notice pointer; internal state became %q", got)
	}
}
