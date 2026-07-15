package scan

import (
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

// TestCloneExecution_NoticeIsDeepCopied pins the defensive-copy contract of
// Executions()/Execution(): mutating a Notice obtained from either accessor
// must never be observable through the outcome's internal state.
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

	executions := outcome.Executions()
	executions[0].Notice.Message = "mutated via Executions"
	if got := outcome.executions[0].Notice.Message; got != "original" {
		t.Errorf("Executions() leaked a shared Notice pointer; internal state became %q", got)
	}

	execution, ok := outcome.Execution(string(types.DetectionTypeSCA))
	if !ok {
		t.Fatal("expected to find the sca execution")
	}
	execution.Notice.Message = "mutated via Execution"
	if got := outcome.executions[0].Notice.Message; got != "original" {
		t.Errorf("Execution() leaked a shared Notice pointer; internal state became %q", got)
	}
}
