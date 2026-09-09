package processing

import (
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

func TestParseSARIFExcludesSuppressedResults(t *testing.T) {
	data := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {
				"name": "test",
				"rules": [{"id": "test/rule", "defaultConfiguration": {"level": "warning"}}]
			}},
			"results": [
				{
					"ruleId": "test/rule",
					"level": "warning",
					"message": {"text": "visible"},
					"locations": [{"physicalLocation": {
						"artifactLocation": {"uri": "visible.go"},
						"region": {"startLine": 3}
					}}]
				},
				{
					"ruleId": "test/rule",
					"level": "warning",
					"message": {"text": "suppressed"},
					"suppressions": [{"kind": "inSource", "status": "accepted"}],
					"locations": [{"physicalLocation": {
						"artifactLocation": {"uri": "suppressed.go"},
						"region": {"startLine": 7}
					}}]
				}
			]
		}]
	}`)

	findings, err := ParseSARIF(data, ".", types.DetectionTypeSAST)
	if err != nil {
		t.Fatalf("ParseSARIF() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(findings))
	}
	if findings[0].File != "visible.go" {
		t.Fatalf("finding file = %q, want visible.go", findings[0].File)
	}
}
