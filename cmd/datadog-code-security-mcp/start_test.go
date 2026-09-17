package main

import (
	"testing"

	"github.com/mark3labs/mcp-go/server"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/constants"
)

func TestSecurityToolsAdvertiseOptionalCalledBySkill(t *testing.T) {
	s := server.NewMCPServer("datadog-code-security-mcp", "test")
	registerSecurityTools(s)

	tools := s.ListTools()
	if len(tools) == 0 {
		t.Fatal("no MCP tools registered")
	}
	for name, tool := range tools {
		if tool == nil {
			t.Errorf("registered tool %q is nil", name)
			continue
		}
		prop, ok := tool.Tool.InputSchema.Properties[constants.ArgCalledBySkill].(map[string]any)
		if !ok {
			t.Errorf("%s is missing optional %s argument", name, constants.ArgCalledBySkill)
			continue
		}
		if prop["type"] != "boolean" {
			t.Errorf("%s %s type = %v, want boolean", name, constants.ArgCalledBySkill, prop["type"])
		}
		for _, required := range tool.Tool.InputSchema.Required {
			if required == constants.ArgCalledBySkill {
				t.Errorf("%s must not require %s", name, constants.ArgCalledBySkill)
			}
		}
	}
}
