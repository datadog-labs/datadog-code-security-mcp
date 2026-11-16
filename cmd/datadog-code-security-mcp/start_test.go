package main

import (
	"context"
	"io/fs"
	"path"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/constants"
	"github.com/datadog-labs/datadog-code-security-mcp/skills"
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

func TestServerAdvertisesInstructionsOnInitialize(t *testing.T) {
	s := newMCPServer(serverInstructions)
	registerSecurityTools(s)

	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":` +
		`{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`)
	resp, ok := s.HandleMessage(context.Background(), msg).(mcp.JSONRPCResponse)
	if !ok {
		t.Fatal("initialize did not return a JSON-RPC response")
	}
	result, ok := resp.Result.(mcp.InitializeResult)
	if !ok {
		t.Fatalf("initialize result has type %T, want mcp.InitializeResult", resp.Result)
	}
	if result.Instructions != serverInstructions {
		t.Errorf("initialize instructions = %q, want serverInstructions", result.Instructions)
	}
}

func TestServerInstructionsFallBackWithoutSkills(t *testing.T) {
	want := " Pass called_by_skill: true when a skill tells you to. " +
		"If the Datadog Code Security skills are not installed, call the tools directly."
	if !strings.HasSuffix(serverInstructions, want) {
		t.Errorf("server instructions do not end with the no-skill fallback: %q", serverInstructions)
	}
}

func TestServerInstructionsNameEmbeddedSkills(t *testing.T) {
	for _, skill := range []string{"scan-and-fix", "verify-findings", "find-security-variants"} {
		requireEmbeddedSkill(t, skill)
		if !strings.Contains(serverInstructions, "dd-codesec-"+skill) {
			t.Errorf("server instructions do not name dd-codesec-%s", skill)
		}
		if !strings.Contains(serverInstructions, "datadog/code-security/"+skill) {
			t.Errorf("server instructions do not name datadog/code-security/%s", skill)
		}
	}
}

func TestSecurityToolDescriptionsPointToSkill(t *testing.T) {
	s := server.NewMCPServer("datadog-code-security-mcp", "test")
	registerSecurityTools(s)

	tools := s.ListTools()
	if len(tools) != len(toolSkills) {
		t.Errorf("registered %d tools, toolSkills maps %d", len(tools), len(toolSkills))
	}
	for name, tool := range tools {
		skill, ok := toolSkills[name]
		if !ok {
			t.Errorf("%s has no entry in toolSkills", name)
			continue
		}
		requireEmbeddedSkill(t, skill)
		if !strings.HasPrefix(tool.Tool.Description, skillStepPrefix(skill)+"\n\n") {
			t.Errorf("%s description does not start with the dd-codesec-%s prefix", name, skill)
		}
	}
}

func requireEmbeddedSkill(t *testing.T, skill string) {
	t.Helper()
	if _, err := fs.Stat(skills.FS, path.Join("dd-codesec-"+skill, "SKILL.md")); err != nil {
		t.Errorf("skill dd-codesec-%s is not embedded: %v", skill, err)
	}
}

func TestSkillStepPrefixWording(t *testing.T) {
	want := "Step of the Datadog Code Security skills: load the dd-codesec-scan-and-fix skill " +
		"(datadog/code-security/scan-and-fix on the Datadog MCP server) before calling this tool, and follow it. " +
		"If the skill is not installed, call this tool directly."
	if got := skillStepPrefix("scan-and-fix"); got != want {
		t.Errorf("skillStepPrefix = %q, want %q", got, want)
	}
}

func TestInstructionsForKeepsValidatedTextWithoutUpdate(t *testing.T) {
	if got := instructionsFor(""); got != serverInstructions {
		t.Errorf("instructionsFor(\"\") changed the validated instructions: %q", got)
	}
}

func TestInstructionsForAppendsUpdateNotice(t *testing.T) {
	got := instructionsFor("9.9.9")
	if !strings.HasPrefix(got, serverInstructions+" ") {
		t.Fatal("update notice must follow the unchanged server instructions")
	}
	notice := strings.TrimPrefix(got, serverInstructions)
	for _, want := range []string{
		"9.9.9",
		"this server runs " + version,
		"dd-codesec-setup-toolchain",
		"brew upgrade datadog-labs/pack/datadog-code-security-mcp",
		"datadog-code-security-mcp setup",
	} {
		if !strings.Contains(notice, want) {
			t.Errorf("update notice does not mention %q: %q", want, notice)
		}
	}
	requireEmbeddedSkill(t, "setup-toolchain")
}
