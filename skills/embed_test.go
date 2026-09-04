package skills

import (
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"
)

var markdownLinkRE = regexp.MustCompile(`\[[^\]]+\]\(([^)]+)\)`)

// wrapperCLIInvocationRE matches shipped skill instructions that run the wrapper
// CLI. Brew, GitHub, and prose mentions of the binary name are excluded because
// they are not followed by a wrapper subcommand.
var wrapperCLIInvocationRE = regexp.MustCompile(`datadog-code-security-mcp\s+(?:scan|version|setup|generate-sbom|start)\b[^` + "`" + `\n|]*`)

func TestFSContainsShippedSkills(t *testing.T) {
	skillIDs := []string{
		"dd-codesec-scan-and-fix",
		"dd-codesec-verify-findings",
		"dd-codesec-setup-toolchain",
	}
	for _, skillID := range skillIDs {
		if _, err := fs.Stat(FS, skillID+"/SKILL.md"); err != nil {
			t.Errorf("missing %s/SKILL.md: %v", skillID, err)
		}
	}

	for _, playbook := range []string{"sast.md", "sca.md", "iac.md", "secrets.md"} {
		path := "dd-codesec-scan-and-fix/references/" + playbook
		if _, err := fs.Stat(FS, path); err != nil {
			t.Errorf("missing %s: %v", path, err)
		}
	}
}

func TestShippedSkillMarkdownLinksResolve(t *testing.T) {
	err := fs.WalkDir(FS, ".", func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || path.Ext(filename) != ".md" {
			return nil
		}

		data, err := fs.ReadFile(FS, filename)
		if err != nil {
			return err
		}
		for _, match := range markdownLinkRE.FindAllStringSubmatch(string(data), -1) {
			target := strings.TrimSpace(match[1])
			if target == "" || strings.HasPrefix(target, "#") || strings.Contains(target, "://") {
				continue
			}
			if fragment := strings.IndexByte(target, '#'); fragment >= 0 {
				target = target[:fragment]
			}
			resolved := path.Clean(path.Join(path.Dir(filename), target))
			if resolved == ".." || strings.HasPrefix(resolved, "../") {
				t.Errorf("%s contains link outside embedded skills: %s", filename, match[1])
				continue
			}
			if _, err := fs.Stat(FS, resolved); err != nil {
				t.Errorf("%s contains unresolved link %s: %v", filename, match[1], err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded skills: %v", err)
	}
}

func TestShippedSkillsAttributeWrapperCLIInvocations(t *testing.T) {
	err := fs.WalkDir(FS, ".", func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || path.Ext(filename) != ".md" {
			return nil
		}

		data, err := fs.ReadFile(FS, filename)
		if err != nil {
			return err
		}
		for _, match := range wrapperCLIInvocationRE.FindAllString(string(data), -1) {
			if !strings.Contains(match, "--called-by-skill") {
				t.Errorf("%s invokes the wrapper without --called-by-skill: %s", filename, match)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded skills: %v", err)
	}
}

func TestScanSkillsPreferLocalMCP(t *testing.T) {
	for _, skillID := range []string{
		"dd-codesec-scan-and-fix",
		"dd-codesec-verify-findings",
	} {
		data, err := fs.ReadFile(FS, skillID+"/SKILL.md")
		if err != nil {
			t.Fatalf("read %s/SKILL.md: %v", skillID, err)
		}
		text := strings.Join(strings.Fields(string(data)), " ")
		prefersMCP := strings.Contains(text, "Prefer the local Code Security MCP") ||
			strings.Contains(text, "Prefer the matching local Code Security MCP")
		if !prefersMCP {
			t.Errorf("%s does not prefer local Code Security MCP scan tools", skillID)
		}
		if !strings.Contains(text, "Fall back to") {
			t.Errorf("%s does not describe CLI as a fallback", skillID)
		}
		if strings.Contains(text, "Preferred CLI") || strings.Contains(text, "Local MCP fallback") {
			t.Errorf("%s still presents the CLI as the preferred scan path", skillID)
		}
		if !strings.Contains(text, "ALL_TOOLS") || !strings.Contains(text, "deferred") {
			t.Errorf("%s does not require complete MCP tool-registry discovery before CLI fallback", skillID)
		}
		if !strings.Contains(text, "same scanner binaries") {
			t.Errorf("%s does not require toolchain preflight for MCP and CLI scans alike", skillID)
		}
	}
}
