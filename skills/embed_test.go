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
		"datadog-code-security-remediation",
		"datadog-code-security-verification",
		"datadog-code-security-toolchain",
	}
	for _, skillID := range skillIDs {
		if _, err := fs.Stat(FS, skillID+"/SKILL.md"); err != nil {
			t.Errorf("missing %s/SKILL.md: %v", skillID, err)
		}
	}

	for _, playbook := range []string{"sast.md", "sca.md", "iac.md", "secrets.md"} {
		path := "datadog-code-security-remediation/references/" + playbook
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
