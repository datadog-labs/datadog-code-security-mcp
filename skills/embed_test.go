package skills

import (
	"io/fs"
	"testing"
)

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
