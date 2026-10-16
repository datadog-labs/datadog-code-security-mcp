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

func TestShippedSkillsAttributeMCPToolCalls(t *testing.T) {
	for _, skillID := range []string{
		"dd-codesec-scan-and-fix",
		"dd-codesec-verify-findings",
		"dd-codesec-setup-toolchain",
	} {
		data, err := fs.ReadFile(FS, skillID+"/SKILL.md")
		if err != nil {
			t.Fatalf("read %s/SKILL.md: %v", skillID, err)
		}
		text := strings.Join(strings.Fields(string(data)), " ")
		if !strings.Contains(text, "called_by_skill: true") {
			t.Errorf("%s does not instruct MCP calls to pass called_by_skill: true", skillID)
		}
		if strings.Contains(strings.ToLower(text), "do not take this flag") {
			t.Errorf("%s still says MCP calls skip skill attribution", skillID)
		}
		if !strings.Contains(text, "outside this skill's workflow") {
			t.Errorf("%s does not tell the agent to omit called_by_skill outside this workflow", skillID)
		}
	}
}

func TestPlatformMatchingRemediationGuidance(t *testing.T) {
	data, err := fs.ReadFile(FS, "dd-codesec-verify-findings/references/platform-matching.md")
	if err != nil {
		t.Fatalf("read platform-matching.md: %v", err)
	}
	text := strings.Join(strings.Fields(string(data)), " ")
	for _, want := range []string{
		"`library_vulnerability` payloads carry them too",
		"never report whether a Datadog-generated fix is open, merged, or under review",
		"`fixed_advisories[].id` includes this finding's `@advisory.id`",
		"Use one candidate's identity and `version` together",
		"Identify a candidate by `original_name`",
		"Take the identifier for any command from the local manifest or lockfile",
		"`new_advisories` is empty or absent",
		"The match is case-sensitive, so a mixed-case ID returns nothing",
		"An empty result from an unnormalized identity is not evidence that the platform has no findings",
		"Prefer a lockfile refresh when one suffices",
		"This is the only case that departs from a qualifying recommendation",
		"Otherwise default to the platform's pick",
		"If the recommendation is absent or does not qualify, fall back to another qualifying candidate and say why",
		"prefer `closest_*` over `latest_*`",
		"`commons-collections:20040616`",
		"from `remaining_advisories`",
		"mention its version as information only; do not offer it as a choice",
		"pre-release or Go pseudo-version",
		"even if that means pinning the transitive package instead of upgrading the direct dependency",
		"Ignore a leading `v` when comparing versions",
		"find the candidate with the same `original_name` and `version`",
		"If no candidate qualifies, say so rather than picking one",
		"If the vulnerable package is transitive and a candidate that fixes this advisory without new ones has `is_auto_solvable: true`",
		"use the entry whose `name` matches the candidate",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("platform-matching.md does not state: %s", want)
		}
	}

	sca, err := fs.ReadFile(FS, "dd-codesec-scan-and-fix/references/sca.md")
	if err != nil {
		t.Fatalf("read sca.md: %v", err)
	}
	scaText := strings.Join(strings.Fields(string(sca)), " ")
	for _, want := range []string{
		"If a transitive package's existing constraints already allow a fixed version",
		"(ecosystem, recommended package)",
		"once per package upgrade",
		"separate list of findings with no recommended upgrade",
		"use `@remediation.recommended.name`, the field the platform groups package updates by",
		"Do not group by `@remediation.package.base`: the platform does not group by it",
		"The local scan does not include a fix version",
		"A count of advisories does not replace this list",
		"The group keeps the recommended package as its name even when the proposed change uses another candidate",
		"In every group where the package or version differs",
		"Local SCA results do not include a package URL or ecosystem",
		"report them as pending until the next platform scan, not as fixed",
		"which defaults to the recommendation",
		"take the parent from the `root_package` candidate",
		"because the recommendation does not qualify or a lockfile refresh suffices",
		"Transitive packages that share a recommended parent stay in one group",
		"If the recommended package is not in the local dependency graph, name the group after the package you would change instead",
		"never treat a package missing from a partial result as having no platform record",
		"list the advisories the upgrade leaves open",
	} {
		if !strings.Contains(scaText, want) {
			t.Errorf("sca.md does not state: %s", want)
		}
	}

	skill, err := fs.ReadFile(FS, "dd-codesec-scan-and-fix/SKILL.md")
	if err != nil {
		t.Fatalf("read SKILL.md: %v", err)
	}
	skillText := strings.Join(strings.Fields(string(skill)), " ")
	if !strings.Contains(skillText, "one finding at a time, except SCA") {
		t.Error("SKILL.md still applies fixes one finding at a time for SCA")
	}
	for _, want := range []string{
		"For SCA, do not skip this lookup when the remote MCP is available",
		"as in the SCA playbook, only after enrichment",
		"A request to scan and fix is not approval of a specific change",
		"even for a lockfile-only refresh",
		"End the turn with the proposal as plain markdown and a direct question",
		"Do not put a proposal in a question card",
	} {
		if !strings.Contains(skillText, want) {
			t.Errorf("SKILL.md does not state: %s", want)
		}
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

func TestSkillsDoNotPrintMCPClientCredentials(t *testing.T) {
	for _, skillID := range []string{
		"dd-codesec-scan-and-fix",
		"dd-codesec-setup-toolchain",
		"dd-codesec-verify-findings",
	} {
		data, err := fs.ReadFile(FS, skillID+"/SKILL.md")
		if err != nil {
			t.Fatalf("read %s/SKILL.md: %v", skillID, err)
		}
		text := strings.Join(strings.Fields(string(data)), " ")
		if !strings.Contains(text, "extract only the server's `command` value") ||
			!strings.Contains(text, "never print the file, its `env` block") {
			t.Errorf("%s does not forbid printing MCP client configuration credentials", skillID)
		}
	}
}
