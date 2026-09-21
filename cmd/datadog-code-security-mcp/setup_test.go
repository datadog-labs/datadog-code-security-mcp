package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	setupcmd "github.com/datadog-labs/datadog-code-security-mcp/internal/setup"
)

func setSetupTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("PATH", "")
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	return home
}

func TestSetupCommandDryRunWritesNothing(t *testing.T) {
	home := setSetupTestHome(t)

	var output bytes.Buffer
	cmd := newSetupCmd()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--client", "agents", "--dry-run"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "would be installed") {
		t.Fatalf("dry-run output = %q", output.String())
	}
	if !strings.Contains(output.String(), "Dry run complete.") {
		t.Fatalf("dry-run footer missing: %q", output.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".agents", "skills")); !os.IsNotExist(err) {
		t.Fatalf("dry run created skills directory: %v", err)
	}
}

func TestSetupCommandJSONOutput(t *testing.T) {
	home := setSetupTestHome(t)
	if err := os.Mkdir(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	cmd := newSetupCmd()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--client", "codex", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var report setupJSONReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON output %q: %v", output.String(), err)
	}
	if report.DryRun {
		t.Fatal("install JSON reported dry_run=true")
	}
	if len(report.Clients) != 1 || report.Clients[0].ClientID != "codex" {
		t.Fatalf("JSON result = %+v", report)
	}
	if report.Clients[0].Status != setupcmd.ClientStatusApplied {
		t.Fatalf("JSON status = %q, want %q", report.Clients[0].Status, setupcmd.ClientStatusApplied)
	}
	if len(report.Clients[0].Changes) != 3 {
		t.Fatalf("installed changes = %d, want 3", len(report.Clients[0].Changes))
	}
}

func TestSetupCommandRejectsUnknownClient(t *testing.T) {
	setSetupTestHome(t)
	cmd := newSetupCmd()
	cmd.SetArgs([]string{"--client", "unknown"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("setup accepted unknown client")
	}
}

func TestSetupCommandConfiguresClaudeBudget(t *testing.T) {
	home := setSetupTestHome(t)
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	cmd := newSetupCmd()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--client", "claude-code"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "skillListingBudgetFraction floor to 0.02") {
		t.Fatalf("setup output = %q", output.String())
	}
	data, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"skillListingBudgetFraction": 0.02`) {
		t.Fatalf("settings = %s", data)
	}
}

func TestSetupCommandCanSkipClaudeBudget(t *testing.T) {
	home := setSetupTestHome(t)
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	cmd := newSetupCmd()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--client", "claude-code", "--skip-skill-listing-budget"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "disabled by --skip-skill-listing-budget") {
		t.Fatalf("setup output = %q", output.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("settings file exists after opt-out: %v", err)
	}
}

func TestSetupCommandInstallsSkillsWhenClaudeSettingsAreMalformed(t *testing.T) {
	home := setSetupTestHome(t)
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	const malformed = `{"skillListingBudgetFraction":`
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(malformed), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	cmd := newSetupCmd()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--client", "claude-code"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "could not update Claude Code skill-listing budget") {
		t.Fatalf("setup output = %q", output.String())
	}
	if !strings.Contains(output.String(), "--skip-skill-listing-budget") {
		t.Fatalf("setup output missing skip flag: %q", output.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "skills", "dd-codesec-scan-and-fix", "SKILL.md")); err != nil {
		t.Fatalf("skills were not installed: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != malformed {
		t.Fatalf("malformed settings were overwritten: %q", data)
	}
}

func TestSetupCommandUsesClaudeConfigDir(t *testing.T) {
	home := setSetupTestHome(t)
	configDir := filepath.Join(home, "custom-claude")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", configDir)

	cmd := newSetupCmd()
	cmd.SetArgs([]string{"--client", "claude-code"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(configDir, "settings.json"),
		filepath.Join(configDir, "skills", "dd-codesec-scan-and-fix", "SKILL.md"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("custom Claude config path %s was not written: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".claude")); !os.IsNotExist(err) {
		t.Fatalf("default Claude directory exists with CLAUDE_CONFIG_DIR set: %v", err)
	}
}

func TestSetupCommandRejectsClaudeConfigDirFileWhenClaudeDetected(t *testing.T) {
	home := setSetupTestHome(t)
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(home, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", file)

	var output bytes.Buffer
	cmd := newSetupCmd()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--client", "claude-code"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("setup succeeded with a file CLAUDE_CONFIG_DIR while Claude was detected")
	}
	if !strings.Contains(err.Error(), "Claude Code") {
		t.Fatalf("error = %v, want Claude Code failure", err)
	}
	if !strings.Contains(output.String(), "not a directory") {
		t.Fatalf("output = %q, want not a directory", output.String())
	}
}

func TestSetupCommandSkipsInvalidClaudeConfigDirWhenClaudeMissing(t *testing.T) {
	home := setSetupTestHome(t)
	file := filepath.Join(home, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", file)

	cmd := newSetupCmd()
	cmd.SetArgs([]string{"--client", "claude-code"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestSetupCommandInstallsAgentsWhenClaudeConfigDirIsFile(t *testing.T) {
	home := setSetupTestHome(t)
	file := filepath.Join(home, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", file)

	cmd := newSetupCmd()
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".agents", "skills", "dd-codesec-scan-and-fix", "SKILL.md")); err != nil {
		t.Fatalf("Agent Skills were not installed: %v", err)
	}
}

func TestSetupCommandFailsClaudeButInstallsAgentsWhenDetected(t *testing.T) {
	home := setSetupTestHome(t)
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(home, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", file)

	var output bytes.Buffer
	cmd := newSetupCmd()
	cmd.SetOut(&output)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("setup succeeded with a file CLAUDE_CONFIG_DIR while Claude was detected")
	}
	if !strings.Contains(err.Error(), "Claude Code") {
		t.Fatalf("error = %v, want Claude Code failure", err)
	}
	if strings.Contains(err.Error(), "Agent Skills") || strings.Contains(err.Error(), "Codex") {
		t.Fatalf("non-Claude clients were reported as failed: %v", err)
	}
	for _, path := range []string{
		filepath.Join(home, ".agents", "skills", "dd-codesec-scan-and-fix", "SKILL.md"),
		filepath.Join(home, ".codex", "skills", "dd-codesec-scan-and-fix", "SKILL.md"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("other client was not installed: %v", err)
		}
	}
}

func TestSetupCommandIgnoresClaudeConfigDirFileWhenClaudeNotSelected(t *testing.T) {
	home := setSetupTestHome(t)
	file := filepath.Join(home, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", file)

	cmd := newSetupCmd()
	cmd.SetArgs([]string{"--client", "agents"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".agents", "skills", "dd-codesec-scan-and-fix", "SKILL.md")); err != nil {
		t.Fatalf("agents setup failed: %v", err)
	}
}

func TestSetupCommandResolvesRelativeClaudeConfigDir(t *testing.T) {
	home := setSetupTestHome(t)
	configDir := filepath.Join(home, "custom-claude")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(cwd, configDir)
	if err != nil {
		t.Skip(err)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", rel)

	cmd := newSetupCmd()
	cmd.SetArgs([]string{"--client", "claude-code"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "settings.json")); err != nil {
		t.Fatalf("relative CLAUDE_CONFIG_DIR was not resolved: %v", err)
	}
}

func TestSetupCommandRemoveSkillsLeavesUnmarkedDirectories(t *testing.T) {
	home := setSetupTestHome(t)

	install := newSetupCmd()
	install.SetArgs([]string{"--client", "agents"})
	if err := install.Execute(); err != nil {
		t.Fatal(err)
	}

	userSkill := filepath.Join(home, ".agents", "skills", "user-skill")
	if err := os.MkdirAll(userSkill, 0o700); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(home, ".agents", "skills", "dd-codesec-scan-and-fix", "SKILL.md")

	var preview bytes.Buffer
	dryRun := newSetupCmd()
	dryRun.SetOut(&preview)
	dryRun.SetArgs([]string{"--client", "agents", "--remove-skills", "--dry-run"})
	if err := dryRun.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(preview.String(), "would be removed") {
		t.Fatalf("remove dry-run output = %q", preview.String())
	}
	if _, err := os.Stat(managed); err != nil {
		t.Fatalf("remove dry-run deleted managed skills: %v", err)
	}

	var output bytes.Buffer
	remove := newSetupCmd()
	remove.SetOut(&output)
	remove.SetArgs([]string{"--client", "agents", "--remove-skills", "--json"})
	if err := remove.Execute(); err != nil {
		t.Fatal(err)
	}
	var report setupJSONReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON output %q: %v", output.String(), err)
	}
	if len(report.Clients) != 1 || report.Clients[0].Status != setupcmd.ClientStatusApplied {
		t.Fatalf("remove JSON result = %+v", report)
	}
	if len(report.Clients[0].Changes) != 3 {
		t.Fatalf("removed changes = %d, want 3", len(report.Clients[0].Changes))
	}
	for _, change := range report.Clients[0].Changes {
		if change.Action != setupcmd.SkillActionRemoved {
			t.Fatalf("unexpected change: %+v", change)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".agents", "skills", "dd-codesec-scan-and-fix")); !os.IsNotExist(err) {
		t.Fatalf("managed skill survived --remove-skills: %v", err)
	}
	if _, err := os.Stat(userSkill); err != nil {
		t.Fatalf("unmarked skill was removed: %v", err)
	}
}

func TestSetupCommandReturnsFailureWithoutWrites(t *testing.T) {
	home := setSetupTestHome(t)
	collision := filepath.Join(home, ".agents", "skills", "dd-codesec-scan-and-fix")
	if err := os.MkdirAll(collision, 0o700); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	cmd := newSetupCmd()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--client", "agents"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("setup reported success for an unowned skill collision")
	}
	if !strings.Contains(output.String(), "Agent Skills: failed") {
		t.Fatalf("failure output = %q", output.String())
	}
	if strings.Contains(output.String(), "Restart") {
		t.Fatalf("blocked client requested restart: %q", output.String())
	}
	skillsDir := filepath.Join(home, ".agents", "skills")
	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "dd-codesec-scan-and-fix" {
		t.Fatalf("blocked client mutated skills dir: %v", names(entries))
	}
}

func TestRenderSetupResultDoesNotRestartWhenAlreadyCurrent(t *testing.T) {
	var output bytes.Buffer
	err := renderSetupResult(&output, setupcmd.Result{
		Clients: []setupcmd.ClientResult{{
			ClientID:    "agents",
			DisplayName: "Agent Skills",
			Status:      setupcmd.ClientStatusApplied,
			SkillsDir:   "/tmp/skills",
		}},
	}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "Restart") {
		t.Fatalf("unchanged setup requested restart: %q", output.String())
	}
	if !strings.Contains(output.String(), "Agent Skills: no changes") {
		t.Fatalf("empty plan output = %q", output.String())
	}
}

func TestRenderSetupResultReportsSkippedClient(t *testing.T) {
	var output bytes.Buffer
	err := renderSetupResult(&output, setupcmd.Result{
		Clients: []setupcmd.ClientResult{{
			ClientID:    "codex",
			DisplayName: "Codex",
			Status:      setupcmd.ClientStatusSkipped,
			Reason:      "client CLI and home markers were not found",
		}},
	}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"○ Codex: skipped (client CLI and home markers were not found)",
		"No selected AI clients were detected",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("skipped client output %q does not contain %q", output.String(), want)
		}
	}
}

func TestRenderSetupResultDoesNotRestartAfterFailure(t *testing.T) {
	var output bytes.Buffer
	err := renderSetupResult(&output, setupcmd.Result{
		Clients: []setupcmd.ClientResult{{
			ClientID:    "agents",
			DisplayName: "Agent Skills",
			Status:      setupcmd.ClientStatusFailed,
			Reason:      "unowned skill directory",
		}},
	}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "Restart") {
		t.Fatalf("failed client requested restart: %q", output.String())
	}
}

func TestRenderSetupResultReportsPartialChangesAfterFailure(t *testing.T) {
	var output bytes.Buffer
	err := renderSetupResult(&output, setupcmd.Result{
		Clients: []setupcmd.ClientResult{{
			ClientID:    "agents",
			DisplayName: "Agent Skills",
			Status:      setupcmd.ClientStatusFailed,
			Reason:      "install second skill: disk full",
			Changes: []setupcmd.SkillChange{{
				SkillID: "dd-codesec-scan-and-fix",
				Action:  setupcmd.SkillActionInstalled,
			}},
		}},
	}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Agent Skills: failed",
		"Partial changes applied before failure:",
		"dd-codesec-scan-and-fix: installed",
		"Restart updated clients",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("partial failure output %q does not contain %q", output.String(), want)
		}
	}
}

func TestRenderSetupResultReportsSettingsAppliedBeforeFailure(t *testing.T) {
	var output bytes.Buffer
	err := renderSetupResult(&output, setupcmd.Result{
		Clients: []setupcmd.ClientResult{{
			ClientID:    "claude-code",
			DisplayName: "Claude Code",
			Status:      setupcmd.ClientStatusFailed,
			Reason:      "install skill: disk full",
			Settings: &setupcmd.SettingsChange{
				Path:   "/home/test/.claude/settings.json",
				Action: setupcmd.SettingsActionUpdated,
				Reason: "set skillListingBudgetFraction floor to 0.02",
			},
		}},
	}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Claude Code: failed",
		"Partial changes applied before failure:",
		"Claude settings /home/test/.claude/settings.json: updated",
		"Restart updated clients",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("partial failure output %q does not contain %q", output.String(), want)
		}
	}
}

func TestRenderSetupResultReportsFailedSettingsInsteadOfNoChanges(t *testing.T) {
	var output bytes.Buffer
	err := renderSetupResult(&output, setupcmd.Result{
		Clients: []setupcmd.ClientResult{{
			ClientID:    "claude-code",
			DisplayName: "Claude Code",
			Status:      setupcmd.ClientStatusApplied,
			SkillsDir:   "/home/test/.claude/skills",
			Settings: &setupcmd.SettingsChange{
				Path:   "/home/test/.claude/settings.json",
				Action: setupcmd.SettingsActionFailed,
				Reason: "replace Claude Code settings: permission denied",
			},
			Warnings: []string{"could not update Claude Code skill-listing budget: permission denied (use --skip-skill-listing-budget to skip this setting)"},
		}},
	}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "no changes") {
		t.Fatalf("failed settings reported as no changes: %q", output.String())
	}
	if strings.Contains(output.String(), "Restart") {
		t.Fatalf("failed settings requested restart: %q", output.String())
	}
	for _, want := range []string{
		"Claude settings /home/test/.claude/settings.json: failed",
		"could not update Claude Code skill-listing budget",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("failed settings output %q does not contain %q", output.String(), want)
		}
	}
}

func TestRenderSetupResultDoesNotTreatUnchangedSettingsAsPartialFailure(t *testing.T) {
	var output bytes.Buffer
	err := renderSetupResult(&output, setupcmd.Result{
		Clients: []setupcmd.ClientResult{{
			ClientID:    "claude-code",
			DisplayName: "Claude Code",
			Status:      setupcmd.ClientStatusFailed,
			Reason:      "unowned skill directory",
			Settings: &setupcmd.SettingsChange{
				Path:   "/home/test/.claude/settings.json",
				Action: setupcmd.SettingsActionUnchanged,
				Reason: "skillListingBudgetFraction is already 0.05",
			},
		}},
	}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "Partial changes applied before failure") {
		t.Fatalf("unchanged settings reported as partial changes: %q", output.String())
	}
	if strings.Contains(output.String(), "Restart") {
		t.Fatalf("unchanged settings requested restart: %q", output.String())
	}
}

func TestRenderSetupResultOmitsFailedSettingsFromPartialChanges(t *testing.T) {
	var output bytes.Buffer
	err := renderSetupResult(&output, setupcmd.Result{
		Clients: []setupcmd.ClientResult{{
			ClientID:    "claude-code",
			DisplayName: "Claude Code",
			Status:      setupcmd.ClientStatusFailed,
			Reason:      "install second skill: disk full",
			Changes: []setupcmd.SkillChange{{
				SkillID: "dd-codesec-scan-and-fix",
				Action:  setupcmd.SkillActionInstalled,
			}},
			Settings: &setupcmd.SettingsChange{
				Path:   "/home/test/.claude/settings.json",
				Action: setupcmd.SettingsActionFailed,
				Reason: "replace Claude Code settings: permission denied",
			},
		}},
	}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Claude Code: failed",
		"Partial changes applied before failure:",
		"dd-codesec-scan-and-fix: installed",
		"Restart updated clients",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("partial failure output %q does not contain %q", output.String(), want)
		}
	}
	if strings.Contains(output.String(), "Claude settings") {
		t.Fatalf("failed settings listed as a partial change: %q", output.String())
	}
}

func TestRenderSetupResultReportsCleanupWarningAfterUpdate(t *testing.T) {
	var output bytes.Buffer
	err := renderSetupResult(&output, setupcmd.Result{
		Clients: []setupcmd.ClientResult{{
			ClientID:    "agents",
			DisplayName: "Agent Skills",
			Status:      setupcmd.ClientStatusApplied,
			Changes: []setupcmd.SkillChange{{
				SkillID: "dd-codesec-scan-and-fix",
				Action:  setupcmd.SkillActionUpdated,
			}},
			Warnings: []string{"updated skill but could not remove its backup"},
		}},
	}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"dd-codesec-scan-and-fix: updated",
		"⚠ updated skill but could not remove its backup",
		"Restart updated clients",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("cleanup warning output %q does not contain %q", output.String(), want)
		}
	}
}

func names(entries []os.DirEntry) []string {
	out := make([]string, len(entries))
	for i, entry := range entries {
		out[i] = entry.Name()
	}
	return out
}
