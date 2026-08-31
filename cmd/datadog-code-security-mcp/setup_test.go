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
	return home
}

func TestSetupCommandDryRunWritesNothing(t *testing.T) {
	home := setSetupTestHome(t)
	if err := os.Mkdir(filepath.Join(home, ".cursor"), 0o700); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	cmd := newSetupCmd()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--client", "cursor", "--dry-run"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "would be installed") {
		t.Fatalf("dry-run output = %q", output.String())
	}
	if !strings.Contains(output.String(), "Dry run complete.") {
		t.Fatalf("dry-run footer missing: %q", output.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".cursor", "skills")); !os.IsNotExist(err) {
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

func TestSetupCommandRemoveSkillsLeavesUnmarkedDirectories(t *testing.T) {
	home := setSetupTestHome(t)
	if err := os.Mkdir(filepath.Join(home, ".cursor"), 0o700); err != nil {
		t.Fatal(err)
	}

	install := newSetupCmd()
	install.SetArgs([]string{"--client", "cursor"})
	if err := install.Execute(); err != nil {
		t.Fatal(err)
	}

	userSkill := filepath.Join(home, ".cursor", "skills", "user-skill")
	if err := os.MkdirAll(userSkill, 0o700); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(home, ".cursor", "skills", "datadog-code-security-remediation", "SKILL.md")

	var preview bytes.Buffer
	dryRun := newSetupCmd()
	dryRun.SetOut(&preview)
	dryRun.SetArgs([]string{"--client", "cursor", "--remove-skills", "--dry-run"})
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
	remove.SetArgs([]string{"--client", "cursor", "--remove-skills", "--json"})
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
	if _, err := os.Stat(filepath.Join(home, ".cursor", "skills", "datadog-code-security-remediation")); !os.IsNotExist(err) {
		t.Fatalf("managed skill survived --remove-skills: %v", err)
	}
	if _, err := os.Stat(userSkill); err != nil {
		t.Fatalf("unmarked skill was removed: %v", err)
	}
}

func TestSetupCommandReturnsFailureWithoutWrites(t *testing.T) {
	home := setSetupTestHome(t)
	collision := filepath.Join(home, ".cursor", "skills", "datadog-code-security-remediation")
	if err := os.MkdirAll(collision, 0o700); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	cmd := newSetupCmd()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--client", "cursor"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("setup reported success for an unowned skill collision")
	}
	if !strings.Contains(output.String(), "Cursor: failed") {
		t.Fatalf("failure output = %q", output.String())
	}
	if strings.Contains(output.String(), "Restart") {
		t.Fatalf("blocked client requested restart: %q", output.String())
	}
	skillsDir := filepath.Join(home, ".cursor", "skills")
	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "datadog-code-security-remediation" {
		t.Fatalf("blocked client mutated skills dir: %v", names(entries))
	}
}

func TestRenderSetupResultDoesNotRestartWhenAlreadyCurrent(t *testing.T) {
	var output bytes.Buffer
	err := renderSetupResult(&output, setupcmd.Result{
		Clients: []setupcmd.ClientResult{{
			ClientID:    "cursor",
			DisplayName: "Cursor",
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
	if !strings.Contains(output.String(), "Cursor: no changes") {
		t.Fatalf("empty plan output = %q", output.String())
	}
}

func TestRenderSetupResultDoesNotRestartAfterFailure(t *testing.T) {
	var output bytes.Buffer
	err := renderSetupResult(&output, setupcmd.Result{
		Clients: []setupcmd.ClientResult{{
			ClientID:    "cursor",
			DisplayName: "Cursor",
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

func names(entries []os.DirEntry) []string {
	out := make([]string, len(entries))
	for i, entry := range entries {
		out[i] = entry.Name()
	}
	return out
}
