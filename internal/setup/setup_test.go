package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func isolatePATH(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", "")
}

func testOptions(home string, desired []string) Options {
	return Options{
		Source:  testSkillFS(),
		Version: "1.0.0",
		HomeDir: home,
		Now:     time.Now(),
		Desired: desired,
	}
}

func TestRunContinuesAfterClientFailure(t *testing.T) {
	isolatePATH(t)
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	collision := filepath.Join(home, ".claude", "skills", "datadog-remediation")
	if err := os.MkdirAll(collision, 0o700); err != nil {
		t.Fatal(err)
	}

	options := testOptions(home, testSkillIDs())
	options.ClientIDs = []string{"claude-code", "agents", "codex"}
	result, err := Run(options)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Clients) != 3 {
		t.Fatalf("clients = %d, want 3", len(result.Clients))
	}
	if result.Clients[0].Status != ClientStatusFailed {
		t.Errorf("Claude status = %s, want failed", result.Clients[0].Status)
	}
	if len(result.Clients[0].Changes) != 0 {
		t.Errorf("Claude changes = %+v, want none", result.Clients[0].Changes)
	}
	if result.Clients[1].Status != ClientStatusApplied {
		t.Errorf("Agent Skills status = %s, want applied", result.Clients[1].Status)
	}
	if result.Clients[2].Status != ClientStatusSkipped {
		t.Errorf("Codex status = %s, want skipped", result.Clients[2].Status)
	}
	if !result.HasFailures() || result.FailureError() == nil {
		t.Fatal("partial failure was not reflected in aggregate result")
	}
	if _, err := os.Stat(filepath.Join(home, ".agents", "skills", "datadog-remediation", "SKILL.md")); err != nil {
		t.Fatalf("Agent Skills was not installed after Claude failure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "skills", "datadog-verification")); !os.IsNotExist(err) {
		t.Fatal("blocked Claude client was mutated")
	}
}

func TestRunRejectsUnknownClient(t *testing.T) {
	options := testOptions(t.TempDir(), testSkillIDs())
	options.ClientIDs = []string{"unknown"}
	if _, err := Run(options); err == nil {
		t.Fatal("Run() accepted an unknown client")
	}
}

func TestResolveClaudeConfigDir(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		got, err := resolveClaudeConfigDir("")
		if err != nil {
			t.Fatal(err)
		}
		if got != "" {
			t.Fatalf("got %q, want empty", got)
		}
	})

	t.Run("existing directory", func(t *testing.T) {
		dir := t.TempDir()
		got, err := resolveClaudeConfigDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		want, err := filepath.Abs(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("missing directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "missing")
		got, err := resolveClaudeConfigDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		want, err := filepath.Abs(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := resolveClaudeConfigDir(file)
		if err == nil {
			t.Fatal("accepted a file path")
		}
		if !strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("relative", func(t *testing.T) {
		dir := t.TempDir()
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(cwd, dir)
		if err != nil {
			t.Skip(err)
		}
		got, err := resolveClaudeConfigDir(filepath.Join(rel, "nested", ".."))
		if err != nil {
			t.Fatal(err)
		}
		want, err := filepath.Abs(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
}

func TestRunFailsClaudeWhenConfigDirIsFileAndClaudeIsDetected(t *testing.T) {
	isolatePATH(t)
	home := t.TempDir()
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

	options := testOptions(home, testSkillIDs())
	options.ClaudeConfigDir = file
	result, err := Run(options)
	if err != nil {
		t.Fatal(err)
	}
	claude := resultClient(t, result, "claude-code")
	if claude.Status != ClientStatusFailed {
		t.Fatalf("Claude status = %s, want failed", claude.Status)
	}
	if !strings.Contains(claude.Reason, "not a directory") {
		t.Fatalf("Claude reason = %q, want not a directory", claude.Reason)
	}
	agents := resultClient(t, result, "agents")
	if agents.Status != ClientStatusApplied {
		t.Fatalf("Agent Skills status = %s, want applied", agents.Status)
	}
	codex := resultClient(t, result, "codex")
	if codex.Status != ClientStatusApplied {
		t.Fatalf("Codex status = %s, want applied", codex.Status)
	}
	if !result.HasFailures() {
		t.Fatal("detected Claude failure was not reported")
	}
	if _, err := os.Stat(filepath.Join(home, ".agents", "skills", "datadog-remediation", "SKILL.md")); err != nil {
		t.Fatalf("Agent Skills were not installed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".codex", "skills", "datadog-remediation", "SKILL.md")); err != nil {
		t.Fatalf("Codex skills were not installed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "skills", "datadog-remediation")); !os.IsNotExist(err) {
		t.Fatal("Claude skills were installed after a config-dir failure")
	}
}

func TestRunSkipsInvalidClaudeConfigDirWhenClaudeIsNotDetected(t *testing.T) {
	isolatePATH(t)
	home := t.TempDir()
	file := filepath.Join(home, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	options := testOptions(home, testSkillIDs())
	options.ClaudeConfigDir = file
	result, err := Run(options)
	if err != nil {
		t.Fatal(err)
	}
	claude := resultClient(t, result, "claude-code")
	if claude.Status != ClientStatusSkipped {
		t.Fatalf("Claude status = %s, want skipped", claude.Status)
	}
	agents := resultClient(t, result, "agents")
	if agents.Status != ClientStatusApplied {
		t.Fatalf("Agent Skills status = %s, want applied", agents.Status)
	}
	if result.HasFailures() {
		t.Fatalf("setup failed without a detected Claude client: %+v", result.Clients)
	}
}

func TestRunIgnoresClaudeConfigDirFileWhenClaudeNotSelected(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := testOptions(t.TempDir(), testSkillIDs())
	options.ClientIDs = []string{"agents"}
	options.ClaudeConfigDir = file
	result, err := Run(options)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Clients) != 1 || result.Clients[0].ClientID != "agents" {
		t.Fatalf("clients = %+v, want agents only", result.Clients)
	}
	if result.Clients[0].Status != ClientStatusApplied {
		t.Fatalf("status = %s, want applied", result.Clients[0].Status)
	}
}

func resultClient(t *testing.T, result Result, id string) ClientResult {
	t.Helper()
	for _, client := range result.Clients {
		if client.ClientID == id {
			return client
		}
	}
	t.Fatalf("client %s not found in %+v", id, result.Clients)
	return ClientResult{}
}

func TestRunDoesNotWriteWhenAnyDesiredSkillIsBlocked(t *testing.T) {
	isolatePATH(t)
	home := t.TempDir()
	collision := filepath.Join(home, ".agents", "skills", "datadog-verification")
	if err := os.MkdirAll(collision, 0o700); err != nil {
		t.Fatal(err)
	}

	options := testOptions(home, testSkillIDs())
	options.ClientIDs = []string{"agents"}
	result, err := Run(options)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Clients) != 1 || result.Clients[0].Status != ClientStatusFailed {
		t.Fatalf("client result = %+v, want one failed client", result.Clients)
	}
	if len(result.Clients[0].Changes) != 0 {
		t.Fatalf("blocked client changes = %+v, want none", result.Clients[0].Changes)
	}
	if _, err := os.Stat(filepath.Join(home, ".agents", "skills", "datadog-remediation")); !os.IsNotExist(err) {
		t.Fatal("sibling skill was written despite a blocked desired skill")
	}
}

func TestRunDoesNotPruneWhenDesiredSkillIsBlocked(t *testing.T) {
	isolatePATH(t)
	home := t.TempDir()
	skillsDir := filepath.Join(home, ".agents", "skills")
	stale := filepath.Join(skillsDir, "datadog-stale")
	collision := filepath.Join(skillsDir, "datadog-verification")
	for _, path := range []string{stale, collision} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeMarker(filepath.Join(stale, markerFilename), ManagedMarker{
		ManagedBy: managedBy,
		SkillID:   "datadog-stale",
		Version:   "0.9.0",
	}); err != nil {
		t.Fatal(err)
	}

	options := testOptions(home, testSkillIDs())
	options.ClientIDs = []string{"agents"}
	result, err := Run(options)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Clients) != 1 || result.Clients[0].Status != ClientStatusFailed {
		t.Fatalf("client result = %+v, want one failed client", result.Clients)
	}
	if len(result.Clients[0].Changes) != 0 {
		t.Fatalf("blocked client changes = %+v, want none", result.Clients[0].Changes)
	}
	if _, err := os.Stat(stale); err != nil {
		t.Fatalf("stale managed skill was pruned despite a blocked desired skill: %v", err)
	}
}

func TestRunRemoveSkillsLeavesUnmarkedDirectories(t *testing.T) {
	isolatePATH(t)
	home := t.TempDir()

	install := testOptions(home, testSkillIDs())
	install.ClientIDs = []string{"agents"}
	installed, err := Run(install)
	if err != nil {
		t.Fatal(err)
	}
	if installed.HasFailures() {
		t.Fatalf("install failed: %+v", installed.Clients)
	}

	userSkill := filepath.Join(home, ".agents", "skills", "user-skill")
	if err := os.MkdirAll(userSkill, 0o700); err != nil {
		t.Fatal(err)
	}

	remove := testOptions(home, nil)
	remove.ClientIDs = []string{"agents"}
	preview, err := Preview(remove)
	if err != nil {
		t.Fatal(err)
	}
	if preview.HasFailures() {
		t.Fatalf("preview remove failed: %+v", preview.Clients)
	}
	if len(preview.Clients) != 1 || preview.Clients[0].Status != ClientStatusApplied {
		t.Fatalf("preview remove result = %+v, want one applied client", preview.Clients)
	}
	if _, err := os.Stat(filepath.Join(home, ".agents", "skills", "datadog-remediation", "SKILL.md")); err != nil {
		t.Fatalf("preview remove deleted managed skills: %v", err)
	}

	result, err := Run(remove)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Clients) != 1 || result.Clients[0].Status != ClientStatusApplied {
		t.Fatalf("remove result = %+v, want one applied client", result.Clients)
	}
	if _, err := os.Stat(filepath.Join(home, ".agents", "skills", "datadog-remediation")); !os.IsNotExist(err) {
		t.Fatalf("managed skill survived empty desired set: %v", err)
	}
	if _, err := os.Stat(userSkill); err != nil {
		t.Fatalf("unmarked skill was removed: %v", err)
	}

	removed := map[string]bool{}
	for _, change := range result.Clients[0].Changes {
		if change.Action != SkillActionRemoved {
			t.Fatalf("unexpected change during remove: %+v", change)
		}
		removed[change.SkillID] = true
	}
	for _, skillID := range testSkillIDs() {
		if !removed[skillID] {
			t.Errorf("missing removal for %s: %+v", skillID, result.Clients[0].Changes)
		}
	}
}
