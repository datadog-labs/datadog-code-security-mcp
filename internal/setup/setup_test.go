package setup

import (
	"os"
	"path/filepath"
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
