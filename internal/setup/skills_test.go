package setup

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func testSkillFS() fstest.MapFS {
	return fstest.MapFS{
		"datadog-remediation/SKILL.md":                 {Data: []byte("skill")},
		"datadog-remediation/references/sast.md":       {Data: []byte("sast")},
		"datadog-remediation/references/nested/foo.md": {Data: []byte("nested")},
		"datadog-verification/SKILL.md":                {Data: []byte("verify")},
	}
}

func testSkillIDs() []string {
	return []string{"datadog-remediation", "datadog-verification"}
}

func mustApplyPlan(t *testing.T, dest, version string, desired []string, now time.Time) []SkillChange {
	t.Helper()
	ops, err := planSkills(testSkillFS(), dest, version, desired, now)
	if err != nil {
		t.Fatal(err)
	}
	applied, warnings, err := applySkills(dest, ops)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected apply warnings: %v", warnings)
	}
	return applied
}

func TestPlanSkillsSynchronisesNestedSkillsIdempotently(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "skills")
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

	changes := mustApplyPlan(t, dest, "1.0.0", testSkillIDs(), now)
	if len(changes) != 2 {
		t.Fatalf("first install changes = %d, want 2", len(changes))
	}
	nested := filepath.Join(dest, "datadog-remediation", "references", "nested", "foo.md")
	if data, err := os.ReadFile(nested); err != nil || string(data) != "nested" {
		t.Fatalf("nested file = %q, %v", data, err)
	}

	changes = mustApplyPlan(t, dest, "1.0.0", testSkillIDs(), now.Add(time.Hour))
	if len(changes) != 0 {
		t.Fatalf("idempotent install changes = %v, want none", changes)
	}

	stale := filepath.Join(dest, "datadog-remediation", "references", "stale.md")
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	changes = mustApplyPlan(t, dest, "1.0.0", testSkillIDs(), now.Add(2*time.Hour))
	if len(changes) != 1 || changes[0].SkillID != "datadog-remediation" {
		t.Fatalf("same-version stale cleanup changes = %+v", changes)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale managed file still exists: %v", err)
	}

	changes = mustApplyPlan(t, dest, "2.0.0", testSkillIDs(), now.Add(3*time.Hour))
	if len(changes) != 2 {
		t.Fatalf("version update changes = %d, want 2", len(changes))
	}
	marker, err := readMarker(filepath.Join(dest, "datadog-remediation", markerFilename))
	if err != nil {
		t.Fatal(err)
	}
	if marker.Version != "2.0.0" || !marker.InstalledAt.Equal(now.Add(3*time.Hour)) {
		t.Fatalf("updated marker = %+v", marker)
	}
}

func TestPlanSkillsWritesNothing(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "skills")
	ops, err := planSkills(testSkillFS(), dest, "1.0.0", testSkillIDs(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 2 {
		t.Fatalf("plan ops = %d, want 2", len(ops))
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("plan created destination: %v", err)
	}
}

func TestPlanSkillsRefusesUnownedCollision(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "skills")
	collision := filepath.Join(dest, "datadog-remediation")
	if err := os.MkdirAll(collision, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(collision, "SKILL.md"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := planSkills(testSkillFS(), dest, "1.0.0", testSkillIDs(), time.Now()); err == nil {
		t.Fatal("planSkills() succeeded over an unowned skill directory")
	}
}

func TestStageSkillFailureLeavesNoPartialDirectory(t *testing.T) {
	dest := t.TempDir()
	entries := []sourceEntry{
		{path: "references", data: []byte("blocks nested directory")},
		{path: "references/sast.md", data: []byte("sast")},
	}
	_, err := stageSkill(dest, "datadog-remediation", entries, ManagedMarker{
		ManagedBy: managedBy,
		SkillID:   "datadog-remediation",
		Version:   "1.0.0",
	})
	if err == nil {
		t.Fatal("stageSkill() succeeded with conflicting file paths")
	}
	remaining, readErr := os.ReadDir(dest)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(remaining) != 0 {
		t.Fatalf("staged failure left partial content: %v", remaining)
	}
}

func TestReplaceSkillCleanupFailureKeepsUpdateAndReturnsWarning(t *testing.T) {
	root := t.TempDir()
	skillPath := filepath.Join(root, "datadog-remediation")
	stagedPath := filepath.Join(root, ".staged")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "SKILL.md"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stagedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stagedPath, "SKILL.md"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}

	warning, err := replaceSkillWithCleanup(stagedPath, skillPath, func(string) error {
		return errors.New("backup is locked")
	})
	if err != nil {
		t.Fatalf("replaceSkillWithCleanup() error = %v", err)
	}
	if !strings.Contains(warning, "could not remove backup") {
		t.Fatalf("warning = %q", warning)
	}
	content, err := os.ReadFile(filepath.Join(skillPath, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "new" {
		t.Fatalf("active skill content = %q, want new", content)
	}
}

func TestPlanSkillsRefusesSymlinkedSkillDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires additional privileges on Windows")
	}

	root := t.TempDir()
	dest := filepath.Join(root, "skills")
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(filepath.Join(target, markerFilename), ManagedMarker{
		ManagedBy: managedBy,
		SkillID:   "datadog-remediation",
		Version:   "1.0.0",
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dest, "datadog-remediation")); err != nil {
		t.Fatal(err)
	}

	if _, err := planSkills(testSkillFS(), dest, "1.0.0", testSkillIDs(), time.Now()); err == nil {
		t.Fatal("planSkills() accepted a symlinked managed skill directory")
	}
	if _, err := os.Stat(filepath.Join(target, markerFilename)); err != nil {
		t.Fatalf("symlink target was modified: %v", err)
	}
}

func TestPlanPruneRemovesOnlyStaleManagedSkills(t *testing.T) {
	dest := t.TempDir()
	stale := filepath.Join(dest, "datadog-stale")
	kept := filepath.Join(dest, "datadog-kept")
	foreign := filepath.Join(dest, "foreign")
	unmarked := filepath.Join(dest, "datadog-user-skill")
	dotDir := filepath.Join(dest, ".system")
	for _, path := range []string{stale, kept, foreign, unmarked, dotDir} {
		if err := os.MkdirAll(filepath.Join(path, "nested"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	if err := writeMarker(filepath.Join(stale, markerFilename), ManagedMarker{
		ManagedBy: managedBy, SkillID: "datadog-stale", Version: "1", InstalledAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(filepath.Join(kept, markerFilename), ManagedMarker{
		ManagedBy: managedBy, SkillID: "datadog-kept", Version: "1", InstalledAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(filepath.Join(foreign, markerFilename), ManagedMarker{
		ManagedBy: "other-vendor", SkillID: "foreign", Version: "1", InstalledAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(filepath.Join(dotDir, markerFilename), ManagedMarker{
		ManagedBy: managedBy, SkillID: ".system", Version: "1", InstalledAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	ops, err := planPrune(dest, map[string]bool{"datadog-kept": true})
	if err != nil {
		t.Fatal(err)
	}
	applied, warnings, err := applySkills(dest, ops)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected apply warnings: %v", warnings)
	}
	if len(applied) != 1 || applied[0].SkillID != "datadog-stale" {
		t.Fatalf("prune changes = %+v", applied)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale directory still exists: %v", err)
	}
	for _, path := range []string{kept, foreign, unmarked, dotDir} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("protected directory %s was removed: %v", path, err)
		}
	}
}
