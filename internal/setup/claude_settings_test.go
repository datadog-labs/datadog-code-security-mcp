package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func claudeTestOptions(t *testing.T) (Options, string) {
	t.Helper()
	isolatePATH(t)
	home := t.TempDir()
	configDir := filepath.Join(home, "custom-claude")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	options := testOptions(home, testSkillIDs())
	options.ClientIDs = []string{"claude-code"}
	options.ClaudeConfigDir = configDir
	return options, filepath.Join(configDir, "settings.json")
}

func readSkillListingBudget(t *testing.T, path string) (float64, map[string]any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	budget, ok := settings["skillListingBudgetFraction"].(float64)
	if !ok {
		t.Fatalf("skillListingBudgetFraction = %#v, want number", settings["skillListingBudgetFraction"])
	}
	return budget, settings
}

func TestRunCreatesClaudeSettingsWithBudgetFloor(t *testing.T) {
	options, settingsPath := claudeTestOptions(t)

	result, err := Run(options)
	if err != nil {
		t.Fatal(err)
	}
	if result.HasFailures() {
		t.Fatalf("setup failed: %+v", result.Clients)
	}
	if got := result.Clients[0].Settings; got == nil || got.Action != SettingsActionUpdated {
		t.Fatalf("settings change = %+v, want updated", got)
	}
	budget, _ := readSkillListingBudget(t, settingsPath)
	if budget != skillListingBudgetFloor {
		t.Fatalf("skillListingBudgetFraction = %v, want %v", budget, skillListingBudgetFloor)
	}
}

func TestRunRaisesClaudeBudgetAndPreservesOtherSettings(t *testing.T) {
	options, settingsPath := claudeTestOptions(t)
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"theme":"dark","skillListingBudgetFraction":0.01}`), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := Run(options)
	if err != nil {
		t.Fatal(err)
	}
	if result.HasFailures() {
		t.Fatalf("setup failed: %+v", result.Clients)
	}
	budget, settings := readSkillListingBudget(t, settingsPath)
	if budget != skillListingBudgetFloor {
		t.Fatalf("skillListingBudgetFraction = %v, want %v", budget, skillListingBudgetFloor)
	}
	if settings["theme"] != "dark" {
		t.Fatalf("theme = %#v, want preserved", settings["theme"])
	}
}

func TestRunUpdatesClaudeSettingsThroughSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional privileges on Windows")
	}
	options, settingsPath := claudeTestOptions(t)
	targetPath := filepath.Join(filepath.Dir(settingsPath), "shared-settings.json")
	const original = `{"theme":"dark","skillListingBudgetFraction":0.01}`
	if err := os.WriteFile(targetPath, []byte(original), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetPath, settingsPath); err != nil {
		t.Fatal(err)
	}

	result, err := Run(options)
	if err != nil {
		t.Fatal(err)
	}
	if result.HasFailures() {
		t.Fatalf("setup failed: %+v", result.Clients)
	}
	info, err := os.Lstat(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("settings symlink was replaced")
	}
	budget, settings := readSkillListingBudget(t, targetPath)
	if budget != skillListingBudgetFloor || settings["theme"] != "dark" {
		t.Fatalf("symlink target settings = %#v", settings)
	}
	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := targetInfo.Mode().Perm(); got != 0o640 {
		t.Fatalf("symlink target permissions = %o, want 640", got)
	}
}

func TestRunInstallsSkillsWhenClaudeSettingsWriteFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional privileges on Windows")
	}
	options, settingsPath := claudeTestOptions(t)
	if err := os.Symlink(filepath.Join(filepath.Dir(settingsPath), "missing.json"), settingsPath); err != nil {
		t.Fatal(err)
	}

	result, err := Run(options)
	if err != nil {
		t.Fatal(err)
	}
	if result.HasFailures() {
		t.Fatalf("settings write failure blocked skill install: %+v", result.Clients)
	}
	if result.Clients[0].Settings != nil {
		t.Fatalf("failed settings write reported as applied: %+v", result.Clients[0].Settings)
	}
	assertClaudeSettingsWarning(t, result.Clients[0].Warnings)
	assertTestSkillsInstalled(t, filepath.Join(options.ClaudeConfigDir, "skills"))
}

func TestRunDoesNotLowerHigherClaudeBudget(t *testing.T) {
	options, settingsPath := claudeTestOptions(t)
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	const original = "{\n  \"skillListingBudgetFraction\": 0.05\n}\n"
	if err := os.WriteFile(settingsPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := Run(options)
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Clients[0].Settings; got == nil || got.Action != SettingsActionUnchanged {
		t.Fatalf("settings change = %+v, want unchanged", got)
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Fatalf("higher budget file changed:\n%s", data)
	}
}

func TestRunSkipsClaudeBudgetWhenRequested(t *testing.T) {
	options, settingsPath := claudeTestOptions(t)
	options.SkipSkillListingBudget = true

	result, err := Run(options)
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Clients[0].Settings; got == nil || got.Action != SettingsActionSkipped {
		t.Fatalf("settings change = %+v, want skipped", got)
	}
	if _, err := os.Stat(settingsPath); !os.IsNotExist(err) {
		t.Fatalf("settings file exists after skip: %v", err)
	}
}

func TestPreviewReportsClaudeBudgetWithoutWriting(t *testing.T) {
	options, settingsPath := claudeTestOptions(t)

	result, err := Preview(options)
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Clients[0].Settings; got == nil || got.Action != SettingsActionUpdated {
		t.Fatalf("settings change = %+v, want planned update", got)
	}
	if _, err := os.Stat(settingsPath); !os.IsNotExist(err) {
		t.Fatalf("settings file exists after preview: %v", err)
	}
}

func TestRunInstallsSkillsWhenClaudeSettingsAreMalformed(t *testing.T) {
	options, settingsPath := claudeTestOptions(t)
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	const malformed = `{"skillListingBudgetFraction":`
	if err := os.WriteFile(settingsPath, []byte(malformed), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := Run(options)
	if err != nil {
		t.Fatal(err)
	}
	if result.HasFailures() {
		t.Fatalf("malformed settings blocked skill install: %+v", result.Clients)
	}
	if result.Clients[0].Settings != nil {
		t.Fatalf("malformed settings reported as applied: %+v", result.Clients[0].Settings)
	}
	assertClaudeSettingsWarning(t, result.Clients[0].Warnings)
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != malformed {
		t.Fatalf("malformed settings were overwritten: %q", data)
	}
	assertTestSkillsInstalled(t, filepath.Join(options.ClaudeConfigDir, "skills"))
}

func TestPreviewWarnsOnMalformedClaudeSettingsWithoutWriting(t *testing.T) {
	options, settingsPath := claudeTestOptions(t)
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	const malformed = `{"skillListingBudgetFraction":`
	if err := os.WriteFile(settingsPath, []byte(malformed), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := Preview(options)
	if err != nil {
		t.Fatal(err)
	}
	if result.HasFailures() {
		t.Fatalf("malformed settings blocked preview: %+v", result.Clients)
	}
	if result.Clients[0].Settings != nil {
		t.Fatalf("malformed settings reported in preview: %+v", result.Clients[0].Settings)
	}
	assertClaudeSettingsWarning(t, result.Clients[0].Warnings)
	if len(result.Clients[0].Changes) == 0 {
		t.Fatal("preview omitted skill changes after settings parse failure")
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != malformed {
		t.Fatalf("preview overwrote malformed settings: %q", data)
	}
	if _, err := os.Stat(filepath.Join(options.ClaudeConfigDir, "skills")); !os.IsNotExist(err) {
		t.Fatalf("preview installed skills: %v", err)
	}
}

func assertClaudeSettingsWarning(t *testing.T, warnings []string) {
	t.Helper()
	for _, warning := range warnings {
		if strings.Contains(warning, "could not update Claude Code skill-listing budget") &&
			strings.Contains(warning, "--skip-skill-listing-budget") {
			return
		}
	}
	t.Fatalf("missing settings warning: %v", warnings)
}

func assertTestSkillsInstalled(t *testing.T, skillsDir string) {
	t.Helper()
	for _, skillID := range testSkillIDs() {
		if _, err := os.Stat(filepath.Join(skillsDir, skillID, "SKILL.md")); err != nil {
			t.Fatalf("skill %s was not installed: %v", skillID, err)
		}
	}
}

func TestRemoveSkillsDoesNotModifyClaudeSettings(t *testing.T) {
	options, settingsPath := claudeTestOptions(t)
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	const original = `{"skillListingBudgetFraction":0.01}`
	if err := os.WriteFile(settingsPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	options.Desired = nil

	result, err := Run(options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Clients[0].Settings != nil {
		t.Fatalf("remove reported settings change: %+v", result.Clients[0].Settings)
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Fatalf("remove changed settings: %q", data)
	}
}
