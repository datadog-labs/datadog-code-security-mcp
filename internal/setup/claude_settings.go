package setup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const skillListingBudgetFloor = 0.02

// SettingsAction describes how setup handled a client settings file.
type SettingsAction string

const (
	SettingsActionUpdated   SettingsAction = "updated"
	SettingsActionUnchanged SettingsAction = "unchanged"
	SettingsActionSkipped   SettingsAction = "skipped"
)

// SettingsChange describes a Claude Code settings reconciliation.
type SettingsChange struct {
	Path   string         `json:"path"`
	Action SettingsAction `json:"action"`
	Reason string         `json:"reason,omitempty"`
}

type claudeSettingsPlan struct {
	change SettingsChange
	data   []byte
	mode   os.FileMode
	target string
}

func claudeSettingsWarning(err error) string {
	return fmt.Sprintf(
		"could not update Claude Code skill-listing budget: %s (use --skip-skill-listing-budget to skip this setting)",
		err)
}

func planClaudeSettings(path string, skip bool) (claudeSettingsPlan, error) {
	if skip {
		return claudeSettingsPlan{change: SettingsChange{
			Path:   path,
			Action: SettingsActionSkipped,
			Reason: "disabled by --skip-skill-listing-budget",
		}}, nil
	}

	targetPath, err := claudeSettingsWriteTarget(path)
	if err != nil {
		return claudeSettingsPlan{}, err
	}

	settings := make(map[string]json.RawMessage)
	mode := os.FileMode(0o600)
	data, err := os.ReadFile(targetPath)
	switch {
	case err == nil:
		info, statErr := os.Stat(targetPath)
		if statErr != nil {
			return claudeSettingsPlan{}, fmt.Errorf("inspect Claude Code settings %s: %w", path, statErr)
		}
		mode = info.Mode().Perm()
		if err := json.Unmarshal(data, &settings); err != nil {
			return claudeSettingsPlan{}, fmt.Errorf("parse Claude Code settings %s: %w", path, err)
		}
		if settings == nil {
			return claudeSettingsPlan{}, fmt.Errorf("parse Claude Code settings %s: expected a JSON object", path)
		}
	case os.IsNotExist(err):
	default:
		return claudeSettingsPlan{}, fmt.Errorf("read Claude Code settings %s: %w", path, err)
	}

	if raw, ok := settings["skillListingBudgetFraction"]; ok {
		var current float64
		if err := json.Unmarshal(raw, &current); err != nil {
			return claudeSettingsPlan{}, fmt.Errorf(
				"parse skillListingBudgetFraction in Claude Code settings %s: %w", path, err)
		}
		if current >= skillListingBudgetFloor {
			return claudeSettingsPlan{change: SettingsChange{
				Path:   path,
				Action: SettingsActionUnchanged,
				Reason: fmt.Sprintf("skillListingBudgetFraction is already %g", current),
			}}, nil
		}
	}

	budgetJSON, err := json.Marshal(skillListingBudgetFloor)
	if err != nil {
		return claudeSettingsPlan{}, fmt.Errorf("encode skillListingBudgetFraction: %w", err)
	}
	settings["skillListingBudgetFraction"] = budgetJSON
	updated, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return claudeSettingsPlan{}, fmt.Errorf("encode Claude Code settings %s: %w", path, err)
	}
	updated = append(updated, '\n')

	return claudeSettingsPlan{
		change: SettingsChange{
			Path:   path,
			Action: SettingsActionUpdated,
			Reason: fmt.Sprintf("set skillListingBudgetFraction floor to %g", skillListingBudgetFloor),
		},
		data:   updated,
		mode:   mode,
		target: targetPath,
	}, nil
}

func applyClaudeSettings(plan claudeSettingsPlan) error {
	if plan.change.Action != SettingsActionUpdated {
		return nil
	}
	// Re-read at apply time so skill install cannot write a stale snapshot
	// over concurrent Claude Code or user edits. No lock: the other writer
	// would not take it, so it would not close the remaining rename window.
	fresh, err := planClaudeSettings(plan.change.Path, false)
	if err != nil {
		return err
	}
	if fresh.change.Action != SettingsActionUpdated {
		return nil
	}
	return writeClaudeSettings(fresh)
}

func writeClaudeSettings(plan claudeSettingsPlan) error {
	targetPath := plan.target
	if targetPath == "" {
		targetPath = plan.change.Path
	}
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create Claude Code settings directory %s: %w", dir, err)
	}

	tempFile, err := os.CreateTemp(dir, "."+filepath.Base(targetPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary Claude Code settings file: %w", err)
	}
	tempPath := tempFile.Name()
	defer func() { _ = os.Remove(tempPath) }()

	closeWithError := func(err error) error {
		_ = tempFile.Close()
		return err
	}
	if err := tempFile.Chmod(plan.mode); err != nil {
		return closeWithError(fmt.Errorf("set Claude Code settings permissions: %w", err))
	}
	if _, err := tempFile.Write(plan.data); err != nil {
		return closeWithError(fmt.Errorf("write temporary Claude Code settings: %w", err))
	}
	if err := tempFile.Sync(); err != nil {
		return closeWithError(fmt.Errorf("sync temporary Claude Code settings: %w", err))
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temporary Claude Code settings: %w", err)
	}
	if err := os.Rename(tempPath, targetPath); err != nil {
		return fmt.Errorf("replace Claude Code settings %s: %w", plan.change.Path, err)
	}
	return nil
}

func claudeSettingsWriteTarget(path string) (string, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return path, nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect Claude Code settings %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return path, nil
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve Claude Code settings symlink %s: %w", path, err)
	}
	return target, nil
}
