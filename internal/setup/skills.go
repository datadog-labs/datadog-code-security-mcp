package setup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	managedBy      = "datadog-code-security-mcp"
	markerFilename = ".datadog-managed.json"
)

// ManagedMarker identifies a skill directory owned by this application.
type ManagedMarker struct {
	ManagedBy   string    `json:"managed_by"`
	SkillID     string    `json:"skill_id"`
	Version     string    `json:"version"`
	InstalledAt time.Time `json:"installed_at"`
}

// SkillChange describes an install, update, or removal performed by setup.
type SkillChange struct {
	SkillID string      `json:"skill_id"`
	Path    string      `json:"path"`
	Action  SkillAction `json:"action"`
}

// SkillAction describes how setup changed a managed skill.
type SkillAction string

const (
	SkillActionInstalled SkillAction = "installed"
	SkillActionUpdated   SkillAction = "updated"
	SkillActionRemoved   SkillAction = "removed"
)

type sourceEntry struct {
	path string
	data []byte
	dir  bool
}

type skillOp struct {
	change  SkillChange
	entries []sourceEntry
	marker  ManagedMarker
}

// EmbeddedSkillIDs returns the top-level skill directories shipped in source.
func EmbeddedSkillIDs(source fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(source, ".")
	if err != nil {
		return nil, fmt.Errorf("list embedded skills: %w", err)
	}

	var skillIDs []string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "datadog-") {
			skillIDs = append(skillIDs, entry.Name())
		}
	}
	sort.Strings(skillIDs)
	if len(skillIDs) == 0 {
		return nil, fmt.Errorf("no embedded Datadog skills found")
	}
	return skillIDs, nil
}

func planSkills(source fs.FS, dest, version string, desired []string, now time.Time) ([]skillOp, error) {
	keep := make(map[string]bool, len(desired))
	var ops []skillOp
	for _, skillID := range desired {
		keep[skillID] = true
		op, needed, err := planSkill(source, dest, skillID, version, now)
		if err != nil {
			return nil, err
		}
		if needed {
			ops = append(ops, op)
		}
	}

	prunes, err := planPrune(dest, keep)
	if err != nil {
		return nil, err
	}
	return append(ops, prunes...), nil
}

func planSkill(source fs.FS, dest, skillID, version string, now time.Time) (skillOp, bool, error) {
	entries, err := readSourceSkill(source, skillID)
	if err != nil {
		return skillOp{}, false, err
	}

	skillPath := filepath.Join(dest, skillID)
	existingMarker, exists, err := inspectExistingSkill(skillPath, skillID)
	if err != nil {
		return skillOp{}, false, err
	}

	changed := !exists
	if exists {
		changed, err = skillNeedsWrite(skillPath, entries, existingMarker, version)
		if err != nil {
			return skillOp{}, false, err
		}
	}
	if !changed {
		return skillOp{}, false, nil
	}

	action := SkillActionUpdated
	if !exists {
		action = SkillActionInstalled
	}
	installedAt := now.UTC()
	if exists && existingMarker.Version == version {
		installedAt = existingMarker.InstalledAt
	}
	return skillOp{
		change: SkillChange{
			SkillID: skillID,
			Path:    skillPath,
			Action:  action,
		},
		entries: entries,
		marker: ManagedMarker{
			ManagedBy:   managedBy,
			SkillID:     skillID,
			Version:     version,
			InstalledAt: installedAt,
		},
	}, true, nil
}

func planPrune(dest string, keep map[string]bool) ([]skillOp, error) {
	entries, err := os.ReadDir(dest)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list skills directory %s: %w", dest, err)
	}

	var ops []skillOp
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		skillPath := filepath.Join(dest, entry.Name())
		marker, err := readMarker(filepath.Join(skillPath, markerFilename))
		if err != nil || marker.ManagedBy != managedBy || keep[marker.SkillID] {
			continue
		}

		ops = append(ops, skillOp{
			change: SkillChange{
				SkillID: marker.SkillID,
				Path:    skillPath,
				Action:  SkillActionRemoved,
			},
		})
	}
	return ops, nil
}

func applySkills(dest string, ops []skillOp) ([]SkillChange, error) {
	if skillDirRequired(ops) {
		if err := os.MkdirAll(dest, 0o700); err != nil {
			return nil, fmt.Errorf("create skills directory %s: %w", dest, err)
		}
	}

	var applied []SkillChange
	for _, op := range ops {
		if err := applyOp(dest, op); err != nil {
			return applied, err
		}
		applied = append(applied, op.change)
	}
	return applied, nil
}

func applyOp(dest string, op skillOp) error {
	switch op.change.Action {
	case SkillActionRemoved:
		if err := os.RemoveAll(op.change.Path); err != nil {
			return fmt.Errorf("remove stale managed skill %s: %w", op.change.Path, err)
		}
		return nil
	case SkillActionInstalled, SkillActionUpdated:
		if _, _, err := inspectExistingSkill(op.change.Path, op.change.SkillID); err != nil {
			return err
		}
		stagedPath, err := stageSkill(dest, op.change.SkillID, op.entries, op.marker)
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(stagedPath) }()
		return replaceSkill(stagedPath, op.change.Path)
	default:
		return fmt.Errorf("unknown skill action %q", op.change.Action)
	}
}

func skillDirRequired(ops []skillOp) bool {
	for _, op := range ops {
		if op.change.Action != SkillActionRemoved {
			return true
		}
	}
	return false
}

func changesFromOps(ops []skillOp) []SkillChange {
	if len(ops) == 0 {
		return nil
	}
	changes := make([]SkillChange, len(ops))
	for i, op := range ops {
		changes[i] = op.change
	}
	return changes
}

func stageSkill(dest, skillID string, entries []sourceEntry, marker ManagedMarker) (string, error) {
	stagedPath, err := os.MkdirTemp(dest, "."+skillID+".tmp-")
	if err != nil {
		return "", fmt.Errorf("create staged skill %s: %w", skillID, err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(stagedPath)
		}
	}()

	for _, entry := range entries {
		target := filepath.Join(stagedPath, filepath.FromSlash(entry.path))
		if entry.dir {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return "", fmt.Errorf("create skill directory %s: %w", target, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return "", fmt.Errorf("create skill parent directory %s: %w", filepath.Dir(target), err)
		}
		if err := os.WriteFile(target, entry.data, 0o600); err != nil {
			return "", fmt.Errorf("write skill file %s: %w", target, err)
		}
	}
	if err := writeMarker(filepath.Join(stagedPath, markerFilename), marker); err != nil {
		return "", err
	}

	cleanup = false
	return stagedPath, nil
}

func replaceSkill(stagedPath, skillPath string) error {
	_, err := os.Lstat(skillPath)
	if os.IsNotExist(err) {
		if err := os.Rename(stagedPath, skillPath); err != nil {
			return fmt.Errorf("install staged skill %s: %w", skillPath, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect skill destination %s: %w", skillPath, err)
	}

	backupPath, err := reservePath(filepath.Dir(skillPath), "."+filepath.Base(skillPath)+".backup-")
	if err != nil {
		return fmt.Errorf("reserve skill backup path %s: %w", skillPath, err)
	}

	if err := os.Rename(skillPath, backupPath); err != nil {
		return fmt.Errorf("back up managed skill %s: %w", skillPath, err)
	}
	if err := os.Rename(stagedPath, skillPath); err != nil {
		if rollbackErr := os.Rename(backupPath, skillPath); rollbackErr != nil {
			return fmt.Errorf("replace managed skill %s: %w (rollback failed: %v)", skillPath, err, rollbackErr)
		}
		return fmt.Errorf("replace managed skill %s: %w", skillPath, err)
	}
	if err := os.RemoveAll(backupPath); err != nil {
		return fmt.Errorf("remove managed skill backup %s: %w", backupPath, err)
	}
	return nil
}

// reservePath creates an exclusive sibling name by making a temporary
// directory, then removing it so the caller can rename onto that path.
func reservePath(dir, pattern string) (string, error) {
	path, err := os.MkdirTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	if err := os.Remove(path); err != nil {
		return "", fmt.Errorf("prepare reserved path %s: %w", path, err)
	}
	return path, nil
}

func readSourceSkill(source fs.FS, skillID string) ([]sourceEntry, error) {
	var entries []sourceEntry
	hasSkillFile := false
	err := fs.WalkDir(source, skillID, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == skillID {
			return nil
		}
		prefix := skillID + "/"
		if !strings.HasPrefix(name, prefix) {
			return fmt.Errorf("invalid embedded skill path %q", name)
		}
		relative := name[len(prefix):]
		if entry.IsDir() {
			entries = append(entries, sourceEntry{path: relative, dir: true})
			return nil
		}
		data, err := fs.ReadFile(source, name)
		if err != nil {
			return err
		}
		if relative == "SKILL.md" {
			hasSkillFile = true
		}
		entries = append(entries, sourceEntry{path: relative, data: data})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read embedded skill %s: %w", skillID, err)
	}
	if !hasSkillFile {
		return nil, fmt.Errorf("embedded skill %s has no SKILL.md", skillID)
	}
	return entries, nil
}

func inspectExistingSkill(skillPath, skillID string) (ManagedMarker, bool, error) {
	info, err := os.Lstat(skillPath)
	if os.IsNotExist(err) {
		return ManagedMarker{}, false, nil
	}
	if err != nil {
		return ManagedMarker{}, false, fmt.Errorf("inspect skill destination %s: %w", skillPath, err)
	}
	if !info.IsDir() {
		return ManagedMarker{}, false, fmt.Errorf("refusing to replace non-directory skill path %s", skillPath)
	}

	marker, err := readMarker(filepath.Join(skillPath, markerFilename))
	if err != nil {
		return ManagedMarker{}, false, fmt.Errorf("refusing to replace unowned skill directory %s: %w", skillPath, err)
	}
	if marker.ManagedBy != managedBy || marker.SkillID != skillID {
		return ManagedMarker{}, false, fmt.Errorf("refusing to replace skill directory %s with a foreign marker", skillPath)
	}
	return marker, true, nil
}

func skillNeedsWrite(skillPath string, entries []sourceEntry, marker ManagedMarker, version string) (bool, error) {
	if marker.Version != version {
		return true, nil
	}

	expected := make(map[string]sourceEntry, len(entries)+1)
	expected[markerFilename] = sourceEntry{path: markerFilename}
	for _, entry := range entries {
		expected[entry.path] = entry
	}

	seen := 0
	changed := false
	err := filepath.WalkDir(skillPath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == skillPath {
			return nil
		}
		relative, err := filepath.Rel(skillPath, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		source, ok := expected[relative]
		if !ok || source.dir != entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			changed = true
			return fs.SkipAll
		}
		seen++
		if source.dir || relative == markerFilename {
			return nil
		}
		current, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(current, source.data) {
			changed = true
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("inspect managed skill contents %s: %w", skillPath, err)
	}
	return changed || seen != len(expected), nil
}

func readMarker(path string) (ManagedMarker, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ManagedMarker{}, err
	}
	var marker ManagedMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		return ManagedMarker{}, fmt.Errorf("parse managed marker %s: %w", path, err)
	}
	return marker, nil
}

func writeMarker(path string, marker ManagedMarker) error {
	data, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return fmt.Errorf("encode managed marker: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write managed marker %s: %w", path, err)
	}
	return nil
}
