package telemetry

import (
	"os"
	"path/filepath"
	"strings"
)

// WorkspaceInfo describes git-related properties of the scan target directory.
type WorkspaceInfo struct {
	IsGitRepo  bool
	IsWorktree bool
}

// DetectWorkspace detects git-related properties of the scan target directory.
// It is best-effort: all errors are silently ignored so telemetry is never affected.
// When dir is empty the attributes are omitted (returned as false) rather than
// inspecting an unknown directory. Detection uses bounded filesystem metadata
// reads rather than spawning Git processes on the user-visible request path.
func DetectWorkspace(dir string) WorkspaceInfo {
	if dir == "" {
		return WorkspaceInfo{}
	}

	current, err := filepath.Abs(dir)
	if err != nil {
		return WorkspaceInfo{}
	}
	if info, statErr := os.Stat(current); statErr == nil && !info.IsDir() {
		current = filepath.Dir(current)
	}

	for {
		gitMetadata := filepath.Join(current, ".git")
		info, statErr := os.Stat(gitMetadata)
		if statErr == nil {
			workspace := WorkspaceInfo{IsGitRepo: true}
			if !info.IsDir() {
				content, readErr := os.ReadFile(gitMetadata)
				if readErr == nil {
					gitDir := filepath.ToSlash(strings.TrimSpace(strings.TrimPrefix(string(content), "gitdir:")))
					workspace.IsWorktree = strings.Contains(gitDir, "/worktrees/")
				}
			}
			return workspace
		}

		parent := filepath.Dir(current)
		if parent == current {
			return WorkspaceInfo{}
		}
		current = parent
	}
}
