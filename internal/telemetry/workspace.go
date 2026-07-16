package telemetry

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxGitPointerSize bounds how much of a ".git" pointer file we read. A real
// "gitdir:" pointer (used by worktrees and submodules) is a single short line,
// so a few KiB is far more than enough. Bounding the read keeps best-effort
// telemetry from allocating excessively on a crafted or oversized ".git" file.
const maxGitPointerSize = 4 << 10 // 4 KiB

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
			// A regular ".git" file is a worktree/submodule pointer
			// ("gitdir: <path>"). Only regular files are read: a non-regular
			// entry (FIFO, device, socket) named ".git" could block or misbehave,
			// and best-effort telemetry must never stall the scan.
			if info.Mode().IsRegular() {
				if gitDir := readGitPointer(gitMetadata); gitDir != "" {
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

// readGitPointer returns the "gitdir:" target from a ".git" pointer file, or ""
// on any error. The read is capped at maxGitPointerSize so a large or crafted
// file cannot balloon memory on the scan path. The caller must have already
// confirmed the path is a regular file.
func readGitPointer(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	content, err := io.ReadAll(io.LimitReader(f, maxGitPointerSize))
	if err != nil {
		return ""
	}
	return filepath.ToSlash(strings.TrimSpace(strings.TrimPrefix(string(content), "gitdir:")))
}
