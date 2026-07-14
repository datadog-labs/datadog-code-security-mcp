package telemetry

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectWorkspace(t *testing.T) {
	normalRepo := t.TempDir()
	if err := os.Mkdir(filepath.Join(normalRepo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	nestedDir := filepath.Join(normalRepo, "internal", "pkg")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		t.Fatal(err)
	}

	worktreeDir := t.TempDir()
	gitDirFile := []byte("gitdir: /tmp/repo/.git/worktrees/feature\n")
	if err := os.WriteFile(filepath.Join(worktreeDir, ".git"), gitDirFile, 0o600); err != nil {
		t.Fatal(err)
	}

	nonGitDir := t.TempDir()

	cases := []struct {
		name         string
		dir          string
		wantGitRepo  bool
		wantWorktree bool
	}{
		{
			name:         "normal repository nested directory",
			dir:          nestedDir,
			wantGitRepo:  true,
			wantWorktree: false,
		},
		{
			name:         "worktree directory",
			dir:          worktreeDir,
			wantGitRepo:  true,
			wantWorktree: true,
		},
		{
			name:         "non-git temp dir",
			dir:          nonGitDir,
			wantGitRepo:  false,
			wantWorktree: false,
		},
		{
			name:         "empty dir returns safe defaults without running git",
			dir:          "",
			wantGitRepo:  false,
			wantWorktree: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			workspace := DetectWorkspace(tc.dir)
			if workspace.IsGitRepo != tc.wantGitRepo {
				t.Errorf("IsGitRepo = %v, want %v", workspace.IsGitRepo, tc.wantGitRepo)
			}
			if workspace.IsWorktree != tc.wantWorktree {
				t.Errorf("IsWorktree = %v, want %v", workspace.IsWorktree, tc.wantWorktree)
			}
		})
	}
}
