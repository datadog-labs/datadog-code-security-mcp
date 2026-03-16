package libraryscan

import (
	"context"
	"os/exec"
	"strings"
)

// DetectGitContext tries to get the repository name and commit hash from the
// git repository at dir. Returns empty strings if not a git repo or git fails.
func DetectGitContext(ctx context.Context, dir string) (repoName, commitHash string) {
	if remote, err := runGitCommand(ctx, dir, "remote", "get-url", "origin"); err == nil {
		repoName = normalizeGitRemoteURL(remote)
	}
	if commit, err := runGitCommand(ctx, dir, "rev-parse", "HEAD"); err == nil {
		commitHash = commit
	}
	return repoName, commitHash
}

func runGitCommand(ctx context.Context, dir string, args ...string) (string, error) {
	cmdArgs := append([]string{"-C", dir}, args...)
	out, err := exec.CommandContext(ctx, "git", cmdArgs...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func normalizeGitRemoteURL(remoteURL string) string {
	remoteURL = strings.TrimSpace(remoteURL)
	remoteURL = strings.TrimSuffix(remoteURL, ".git")

	// SSH format: git@github.com:owner/repo → github.com/owner/repo
	if idx := strings.Index(remoteURL, ":"); idx != -1 && strings.Contains(remoteURL[:idx], "@") {
		host := remoteURL[:idx]
		path := remoteURL[idx+1:]
		if atIdx := strings.Index(host, "@"); atIdx != -1 {
			host = host[atIdx+1:]
		}
		return host + "/" + path
	}

	// HTTPS format: https://github.com/owner/repo → github.com/owner/repo
	if i := strings.Index(remoteURL, "://"); i != -1 {
		return remoteURL[i+3:]
	}

	return remoteURL
}
