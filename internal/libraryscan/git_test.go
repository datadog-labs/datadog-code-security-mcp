package libraryscan

import (
	"context"
	"testing"
)

func TestNormalizeGitRemoteURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "ssh format with .git suffix",
			input:    "git@github.com:owner/repo.git",
			expected: "github.com/owner/repo",
		},
		{
			name:     "https format with .git suffix",
			input:    "https://github.com/owner/repo.git",
			expected: "github.com/owner/repo",
		},
		{
			name:     "https format without .git suffix",
			input:    "https://github.com/owner/repo",
			expected: "github.com/owner/repo",
		},
		{
			name:     "already normalized",
			input:    "owner/repo",
			expected: "owner/repo",
		},
		{
			name:     "ssh format without .git suffix",
			input:    "git@github.com:owner/repo",
			expected: "github.com/owner/repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeGitRemoteURL(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeGitRemoteURL(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDetectGitContext_NonGitDir(t *testing.T) {
	// Running in /tmp should not be a git repo — expect empty strings, no panic
	repoName, commitHash := DetectGitContext(context.Background(), "/tmp")
	if repoName != "" {
		t.Errorf("expected empty repoName for non-git dir, got %q", repoName)
	}
	if commitHash != "" {
		t.Errorf("expected empty commitHash for non-git dir, got %q", commitHash)
	}
}
