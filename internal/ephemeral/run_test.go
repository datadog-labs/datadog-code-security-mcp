package ephemeral

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// fakeAnalyzerScript stands in for datadog-static-analyzer. --help prints the
// configured usage. A scan records its arguments and writes FINDINGS to --output.
const fakeAnalyzerScript = `#!/bin/sh
if [ "$1" = "--help" ]; then
  printf '%s\n' "$HELP_TEXT"
  exit 0
fi
printf '%s\n' "$@" > "$ARGS_FILE"
while [ $# -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    printf '%s' "$FINDINGS" > "$2"
  fi
  shift
done
exit "${EXIT_CODE:-0}"
`

type fakeAnalyzer struct {
	argsFile string
}

func installFakeAnalyzer(t *testing.T, help, findings string, exitCode string) fakeAnalyzer {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake analyzer is a POSIX shell script")
	}
	binDir := t.TempDir()
	script := filepath.Join(binDir, "datadog-static-analyzer")
	if err := os.WriteFile(script, []byte(fakeAnalyzerScript), 0o755); err != nil {
		t.Fatal(err)
	}
	argsFile := filepath.Join(t.TempDir(), "args")
	t.Setenv("PATH", binDir)
	t.Setenv("HELP_TEXT", help)
	t.Setenv("FINDINGS", findings)
	t.Setenv("ARGS_FILE", argsFile)
	t.Setenv("EXIT_CODE", exitCode)
	return fakeAnalyzer{argsFile: argsFile}
}

func (f fakeAnalyzer) args(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(f.argsFile)
	if err != nil {
		t.Fatalf("analyzer was not run: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func validInput() Input {
	return Input{
		RuleCode:        "function visit(captures) {}",
		TreeSitterQuery: "(identifier) @id",
		Language:        "GO",
	}
}

func TestScanPassesRulesWithConfig(t *testing.T) {
	fake := installFakeAnalyzer(t, "  -r, --rules FILE\n      --rules-with-config", `[{"rule":"ephemeral"}]`, "0")
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(context.Background(), ScanRequest{
		Input:     validInput(),
		Directory: repo,
		Paths:     []string{"src", filepath.Join(repo, "src")},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if string(result.Findings) != `[{"rule":"ephemeral"}]` {
		t.Errorf("findings = %s", result.Findings)
	}

	args := fake.args(t)
	index := slices.Index(args, "-r")
	if index < 0 || index+2 >= len(args) || args[index+2] != "--rules-with-config" {
		t.Errorf("--rules-with-config must follow -r <file>: %v", args)
	}
	if !slices.Contains(args, "-b") {
		t.Errorf("missing -b: %v", args)
	}
	var subdirs []string
	for i, arg := range args {
		if arg == "-u" && i+1 < len(args) {
			subdirs = append(subdirs, args[i+1])
		}
	}
	if !slices.Equal(subdirs, []string{"src", "src"}) {
		t.Errorf("-u paths = %v, want relative src twice", subdirs)
	}
}

func TestScanKeepsFindingsOnNonZeroExit(t *testing.T) {
	installFakeAnalyzer(t, "--rules-with-config", `[{"rule":"ephemeral"}]`, "1")

	result, err := Scan(context.Background(), ScanRequest{Input: validInput(), Directory: t.TempDir()})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if string(result.Findings) != `[{"rule":"ephemeral"}]` {
		t.Errorf("findings = %s", result.Findings)
	}
}

func TestScanRequiresRulesWithConfigSupport(t *testing.T) {
	fake := installFakeAnalyzer(t, "  -r, --rules FILE", "[]", "0")

	_, err := Scan(context.Background(), ScanRequest{Input: validInput(), Directory: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "--rules-with-config") || !strings.Contains(err.Error(), "0.9.10") {
		t.Fatalf("error = %v, want upgrade error naming --rules-with-config and 0.9.10", err)
	}
	if _, statErr := os.Stat(fake.argsFile); statErr == nil {
		t.Error("analyzer scan ran on a binary without --rules-with-config")
	}
}

func TestScanReportsScannerFailure(t *testing.T) {
	installFakeAnalyzer(t, "--rules-with-config", "", "3")

	_, err := Scan(context.Background(), ScanRequest{Input: validInput(), Directory: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "scanner failed") {
		t.Fatalf("error = %v, want scanner failure", err)
	}
}

func TestResolveTargetsFollowsSymlinks(t *testing.T) {
	repo := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		filepath.Join(repo, "escape"):      outside,
		filepath.Join(repo, "inside"):      filepath.Join(repo, "src"),
		filepath.Join(outside, "repolink"): repo,
	}
	for link, target := range links {
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}

	if _, _, err := resolveTargets(repo, []string{"escape"}); err == nil || !strings.Contains(err.Error(), "outside directory") {
		t.Fatalf("link to outside: error = %v, want outside directory", err)
	}
	if _, got, err := resolveTargets(repo, []string{"inside"}); err != nil || !slices.Equal(got, []string{"inside"}) {
		t.Fatalf("link inside: paths = %v, error = %v", got, err)
	}
	symlinkedRoot := filepath.Join(outside, "repolink")
	if _, got, err := resolveTargets(symlinkedRoot, []string{"src", "inside"}); err != nil || !slices.Equal(got, []string{"src", "inside"}) {
		t.Fatalf("symlinked root: paths = %v, error = %v", got, err)
	}
	if _, _, err := resolveTargets(symlinkedRoot, []string{"escape"}); err == nil || !strings.Contains(err.Error(), "outside directory") {
		t.Fatalf("symlinked root, link to outside: error = %v, want outside directory", err)
	}
}

func TestResolveTargets(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(repo, "file.go")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()

	tests := []struct {
		name      string
		directory string
		paths     []string
		want      []string
		wantErr   string
	}{
		{name: "no paths", directory: repo},
		{name: "relative and cleaned", directory: repo, paths: []string{"a/./b", " ", "a/b/.."}, want: []string{filepath.Join("a", "b"), "a"}},
		{name: "absolute inside", directory: repo, paths: []string{filepath.Join(repo, "a")}, want: []string{"a"}},
		{name: "parent escape", directory: repo, paths: []string{"../x"}, wantErr: "outside directory"},
		{name: "nested escape", directory: repo, paths: []string{"a/../../x"}, wantErr: "outside directory"},
		{name: "absolute outside", directory: repo, paths: []string{outside}, wantErr: "outside directory"},
		{name: "missing path", directory: repo, paths: []string{"missing"}, wantErr: "missing"},
		{name: "directory is a file", directory: file, wantErr: "is not a directory"},
		{name: "directory missing", directory: filepath.Join(repo, "nope"), wantErr: "directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, got, err := resolveTargets(tt.directory, tt.paths)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveTargets: %v", err)
			}
			if root != repo {
				t.Errorf("root = %s, want %s", root, repo)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("paths = %v, want %v", got, tt.want)
			}
		})
	}
}
