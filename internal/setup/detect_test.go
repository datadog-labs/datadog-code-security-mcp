package setup

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIsInstalledFromPATH(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses an executable shell script")
	}

	home := t.TempDir()
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "codex"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	client, err := ClientByID("codex")
	if err != nil {
		t.Fatal(err)
	}
	detection, err := IsInstalled(client, home)
	if err != nil {
		t.Fatal(err)
	}
	if !detection.Installed {
		t.Fatal("codex on PATH was not detected")
	}
	if detection.Reason != "codex found on PATH" {
		t.Errorf("Reason = %q", detection.Reason)
	}
}

func TestIsInstalledFromHomeMarker(t *testing.T) {
	isolatePATH(t)
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}

	client, err := ClientByID("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	detection, err := IsInstalled(client, home)
	if err != nil {
		t.Fatal(err)
	}
	if !detection.Installed {
		t.Fatal("home marker was not detected")
	}
}

func TestIsInstalledWhenMissing(t *testing.T) {
	isolatePATH(t)
	client, err := ClientByID("codex")
	if err != nil {
		t.Fatal(err)
	}
	detection, err := IsInstalled(client, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if detection.Installed {
		t.Fatal("missing client was reported installed")
	}
	if detection.Reason != "client CLI and home markers were not found" {
		t.Errorf("Reason = %q", detection.Reason)
	}
}

func TestIsInstalledForSharedDestination(t *testing.T) {
	isolatePATH(t)
	client, err := ClientByID("agents")
	if err != nil {
		t.Fatal(err)
	}
	detection, err := IsInstalled(client, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !detection.Installed {
		t.Fatal("shared Agent Skills destination was not enabled")
	}
	if detection.Reason != "shared Agent Skills directory" {
		t.Errorf("Reason = %q", detection.Reason)
	}
}

func TestClientRegistry(t *testing.T) {
	want := map[string]string{
		"agents":      filepath.Join(".agents", "skills"),
		"claude-code": filepath.Join(".claude", "skills"),
		"codex":       filepath.Join(".codex", "skills"),
	}
	for _, client := range Clients() {
		relative, ok := want[client.ID]
		if !ok {
			t.Fatalf("unexpected client %q", client.ID)
		}
		if got := client.SkillsDir("/home/test"); got != filepath.Join("/home/test", relative) {
			t.Errorf("%s SkillsDir = %q", client.ID, got)
		}
		delete(want, client.ID)
	}
	if len(want) != 0 {
		t.Fatalf("missing clients: %v", want)
	}
}
