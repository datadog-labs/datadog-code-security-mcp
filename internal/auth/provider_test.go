package auth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// installFakeDDAuth puts a dd-auth on PATH that returns key-N and app-N on
// its Nth run. PATH holds only the fake's directory, so the script may use
// shell builtins only.
func installFakeDDAuth(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake dd-auth is a shell script")
	}
	dir := t.TempDir()
	countFile := filepath.Join(dir, "count")
	script := fmt.Sprintf(`#!/bin/sh
n=0
[ -f %[1]q ] && read -r n < %[1]q
n=$((n + 1))
echo "$n" > %[1]q
echo "DD_API_KEY=key-$n"
echo "DD_APP_KEY=app-$n"
`, countFile)
	if err := os.WriteFile(filepath.Join(dir, "dd-auth"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func TestGetCredentialsRefreshesExpiredDDAuthKeys(t *testing.T) {
	installFakeDDAuth(t)
	p, err := NewProvider(&Config{DDAuthDomain: "app.datadoghq.com", Site: "datadoghq.com"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	p.now = func() time.Time { return now }

	steps := []struct {
		advance time.Duration
		wantKey string
	}{
		{advance: 0, wantKey: "key-1"},
		{advance: 30 * time.Minute, wantKey: "key-1"},
		{advance: 31 * time.Minute, wantKey: "key-2"},
	}
	for _, step := range steps {
		now = now.Add(step.advance)
		creds, err := p.GetCredentials(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if creds.APIKey != step.wantKey {
			t.Fatalf("after %s: APIKey = %q, want %q", step.advance, creds.APIKey, step.wantKey)
		}
	}
}
