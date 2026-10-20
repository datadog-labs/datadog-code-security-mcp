package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/auth"
)

func useAuthProvider(t *testing.T, cfg *auth.Config) {
	t.Helper()
	p, err := auth.NewProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	prev := authProvider
	authProvider = p
	t.Cleanup(func() { authProvider = prev })
}

// Keys exported by an earlier call must not stop later calls from going
// through dd-auth, or they are never refreshed.
func TestSetAuthCredentialsAsksDDAuthWhenEnvAlreadyHasKeys(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake dd-auth is a shell script")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\necho DD_API_KEY=fresh-api\necho DD_APP_KEY=fresh-app\n"
	if err := os.WriteFile(filepath.Join(dir, "dd-auth"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("DD_API_KEY", "exported-earlier")
	t.Setenv("DD_APP_KEY", "exported-earlier")
	useAuthProvider(t, &auth.Config{DDAuthDomain: "app.datadoghq.com", Site: "datadoghq.com"})

	if err := setAuthCredentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("DD_API_KEY"); got != "fresh-api" {
		t.Fatalf("DD_API_KEY = %q, want fresh-api from dd-auth", got)
	}
}

func TestSetAuthCredentialsKeepsPermanentKeys(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("DD_API_KEY", "permanent-api")
	t.Setenv("DD_APP_KEY", "permanent-app")
	useAuthProvider(t, &auth.Config{
		APIKey:       "permanent-api",
		APPKey:       "permanent-app",
		DDAuthDomain: "app.datadoghq.com",
		Site:         "datadoghq.com",
	})

	if err := setAuthCredentials(context.Background()); err != nil {
		t.Fatalf("permanent keys must not need dd-auth: %v", err)
	}
	if got := os.Getenv("DD_API_KEY"); got != "permanent-api" {
		t.Fatalf("DD_API_KEY = %q, want permanent-api", got)
	}
}
