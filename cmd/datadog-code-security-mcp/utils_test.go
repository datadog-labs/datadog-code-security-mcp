package main

import (
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/auth"
)

func TestDetectAuthMethod_EnvVar(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-api-key")
	prev := authProvider
	authProvider = nil
	t.Cleanup(func() { authProvider = prev })

	if got := detectAuthMethod(); got != "env_var" {
		t.Errorf("detectAuthMethod() = %q, want %q", got, "env_var")
	}
}

func TestDetectAuthMethod_AuthProvider(t *testing.T) {
	t.Setenv("DD_API_KEY", "")

	provider, err := auth.NewProvider(&auth.Config{DDAuthDomain: "datadoghq.com"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	prev := authProvider
	authProvider = provider
	t.Cleanup(func() { authProvider = prev })

	if got := detectAuthMethod(); got != "auth_provider" {
		t.Errorf("detectAuthMethod() = %q, want %q", got, "auth_provider")
	}
}

func TestDetectAuthMethod_None(t *testing.T) {
	t.Setenv("DD_API_KEY", "")
	prev := authProvider
	authProvider = nil
	t.Cleanup(func() { authProvider = prev })

	if got := detectAuthMethod(); got != "none" {
		t.Errorf("detectAuthMethod() = %q, want %q", got, "none")
	}
}

func TestDetectAuthMethod_EnvVarTakesPrecedenceOverProvider(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-api-key")

	provider, err := auth.NewProvider(&auth.Config{DDAuthDomain: "datadoghq.com"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	prev := authProvider
	authProvider = provider
	t.Cleanup(func() { authProvider = prev })

	if got := detectAuthMethod(); got != "env_var" {
		t.Errorf("detectAuthMethod() = %q, want %q (env_var should take precedence)", got, "env_var")
	}
}
