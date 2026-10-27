package main

import (
	"context"
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/auth"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/telemetry"
)

func TestPreparePromoteAuthCLIUsesEnvKeys(t *testing.T) {
	t.Setenv("DD_API_KEY", "key")
	t.Setenv("DD_APP_KEY", "app")
	t.Setenv("DD_AUTH_DOMAIN", "")

	method, err := preparePromoteAuth(context.Background(), telemetry.InterfaceCLI)
	if err != nil {
		t.Fatalf("preparePromoteAuth() error = %v", err)
	}
	if method != auth.MethodEnvVar {
		t.Fatalf("method = %q, want %q", method, auth.MethodEnvVar)
	}
}

func TestPreparePromoteAuthCLIMissingCredentials(t *testing.T) {
	t.Setenv("DD_API_KEY", "")
	t.Setenv("DD_APP_KEY", "")
	t.Setenv("DD_AUTH_DOMAIN", "")

	if _, err := preparePromoteAuth(context.Background(), telemetry.InterfaceCLI); err == nil {
		t.Fatal("expected an error when no credentials are configured")
	}
}

func TestPreparePromoteAuthMCPKeepsStartupMethod(t *testing.T) {
	t.Setenv("DD_API_KEY", "key")
	t.Setenv("DD_APP_KEY", "app")

	prev := mcpAuthMethod
	mcpAuthMethod = auth.MethodAuthProvider
	t.Cleanup(func() { mcpAuthMethod = prev })

	method, err := preparePromoteAuth(context.Background(), telemetry.InterfaceMCP)
	if err != nil {
		t.Fatalf("preparePromoteAuth() error = %v", err)
	}
	if method != auth.MethodAuthProvider {
		t.Fatalf("method = %q, want %q", method, auth.MethodAuthProvider)
	}
}
