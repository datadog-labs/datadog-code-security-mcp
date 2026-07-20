package main

import (
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/auth"
)

// TestDetectAuthMethod_ReturnsCachedValue verifies detectAuthMethod simply
// returns the process-level mcpAuthMethod, whatever it was set to.
func TestDetectAuthMethod_ReturnsCachedValue(t *testing.T) {
	for _, method := range []string{auth.MethodEnvVar, auth.MethodAuthProvider, auth.MethodNone} {
		t.Run(method, func(t *testing.T) {
			prev := mcpAuthMethod
			mcpAuthMethod = method
			t.Cleanup(func() { mcpAuthMethod = prev })

			if got := detectAuthMethod(); got != method {
				t.Errorf("detectAuthMethod() = %q, want %q", got, method)
			}
		})
	}
}

// TestDetectAuthMethod_UnaffectedByLaterEnvMutation is the regression guard
// for the bug where every MCP tool call after the first authenticated one
// misreported auth_method as "env_var". Once mcpAuthMethod is captured (as
// runServer does at startup), later exporting DD_API_KEY into the process
// environment — exactly what setAuthCredentials does as a side effect of
// resolving dd-auth credentials — must not change what detectAuthMethod
// returns.
func TestDetectAuthMethod_UnaffectedByLaterEnvMutation(t *testing.T) {
	prev := mcpAuthMethod
	mcpAuthMethod = auth.MethodAuthProvider
	t.Cleanup(func() { mcpAuthMethod = prev })

	// Simulate the side effect of a prior call's setAuthCredentials/ApplyToEnv.
	t.Setenv("DD_API_KEY", "resolved-via-dd-auth")

	if got := detectAuthMethod(); got != auth.MethodAuthProvider {
		t.Errorf("detectAuthMethod() = %q, want %q (must not flip to env_var just because DD_API_KEY is now set)", got, auth.MethodAuthProvider)
	}
}
