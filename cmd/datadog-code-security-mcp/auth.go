package main

import (
	"context"
	"fmt"
	"os"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/constants"
)

// setAuthCredentials resolves credentials from the MCP server's auth provider
// and exports them as environment variables so the scanner subprocess can read
// them. Errors are fatal for the MCP path, which requires credentials to fetch
// rules. The shared apply logic lives in internal/auth (see Provider.ApplyToEnv).
func setAuthCredentials(ctx context.Context) error {
	// dd-auth keys expire, and after the first call the environment holds the
	// keys this process exported, so it cannot tell us they are still valid.
	// The provider reuses its cached keys until they expire.
	if usesDDAuthOnly() {
		return applyProviderCredentials(ctx)
	}

	if os.Getenv(constants.EnvAPIKey) != "" && os.Getenv(constants.EnvAPPKey) != "" {
		fmt.Fprintf(os.Stderr, "Using %s and %s from environment\n", constants.EnvAPIKey, constants.EnvAPPKey)
		return nil
	}

	if authProvider == nil || !authProvider.IsConfigured() {
		return fmt.Errorf("no authentication configured (set %s/%s or %s)",
			constants.EnvAPIKey, constants.EnvAPPKey, constants.EnvAuthDomain)
	}

	return applyProviderCredentials(ctx)
}

// usesDDAuthOnly reports whether the server started with DD_AUTH_DOMAIN and
// without both permanent keys.
func usesDDAuthOnly() bool {
	if authProvider == nil {
		return false
	}
	cfg := authProvider.Config()
	return cfg.HasDDAuth() && !cfg.HasAPIKeys()
}

func applyProviderCredentials(ctx context.Context) error {
	applied, err := authProvider.ApplyToEnv(ctx)
	if err != nil {
		return fmt.Errorf("failed to apply credentials: %w", err)
	}
	if applied {
		fmt.Fprintln(os.Stderr, "Datadog credentials set from auth provider")
	}

	return nil
}
