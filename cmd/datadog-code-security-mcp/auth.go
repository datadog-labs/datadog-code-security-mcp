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
	// Check if already set via environment variables
	if os.Getenv(constants.EnvAPIKey) != "" && os.Getenv(constants.EnvAPPKey) != "" {
		fmt.Fprintf(os.Stderr, "Using %s and %s from environment\n", constants.EnvAPIKey, constants.EnvAPPKey)
		return nil
	}

	if authProvider == nil || !authProvider.IsConfigured() {
		return fmt.Errorf("no authentication configured (set %s/%s or %s)",
			constants.EnvAPIKey, constants.EnvAPPKey, constants.EnvAuthDomain)
	}

	applied, err := authProvider.ApplyToEnv(ctx)
	if err != nil {
		return fmt.Errorf("failed to apply credentials: %w", err)
	}
	if applied {
		fmt.Fprintln(os.Stderr, "Datadog credentials set from auth provider")
	}

	return nil
}
