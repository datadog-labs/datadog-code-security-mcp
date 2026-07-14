package main

import (
	"context"
	"fmt"
	"os"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/constants"
)

// setAuthCredentials gets credentials from auth provider and sets them as environment variables
// This allows the scanner subprocess to access them.
//
// TODO(refactor): this duplicates the credential-loading logic in scan.go's
// loadAuthToEnv. Both should be consolidated into internal/auth so the CLI
// and MCP paths share a single implementation. Track in a follow-up PR.
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

	creds, err := authProvider.GetCredentials(ctx)
	if err != nil {
		return fmt.Errorf("failed to get credentials: %w", err)
	}

	if creds == nil {
		return fmt.Errorf("no credentials available from auth provider")
	}

	// Set environment variables for scanner subprocess
	if creds.APIKey != "" {
		if err := os.Setenv(constants.EnvAPIKey, creds.APIKey); err != nil {
			return fmt.Errorf("set %s: %w", constants.EnvAPIKey, err)
		}
		fmt.Fprintf(os.Stderr, "%s set from auth provider\n", constants.EnvAPIKey)
	}
	if creds.APPKey != "" {
		if err := os.Setenv(constants.EnvAPPKey, creds.APPKey); err != nil {
			return fmt.Errorf("set %s: %w", constants.EnvAPPKey, err)
		}
		fmt.Fprintf(os.Stderr, "%s set from auth provider\n", constants.EnvAPPKey)
	}
	if creds.Site != "" {
		if err := os.Setenv(constants.EnvSite, creds.Site); err != nil {
			return fmt.Errorf("set %s: %w", constants.EnvSite, err)
		}
		fmt.Fprintf(os.Stderr, "%s set to: %s\n", constants.EnvSite, creds.Site)
	}

	return nil
}
