package main

import (
	"context"
	"fmt"
	"os"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/constants"
)

// setAuthCredentials gets credentials from auth provider and sets them as environment variables
// This allows the scanner subprocess to access them
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
		os.Setenv(constants.EnvAPIKey, creds.APIKey)
		fmt.Fprintf(os.Stderr, "%s set from auth provider\n", constants.EnvAPIKey)
	}
	if creds.APPKey != "" {
		os.Setenv(constants.EnvAPPKey, creds.APPKey)
		fmt.Fprintf(os.Stderr, "%s set from auth provider\n", constants.EnvAPPKey)
	}
	if creds.Site != "" {
		os.Setenv(constants.EnvSite, creds.Site)
		fmt.Fprintf(os.Stderr, "%s set to: %s\n", constants.EnvSite, creds.Site)
	}

	return nil
}
