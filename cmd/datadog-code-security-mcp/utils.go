package main

import (
	"os"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/constants"
)

// detectAuthMethod returns how credentials are configured before any auth loading.
// Must be called before loadAuthToEnv() or setAuthCredentials() mutates the environment.
func detectAuthMethod() string {
	if os.Getenv(constants.EnvAPIKey) != "" {
		return "env_var"
	}
	if authProvider != nil && authProvider.IsConfigured() {
		return "auth_provider"
	}
	return "none"
}
