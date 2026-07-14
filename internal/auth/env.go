package auth

import (
	"context"
	"fmt"
	"os"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/constants"
)

// ApplyToEnv fetches credentials from the provider and exports them as
// DD_API_KEY / DD_APP_KEY / DD_SITE in the process environment so scanner
// subprocesses inherit them. It reports whether any credential was applied.
// A nil or unconfigured provider is a no-op that returns (false, nil).
func (p *Provider) ApplyToEnv(ctx context.Context) (bool, error) {
	if p == nil || !p.IsConfigured() {
		return false, nil
	}
	creds, err := p.GetCredentials(ctx)
	if err != nil {
		return false, err
	}
	if creds == nil {
		return false, nil
	}
	return creds.applyToEnv()
}

// applyToEnv exports the non-empty credential fields to the environment,
// returning whether anything was set.
func (c *Credentials) applyToEnv() (bool, error) {
	applied := false
	for _, kv := range []struct{ key, val string }{
		{constants.EnvAPIKey, c.APIKey},
		{constants.EnvAPPKey, c.APPKey},
		{constants.EnvSite, c.Site},
	} {
		if kv.val == "" {
			continue
		}
		if err := os.Setenv(kv.key, kv.val); err != nil {
			return applied, fmt.Errorf("set %s: %w", kv.key, err)
		}
		applied = true
	}
	return applied, nil
}

// LoadAndApplyToEnv loads auth config from the environment, builds a provider,
// and applies any resolved credentials to the environment. It is the entry
// point for paths that do not already hold a Provider (e.g. the CLI). A missing
// or unconfigured setup is a no-op that returns (false, nil).
func LoadAndApplyToEnv(ctx context.Context) (bool, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return false, err
	}
	if !cfg.IsConfigured() {
		return false, nil
	}
	p, err := NewProvider(cfg)
	if err != nil {
		return false, err
	}
	return p.ApplyToEnv(ctx)
}
