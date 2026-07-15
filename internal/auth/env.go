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
// point for paths that do not already hold a Provider (e.g. the CLI).
//
// It returns the auth method (see Config.Method), computed from the config as
// loaded here — before any credential this call resolves is exported to the
// environment. Callers must capture this return value once and reuse it
// (e.g. for telemetry) rather than re-deriving the method later by inspecting
// the environment, which would by then reflect this call's own side effect.
// A missing or unconfigured setup is a no-op that returns (MethodNone, nil).
func LoadAndApplyToEnv(ctx context.Context) (string, error) {
	cfg, err := LoadConfig()
	if err != nil {
		return "", err
	}
	method := cfg.Method()
	if !cfg.IsConfigured() {
		return method, nil
	}
	p, err := NewProvider(cfg)
	if err != nil {
		return method, err
	}
	if _, err := p.ApplyToEnv(ctx); err != nil {
		return method, err
	}
	return method, nil
}
