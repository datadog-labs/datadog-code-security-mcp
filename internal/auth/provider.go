package auth

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Credentials holds authentication credentials
type Credentials struct {
	APIKey  string
	APPKey  string
	Site    string
	Expires time.Time // For dd-auth token expiration
}

// Provider provides authentication credentials
type Provider struct {
	config *Config
	mu     sync.RWMutex
	cached *Credentials
}

// NewProvider creates a new authentication provider
func NewProvider(cfg *Config) (*Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid auth config: %w", err)
	}

	return &Provider{
		config: cfg,
	}, nil
}

// GetCredentials returns authentication credentials
// This method is safe to call even when authentication is not configured
func (p *Provider) GetCredentials(ctx context.Context) (*Credentials, error) {
	if !p.config.IsConfigured() {
		return nil, nil // No auth configured, return nil (not an error)
	}

	// Try cached credentials first
	if creds := p.getCached(); creds != nil {
		return creds, nil
	}

	// Fetch new credentials
	var creds *Credentials
	var err error

	if p.config.HasAPIKeys() {
		creds, err = p.getAPIKeyCredentials()
	} else if p.config.HasDDAuth() {
		creds, err = p.getDDAuthCredentials(ctx)
	} else {
		return nil, fmt.Errorf("no authentication method configured")
	}

	if err != nil {
		return nil, err
	}

	// Cache credentials
	p.setCached(creds)

	return creds, nil
}

// getAPIKeyCredentials returns credentials from environment variables
func (p *Provider) getAPIKeyCredentials() (*Credentials, error) {
	return &Credentials{
		APIKey: p.config.APIKey,
		APPKey: p.config.APPKey,
		Site:   p.config.Site,
	}, nil
}

// getDDAuthCredentials fetches credentials from dd-auth
func (p *Provider) getDDAuthCredentials(ctx context.Context) (*Credentials, error) {
	// Call dd-auth --output to get credentials in shell export format
	cmd := exec.CommandContext(ctx, "dd-auth", "--output")

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("dd-auth failed: %s", string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("failed to execute dd-auth: %w", err)
	}

	// Parse dd-auth shell output format:
	// DD_API_KEY=...
	// DD_APP_KEY=...
	// DD_SITE=...
	creds := &Credentials{}

	// Parse each line looking for DD_API_KEY, DD_APP_KEY, DD_SITE
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key, value := parts[0], parts[1]
		switch key {
		case "DD_API_KEY":
			creds.APIKey = value
		case "DD_APP_KEY":
			creds.APPKey = value
		case "DD_SITE":
			creds.Site = value
		}
	}

	if creds.APIKey == "" || creds.APPKey == "" {
		return nil, fmt.Errorf("dd-auth returned empty credentials")
	}

	// dd-auth tokens typically expire after 1 hour
	creds.Expires = time.Now().Add(1 * time.Hour)

	return creds, nil
}

// getCached returns cached credentials if valid
func (p *Provider) getCached() *Credentials {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.cached == nil {
		return nil
	}

	// Check if expired (for dd-auth)
	if !p.cached.Expires.IsZero() && time.Now().After(p.cached.Expires) {
		return nil
	}

	return p.cached
}

// setCached caches credentials
func (p *Provider) setCached(creds *Credentials) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cached = creds
}

// IsConfigured returns true if authentication is configured
func (p *Provider) IsConfigured() bool {
	return p.config.IsConfigured()
}

// Config returns the authentication configuration
func (p *Provider) Config() *Config {
	return p.config
}
