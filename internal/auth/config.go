package auth

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Config holds authentication configuration
type Config struct {
	// API authentication (Option 1)
	APIKey string
	APPKey string
	Site   string

	// dd-auth integration (Option 2)
	DDAuthDomain string

	// Derived
	APIEndpoint string
}

// Valid Datadog sites (whitelist for security)
var validDatadogSites = map[string]bool{
	"datadoghq.com":     true,
	"us3.datadoghq.com": true,
	"us5.datadoghq.com": true,
	"datadoghq.eu":      true,
	"ddog-gov.com":      true,
	"ap1.datadoghq.com": true,
}

// Domain validation regex - only allows valid domain characters
var domainRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// LoadConfig loads authentication configuration from environment variables
func LoadConfig() (*Config, error) {
	cfg := &Config{
		APIKey:       os.Getenv("DD_API_KEY"),
		APPKey:       os.Getenv("DD_APP_KEY"),
		Site:         os.Getenv("DD_SITE"),
		DDAuthDomain: os.Getenv("DD_AUTH_DOMAIN"),
	}

	// Default site
	if cfg.Site == "" {
		cfg.Site = "datadoghq.com"
	}

	// Validate and sanitize site to prevent path injection
	if err := validateSite(&cfg.Site); err != nil {
		return nil, fmt.Errorf("invalid DD_SITE: %w", err)
	}

	// Construct API endpoint (site is now validated)
	cfg.APIEndpoint = fmt.Sprintf("https://api.%s", cfg.Site)

	return cfg, nil
}

// validateSite validates and sanitizes the Datadog site domain
func validateSite(site *string) error {
	// Normalize: trim whitespace and convert to lowercase
	*site = strings.TrimSpace(strings.ToLower(*site))

	// Security: Check against whitelist of known Datadog sites
	if validDatadogSites[*site] {
		return nil
	}

	// Security: Validate domain format (prevent path injection, special characters)
	if !domainRegex.MatchString(*site) {
		return fmt.Errorf("site contains invalid characters (must be a valid domain)")
	}

	// Security: Block common path traversal patterns
	if strings.Contains(*site, "..") || strings.Contains(*site, "/") || strings.Contains(*site, "\\") {
		return fmt.Errorf("site contains invalid path characters")
	}

	// Security: Ensure it's a datadoghq.com subdomain for non-whitelisted sites
	if !strings.HasSuffix(*site, ".datadoghq.com") && !strings.HasSuffix(*site, ".ddog-gov.com") {
		return fmt.Errorf("site must be a valid Datadog domain (e.g., datadoghq.com, datadoghq.eu, ddog-gov.com)")
	}

	return nil
}

// IsConfigured returns true if any authentication method is configured
func (c *Config) IsConfigured() bool {
	return c.HasAPIKeys() || c.HasDDAuth()
}

// HasAPIKeys returns true if API key authentication is configured
func (c *Config) HasAPIKeys() bool {
	return c.APIKey != "" && c.APPKey != ""
}

// HasDDAuth returns true if dd-auth is configured
func (c *Config) HasDDAuth() bool {
	return c.DDAuthDomain != ""
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if !c.IsConfigured() {
		// No authentication is valid (local-only mode)
		return nil
	}

	if c.HasAPIKeys() {
		if c.APIKey == "" {
			return fmt.Errorf("DD_API_KEY is required when using API key authentication")
		}
		if c.APPKey == "" {
			return fmt.Errorf("DD_APP_KEY is required when using API key authentication")
		}
	}

	if c.HasDDAuth() {
		if c.DDAuthDomain == "" {
			return fmt.Errorf("DD_AUTH_DOMAIN is required when using dd-auth")
		}
	}

	return nil
}

// String returns a string representation (with sensitive data masked)
func (c *Config) String() string {
	if !c.IsConfigured() {
		return "Auth: none (local-only mode)"
	}

	if c.HasAPIKeys() {
		return fmt.Sprintf("Auth: API keys (site=%s, endpoint=%s)", c.Site, c.APIEndpoint)
	}

	if c.HasDDAuth() {
		return fmt.Sprintf("Auth: dd-auth (domain=%s)", c.DDAuthDomain)
	}

	return "Auth: unknown"
}
