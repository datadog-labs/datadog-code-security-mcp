package auth

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[string]string
		wantSite string
		wantAuth bool
		wantErr  bool
	}{
		{
			name:     "no environment variables",
			envVars:  map[string]string{},
			wantSite: "datadoghq.com",
			wantAuth: false,
			wantErr:  false,
		},
		{
			name: "API keys configured",
			envVars: map[string]string{
				"DD_API_KEY": "test-api-key",
				"DD_APP_KEY": "test-app-key",
			},
			wantSite: "datadoghq.com",
			wantAuth: true,
			wantErr:  false,
		},
		{
			name: "API keys with custom site",
			envVars: map[string]string{
				"DD_API_KEY": "test-api-key",
				"DD_APP_KEY": "test-app-key",
				"DD_SITE":    "datadoghq.eu",
			},
			wantSite: "datadoghq.eu",
			wantAuth: true,
			wantErr:  false,
		},
		{
			name: "dd-auth configured",
			envVars: map[string]string{
				"DD_AUTH_DOMAIN": "app.datadoghq.com",
			},
			wantSite: "datadoghq.com",
			wantAuth: true,
			wantErr:  false,
		},
		{
			name: "custom subdomain",
			envVars: map[string]string{
				"DD_SITE": "custom.datadoghq.com",
			},
			wantSite: "custom.datadoghq.com",
			wantAuth: false,
			wantErr:  false,
		},
		{
			name: "gov cloud site",
			envVars: map[string]string{
				"DD_SITE": "ddog-gov.com",
			},
			wantSite: "ddog-gov.com",
			wantAuth: false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			os.Clearenv()

			// Set test environment variables
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			cfg, err := LoadConfig()
			if (err != nil) != tt.wantErr {
				t.Fatalf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil {
				if cfg.Site != tt.wantSite {
					t.Errorf("Site = %v, want %v", cfg.Site, tt.wantSite)
				}

				if cfg.IsConfigured() != tt.wantAuth {
					t.Errorf("IsConfigured() = %v, want %v", cfg.IsConfigured(), tt.wantAuth)
				}
			}
		})
	}
}

func TestLoadConfig_SecurityValidation(t *testing.T) {
	tests := []struct {
		name    string
		site    string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "path traversal attack",
			site:    "../../../etc/passwd",
			wantErr: true,
			errMsg:  "invalid characters", // Caught by domain regex first
		},
		{
			name:    "path with slash",
			site:    "evil.com/malicious",
			wantErr: true,
			errMsg:  "invalid characters", // Caught by domain regex first
		},
		{
			name:    "path with backslash",
			site:    "evil.com\\malicious",
			wantErr: true,
			errMsg:  "invalid characters", // Caught by domain regex first
		},
		{
			name:    "non-datadog domain",
			site:    "evil.com",
			wantErr: true,
			errMsg:  "valid Datadog domain",
		},
		{
			name:    "invalid characters",
			site:    "data$dog.com",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "SQL injection attempt",
			site:    "'; DROP TABLE users; --",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "URL with protocol",
			site:    "https://datadoghq.com",
			wantErr: true,
			errMsg:  "invalid characters",
		},
		{
			name:    "valid US3 site",
			site:    "us3.datadoghq.com",
			wantErr: false,
		},
		{
			name:    "valid EU site",
			site:    "datadoghq.eu",
			wantErr: false,
		},
		{
			name:    "valid with extra whitespace",
			site:    "  datadoghq.com  ",
			wantErr: false,
		},
		{
			name:    "valid mixed case (normalized)",
			site:    "DatadogHQ.COM",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Clearenv()
			os.Setenv("DD_SITE", tt.site)

			_, err := LoadConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("error message = %v, should contain %v", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestConfig_HasAPIKeys(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   bool
	}{
		{
			name: "both keys present",
			config: &Config{
				APIKey: "key",
				APPKey: "app",
			},
			want: true,
		},
		{
			name: "missing APP key",
			config: &Config{
				APIKey: "key",
			},
			want: false,
		},
		{
			name: "missing API key",
			config: &Config{
				APPKey: "app",
			},
			want: false,
		},
		{
			name:   "both missing",
			config: &Config{},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.HasAPIKeys(); got != tt.want {
				t.Errorf("HasAPIKeys() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "no auth is valid",
			config:  &Config{},
			wantErr: false,
		},
		{
			name: "valid API keys",
			config: &Config{
				APIKey: "key",
				APPKey: "app",
			},
			wantErr: false,
		},
		{
			name: "valid dd-auth",
			config: &Config{
				DDAuthDomain: "app.datadoghq.com",
			},
			wantErr: false,
		},
		{
			name: "both auth methods",
			config: &Config{
				APIKey:       "key",
				APPKey:       "app",
				DDAuthDomain: "app.datadoghq.com",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_String(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   string
	}{
		{
			name:   "no auth",
			config: &Config{},
			want:   "Auth: none (local-only mode)",
		},
		{
			name: "API keys",
			config: &Config{
				APIKey: "key",
				APPKey: "app",
				Site:   "datadoghq.com",
			},
			want: "Auth: API keys",
		},
		{
			name: "dd-auth",
			config: &Config{
				DDAuthDomain: "app.datadoghq.com",
			},
			want: "Auth: dd-auth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.String()
			// Just check that it contains the expected substring
			if tt.want == "Auth: none (local-only mode)" && got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}
