package telemetry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

const configFileName = "config.json"
const configDirName = ".datadog-code-security-mcp"

// persistedConfig is the on-disk representation of the telemetry configuration.
type persistedConfig struct {
	InstallID            string `json:"install_id"`
	TelemetryEnabled     *bool  `json:"telemetry_enabled,omitempty"`
	FirstRunNoticeShown  bool   `json:"first_run_notice_shown"`
}

// configLoadResult is the outcome of loadOrCreateConfig. Errors are represented
// as categorized kind strings (never raw messages or paths) so they are safe to
// include in telemetry.
type configLoadResult struct {
	config      persistedConfig
	errors      []string // categorized problem kinds, e.g. "config_dir_unavailable"
	idEphemeral bool     // true when install_id could not be persisted to disk
}

// loadOrCreateConfig reads the config file from ~/.datadog-code-security-mcp/config.json,
// creating it (and its directory) on first run with a fresh install_id. All filesystem
// errors are non-fatal; callers always receive a usable config.
func loadOrCreateConfig() configLoadResult {
	var errs []string

	path, err := configPath()
	if err != nil {
		errs = append(errs, "config_dir_unavailable")
		return configLoadResult{config: newConfig(), errors: errs, idEphemeral: true}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			// Unreadable but present — return a fresh ephemeral config without writing.
			errs = append(errs, "config_read_failed")
			return configLoadResult{config: newConfig(), errors: errs, idEphemeral: true}
		}
		// File does not exist yet — create it.
		cfg := newConfig()
		if saveErr := saveConfig(cfg, path); saveErr != nil {
			errs = append(errs, "config_save_failed")
			return configLoadResult{config: cfg, errors: errs, idEphemeral: true}
		}
		return configLoadResult{config: cfg}
	}

	var cfg persistedConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		errs = append(errs, "config_parse_failed")
		return configLoadResult{config: newConfig(), errors: errs, idEphemeral: true}
	}

	// Repair missing install_id (corrupted file).
	if cfg.InstallID == "" {
		cfg.InstallID = uuid.New().String()
		if saveErr := saveConfig(cfg, path); saveErr != nil {
			errs = append(errs, "config_save_failed")
			return configLoadResult{config: cfg, errors: errs, idEphemeral: true}
		}
	}

	return configLoadResult{config: cfg}
}

// saveConfig atomically writes cfg to path (temp file + rename).
func saveConfig(cfg persistedConfig, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write temp config: %w", err)
	}

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename config: %w", err)
	}

	return nil
}

// persistConfig saves cfg, re-resolving the path. Non-fatal on error.
func persistConfig(cfg persistedConfig) {
	path, err := configPath()
	if err != nil {
		return
	}
	_ = saveConfig(cfg, path)
}

// configPath returns the full path to the config file, creating the directory if needed.
func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("user home dir: %w", err)
	}

	dir := filepath.Join(home, configDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}

	return filepath.Join(dir, configFileName), nil
}

// newConfig creates a fresh config with a new random install_id.
func newConfig() persistedConfig {
	return persistedConfig{
		InstallID: uuid.New().String(),
	}
}
