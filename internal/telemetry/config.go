package telemetry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

const (
	configFileName = "config.json"
	configDirName  = ".datadog-code-security-mcp"
	configLockName = "config.lock"

	configLockWait       = 2 * time.Second
	configLockStaleAfter = 30 * time.Second
	configLockPoll       = 10 * time.Millisecond
)

// persistedConfig is the on-disk representation of the telemetry configuration.
type persistedConfig struct {
	InstallID           string `json:"install_id"`
	TelemetryEnabled    *bool  `json:"telemetry_enabled,omitempty"`
	FirstRunNoticeShown bool   `json:"first_run_notice_shown"`
	unknownFields       map[string]json.RawMessage
}

func (c *persistedConfig) UnmarshalJSON(data []byte) error {
	type configFields persistedConfig
	var fields configFields
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}

	var unknown map[string]json.RawMessage
	if err := json.Unmarshal(data, &unknown); err != nil {
		return err
	}
	delete(unknown, "install_id")
	delete(unknown, "telemetry_enabled")
	delete(unknown, "first_run_notice_shown")

	*c = persistedConfig(fields)
	c.unknownFields = unknown
	return nil
}

func (c persistedConfig) MarshalJSON() ([]byte, error) {
	type configFields persistedConfig
	data, err := json.Marshal(configFields(c))
	if err != nil {
		return nil, err
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	for name, value := range c.unknownFields {
		if _, known := fields[name]; !known {
			fields[name] = value
		}
	}
	return json.Marshal(fields)
}

// configLoadResult is the outcome of loadOrCreateConfig. Errors are represented
// as categorized kind strings (never raw messages or paths) so they are safe to
// include in telemetry.
type configLoadResult struct {
	config      persistedConfig
	errors      []string // categorized problem kinds, e.g. "config_dir_unavailable"
	idEphemeral bool     // true when install_id could not be persisted to disk
}

// configUpdateResult reports a best-effort targeted persistence operation.
// Only categorized errors are exposed so callers cannot accidentally include
// local filesystem paths in telemetry.
type configUpdateResult struct {
	errors  []string
	updated bool
}

// loadOrCreateConfig reads the config file from ~/.datadog-code-security-mcp/config.json,
// creating it (and its directory) on first run with a fresh install_id. All filesystem
// errors are non-fatal; callers always receive a usable config.
func loadOrCreateConfig() configLoadResult {
	path, err := configPath()
	if err != nil {
		return configLoadResult{
			config:      newConfig(),
			errors:      []string{"config_dir_unavailable"},
			idEphemeral: true,
		}
	}

	lock, err := acquireConfigLock(filepath.Join(filepath.Dir(path), configLockName), configLockWait, configLockStaleAfter)
	if err != nil {
		// Atomic replacement makes an unlocked read safe, and avoiding an
		// unlocked write prevents a timed-out process from racing the lock owner.
		cfg, readErr := readConfig(path)
		if readErr == nil {
			result := configLoadResult{config: cfg, errors: []string{"config_lock_unavailable"}}
			if result.config.InstallID == "" {
				result.config.InstallID = uuid.New().String()
				result.idEphemeral = true
			}
			return result
		}
		kind := "config_read_failed"
		if os.IsNotExist(readErr) {
			return configLoadResult{
				config:      newConfig(),
				errors:      []string{"config_lock_unavailable"},
				idEphemeral: true,
			}
		} else if isConfigParseError(readErr) {
			kind = "config_parse_failed"
		}
		return configLoadResult{
			config:      newConfig(),
			errors:      []string{"config_lock_unavailable", kind},
			idEphemeral: true,
		}
	}
	defer lock.release()

	cfg, err := readConfig(path)
	if err != nil {
		if !os.IsNotExist(err) {
			kind := "config_read_failed"
			if isConfigParseError(err) {
				kind = "config_parse_failed"
			}
			return configLoadResult{
				config:      newConfig(),
				errors:      []string{kind},
				idEphemeral: true,
			}
		}

		cfg = newConfig()
		if saveErr := saveConfig(cfg, path); saveErr != nil {
			return configLoadResult{
				config:      cfg,
				errors:      []string{"config_save_failed"},
				idEphemeral: true,
			}
		}
		return configLoadResult{config: cfg}
	}

	// Repair missing install_id (corrupted file).
	if cfg.InstallID == "" {
		cfg.InstallID = uuid.New().String()
		if saveErr := saveConfig(cfg, path); saveErr != nil {
			return configLoadResult{
				config:      cfg,
				errors:      []string{"config_save_failed"},
				idEphemeral: true,
			}
		}
	}

	return configLoadResult{config: cfg}
}

type configParseError struct {
	err error
}

func (e *configParseError) Error() string {
	return e.err.Error()
}

func (e *configParseError) Unwrap() error {
	return e.err
}

func isConfigParseError(err error) bool {
	_, ok := err.(*configParseError)
	return ok
}

func readConfig(path string) (persistedConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return persistedConfig{}, err
	}

	var cfg persistedConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return persistedConfig{}, &configParseError{err: err}
	}
	return cfg, nil
}

// saveConfig atomically writes cfg to path. Its caller must hold the config
// lock whenever path is the live telemetry config.
func saveConfig(cfg persistedConfig, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}

	cleanup = false
	return nil
}

// updateConfig performs a targeted read-modify-write while holding the
// cross-process config lock. The callback must only mutate the fields it owns.
func updateConfig(update func(*persistedConfig)) configUpdateResult {
	path, err := configPath()
	if err != nil {
		return configUpdateResult{errors: []string{"config_dir_unavailable"}}
	}

	lock, err := acquireConfigLock(filepath.Join(filepath.Dir(path), configLockName), configLockWait, configLockStaleAfter)
	if err != nil {
		return configUpdateResult{errors: []string{"config_lock_unavailable"}}
	}
	defer lock.release()

	cfg, err := readConfig(path)
	if err != nil {
		if !os.IsNotExist(err) {
			kind := "config_read_failed"
			if isConfigParseError(err) {
				kind = "config_parse_failed"
			}
			return configUpdateResult{errors: []string{kind}}
		}
		cfg = newConfig()
	}

	update(&cfg)
	if err := saveConfig(cfg, path); err != nil {
		return configUpdateResult{errors: []string{"config_save_failed"}}
	}
	return configUpdateResult{updated: true}
}

type configLock struct {
	path      string
	ownerPath string
}

func acquireConfigLock(path string, wait, staleAfter time.Duration) (*configLock, error) {
	deadline := time.Now().Add(wait)

	for {
		err := os.Mkdir(path, 0o700)
		if err == nil {
			ownerPath := filepath.Join(path, uuid.New().String())
			owner, ownerErr := os.OpenFile(ownerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if ownerErr != nil {
				_ = os.Remove(path)
				return nil, fmt.Errorf("create lock owner: %w", ownerErr)
			}
			if _, ownerErr = fmt.Fprintf(owner, "%d\n", os.Getpid()); ownerErr == nil {
				ownerErr = owner.Sync()
			}
			if closeErr := owner.Close(); ownerErr == nil {
				ownerErr = closeErr
			}
			if ownerErr != nil {
				_ = os.Remove(ownerPath)
				_ = os.Remove(path)
				return nil, fmt.Errorf("initialize lock owner: %w", ownerErr)
			}
			return &configLock{path: path, ownerPath: ownerPath}, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("create config lock: %w", err)
		}

		recovered, recoverErr := recoverStaleConfigLock(path, staleAfter)
		if recoverErr != nil {
			return nil, recoverErr
		}
		if recovered {
			continue
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("config lock wait exceeded")
		}
		sleep := configLockPoll
		if remaining < sleep {
			sleep = remaining
		}
		time.Sleep(sleep)
	}
}

func recoverStaleConfigLock(path string, staleAfter time.Duration) (bool, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat config lock: %w", err)
	}
	if time.Since(info.ModTime()) < staleAfter {
		return false, nil
	}

	entries, err := os.ReadDir(path)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read stale config lock: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return false, fmt.Errorf("stale config lock contains unexpected directory")
		}
		if err := os.Remove(filepath.Join(path, entry.Name())); err != nil && !os.IsNotExist(err) {
			return false, fmt.Errorf("remove stale config lock owner: %w", err)
		}
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		// A new owner may have appeared while the stale directory was being
		// cleaned. Treat a non-empty lock as active and retry normally.
		return false, nil
	}
	return true, nil
}

func (l *configLock) release() {
	if l == nil {
		return
	}
	// The owner filename is unique. If stale recovery already removed this
	// owner and another process acquired the lock, these removals cannot delete
	// the successor's owner file or its non-empty lock directory.
	if err := os.Remove(l.ownerPath); err != nil {
		return
	}
	_ = os.Remove(l.path)
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
