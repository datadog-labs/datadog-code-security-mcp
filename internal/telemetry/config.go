package telemetry

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

const (
	configFileName = "config.json"
	configDirName  = ".datadog-code-security-mcp"
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
	// renameAttempts is the number of atomic-rename attempts the last persistence
	// operation needed (1 on a clean write). Values > 1 indicate cross-process
	// write contention (seen almost exclusively on Windows); 0 means no write
	// was attempted or it failed before the rename step.
	renameAttempts int
}

// configUpdateResult reports a best-effort targeted persistence operation.
// Only categorized errors are exposed so callers cannot accidentally include
// local filesystem paths in telemetry.
type configUpdateResult struct {
	errors  []string
	updated bool
	// renameAttempts mirrors configLoadResult.renameAttempts for update writes.
	renameAttempts int
}

// loadOrCreateConfig reads the config file from ~/.datadog-code-security-mcp/config.json,
// creating it (and its directory) on first run with a fresh install_id. All filesystem
// errors are non-fatal; callers always receive a usable config.
//
// No cross-process lock is taken: reads are safe because writes are atomic
// (write-temp + rename), and first-run creation uses an atomic create-if-absent
// so concurrent first-runs converge on a single install_id. Concurrent targeted
// updates to distinct fields are last-writer-wins — an accepted trade-off given
// they are rare (opt-out and the one-time notice flag) and low-stakes.
func loadOrCreateConfig() configLoadResult {
	path, err := configPath()
	if err != nil {
		return configLoadResult{
			config:      newConfig(),
			errors:      []string{"config_dir_unavailable"},
			idEphemeral: true,
		}
	}

	cfg, err := readConfig(path)
	if err == nil {
		// Repair missing install_id (corrupted file).
		if cfg.InstallID == "" {
			cfg.InstallID = uuid.New().String()
			attempts, saveErr := saveConfig(cfg, path)
			if saveErr != nil {
				return configLoadResult{
					config:         cfg,
					errors:         []string{"config_save_failed"},
					idEphemeral:    true,
					renameAttempts: attempts,
				}
			}
			return configLoadResult{config: cfg, renameAttempts: attempts}
		}
		return configLoadResult{config: cfg}
	}

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

	// First run: create the file atomically. If another process wins the race,
	// adopt its config so every concurrent first-run converges on one install_id.
	cfg = newConfig()
	created, createErr := createConfigIfAbsent(cfg, path)
	if createErr != nil {
		return configLoadResult{
			config:      cfg,
			errors:      []string{"config_save_failed"},
			idEphemeral: true,
		}
	}
	if !created {
		if existing, readErr := readConfig(path); readErr == nil && existing.InstallID != "" {
			return configLoadResult{config: existing}
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

// writeTempConfigFile marshals cfg and writes it to a new temp file in dir,
// named per pattern (see os.CreateTemp), fully durable on disk (chmod'd to
// 0600, written, and fsync'd) before returning. It's shared by saveConfig and
// createConfigIfAbsent, which differ only in how they commit the temp file
// (rename vs. hard-link) once it's ready.
//
// On any failure the temp file is removed and "" is returned; on success the
// caller owns removing tmpName once its commit step has run.
func writeTempConfigFile(cfg persistedConfig, dir, pattern string) (tmpName string, err error) {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal config: %w", err)
	}

	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", fmt.Errorf("create temp config: %w", err)
	}
	tmpName = tmp.Name()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("chmod temp config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("sync temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("close temp config: %w", err)
	}

	return tmpName, nil
}

// saveConfig atomically writes cfg to path via a temp file and rename, so
// readers never observe a partial write. It returns the number of atomic-rename
// attempts made (1 on a clean write, > 1 under contention, 0 when it failed
// before reaching the rename step) so callers can surface write contention in
// telemetry.
func saveConfig(cfg persistedConfig, path string) (int, error) {
	tmpName, err := writeTempConfigFile(cfg, filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return 0, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	attempts, err := renameWithRetry(tmpName, path)
	if err != nil {
		return attempts, fmt.Errorf("replace config: %w", err)
	}

	cleanup = false
	return attempts, nil
}

// renameFn performs the actual rename in renameWithRetry. It's a package
// variable (rather than a direct os.Rename call) purely so tests can
// substitute a fake that simulates the transient failures this retry loop
// exists to recover from — real POSIX renames essentially never fail
// transiently, so exercising the loop otherwise requires OS-specific
// contention that isn't reliably reproducible in CI.
var renameFn = os.Rename

// renameWithRetry renames oldpath to newpath, retrying on failure. Unlike POSIX
// rename(2), Windows' MoveFileEx can transiently fail with a sharing violation
// when multiple processes/goroutines race to replace the same destination file
// at nearly the same instant (there is no cross-process lock around config
// updates by design). Retrying with backoff plus jitter — to desynchronize the
// racing writers — resolves that contention; on POSIX this loop exits on the
// first attempt.
//
// It returns the number of attempts made (1 when the first rename succeeds) so
// callers can distinguish a clean write from a contended-but-recovered one.
func renameWithRetry(oldpath, newpath string) (attempts int, err error) {
	const maxAttempts = 10
	for attempt := 0; attempt < maxAttempts; attempt++ {
		attempts = attempt + 1
		if err = renameFn(oldpath, newpath); err == nil {
			return attempts, nil
		}
		if attempt < maxAttempts-1 {
			backoff := time.Duration(attempt+1) * 5 * time.Millisecond
			jitter := time.Duration(rand.Int63n(int64(5 * time.Millisecond)))
			time.Sleep(backoff + jitter)
		}
	}
	return attempts, err
}

// updateConfig performs a targeted read-modify-write. The callback must only
// mutate the fields it owns. There is no cross-process lock: the write itself
// is atomic, so concurrent updates to distinct fields are last-writer-wins.
func updateConfig(update func(*persistedConfig)) configUpdateResult {
	path, err := configPath()
	if err != nil {
		return configUpdateResult{errors: []string{"config_dir_unavailable"}}
	}

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
	attempts, saveErr := saveConfig(cfg, path)
	if saveErr != nil {
		return configUpdateResult{errors: []string{"config_save_failed"}, renameAttempts: attempts}
	}
	return configUpdateResult{updated: true, renameAttempts: attempts}
}

// createConfigIfAbsent atomically creates path with cfg only if it does not yet
// exist. It writes a fully-formed temp file and hard-links it into place, so a
// concurrent reader never observes a partial file and concurrent first-runs
// converge on a single install_id without a lock. Returns created=false (and no
// error) when the file already exists, signalling the caller to re-read it.
func createConfigIfAbsent(cfg persistedConfig, path string) (created bool, err error) {
	tmpName, err := writeTempConfigFile(cfg, filepath.Dir(path), "."+filepath.Base(path)+".new-*")
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(tmpName) }()

	if err := os.Link(tmpName, path); err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("link config: %w", err)
	}
	return true, nil
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
