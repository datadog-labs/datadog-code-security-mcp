package telemetry

import (
	"os"
	"path/filepath"
	"testing"
)

// withTempHome redirects os.UserHomeDir by changing $HOME to a temp dir.
func withTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

// TestInstallID_StableAcrossLoads verifies the same install_id is returned
// on subsequent loads (unique-per-installation requirement).
func TestInstallID_StableAcrossLoads(t *testing.T) {
	withTempHome(t)

	first := loadOrCreateConfig()
	if first.config.InstallID == "" {
		t.Fatal("first load: install_id is empty")
	}
	if len(first.errors) > 0 {
		t.Errorf("unexpected config errors on first load: %v", first.errors)
	}

	second := loadOrCreateConfig()
	if second.config.InstallID != first.config.InstallID {
		t.Errorf("install_id changed between loads: %q vs %q", first.config.InstallID, second.config.InstallID)
	}
}

// TestInstallID_UniquePerInstall verifies different home dirs produce different ids.
func TestInstallID_UniquePerInstall(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	t.Setenv("HOME", dir1)
	r1 := loadOrCreateConfig()

	t.Setenv("HOME", dir2)
	r2 := loadOrCreateConfig()

	if r1.config.InstallID == r2.config.InstallID {
		t.Error("different installs should not share an install_id")
	}
}

// TestAtomicWrite verifies that saveConfig writes to a temp file and renames atomically.
func TestAtomicWrite_NoTempFileLeft(t *testing.T) {
	home := withTempHome(t)

	cfg := newConfig()
	path, err := configPath()
	if err != nil {
		t.Fatalf("configPath: %v", err)
	}
	if err := saveConfig(cfg, path); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}

	// The .tmp file must not exist after a successful write.
	tmp := path + ".tmp"
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("temp file %q should not exist after atomic write", tmp)
	}

	// The real config file must exist.
	configDir := filepath.Join(home, configDirName)
	if _, err := os.Stat(filepath.Join(configDir, configFileName)); err != nil {
		t.Errorf("config file not found: %v", err)
	}
}

// TestConfigDir_Permissions verifies the config dir is created with mode 0700.
func TestConfigDir_Permissions(t *testing.T) {
	home := withTempHome(t)

	result := loadOrCreateConfig()
	if len(result.errors) > 0 {
		t.Fatalf("unexpected config errors: %v", result.errors)
	}

	dir := filepath.Join(home, configDirName)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat config dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("config dir permissions = %o, want 0700", perm)
	}
}

// TestFirstRunNoticeFlag_Persisted verifies first_run_notice_shown is persisted.
func TestFirstRunNoticeFlag_Persisted(t *testing.T) {
	withTempHome(t)

	r := loadOrCreateConfig()
	if r.config.FirstRunNoticeShown {
		t.Fatal("first_run_notice_shown should be false on first load")
	}

	cfg := r.config
	cfg.FirstRunNoticeShown = true
	persistConfig(cfg)

	reloaded := loadOrCreateConfig()
	if !reloaded.config.FirstRunNoticeShown {
		t.Error("first_run_notice_shown not persisted across loads")
	}
}

// TestIsEnabled_DoNotTrack verifies DO_NOT_TRACK disables telemetry.
func TestIsEnabled_DoNotTrack(t *testing.T) {
	t.Setenv("DO_NOT_TRACK", "1")
	cfg := persistedConfig{InstallID: "test"}
	if isEnabled(Options{CompiledToken: "tok"}, cfg) {
		t.Error("telemetry should be disabled when DO_NOT_TRACK=1")
	}
}

// TestIsEnabled_EnvVar verifies DD_CODE_SECURITY_TELEMETRY_DISABLED disables telemetry.
func TestIsEnabled_EnvVar(t *testing.T) {
	t.Setenv("DD_CODE_SECURITY_TELEMETRY_DISABLED", "true")
	cfg := persistedConfig{InstallID: "test"}
	if isEnabled(Options{CompiledToken: "tok"}, cfg) {
		t.Error("telemetry should be disabled when DD_CODE_SECURITY_TELEMETRY_DISABLED=true")
	}
}

// TestIsEnabled_NoTelemetryFlag verifies the --no-telemetry flag disables telemetry.
func TestIsEnabled_NoTelemetryFlag(t *testing.T) {
	cfg := persistedConfig{InstallID: "test"}
	if isEnabled(Options{CompiledToken: "tok", NoTelemetry: true}, cfg) {
		t.Error("telemetry should be disabled when NoTelemetry=true")
	}
}

// TestIsEnabled_ConfigFileOptOut verifies config file opt-out is respected.
func TestIsEnabled_ConfigFileOptOut(t *testing.T) {
	disabled := false
	cfg := persistedConfig{InstallID: "test", TelemetryEnabled: &disabled}
	if isEnabled(Options{CompiledToken: "tok"}, cfg) {
		t.Error("telemetry should be disabled when config.telemetry_enabled=false")
	}
}

// TestLoadOrCreate_NoErrorsOnHappyPath verifies errors slice is empty when all I/O succeeds.
func TestLoadOrCreate_NoErrorsOnHappyPath(t *testing.T) {
	withTempHome(t)
	r := loadOrCreateConfig()
	if len(r.errors) != 0 {
		t.Errorf("expected no config errors, got %v", r.errors)
	}
	if r.idEphemeral {
		t.Error("id_ephemeral should be false when config was successfully persisted")
	}
}

// TestLoadOrCreate_ErrorsWhenDirUnavailable verifies config_dir_unavailable is reported
// when HOME is unset/invalid so the config directory cannot be created.
func TestLoadOrCreate_ErrorsWhenDirUnavailable(t *testing.T) {
	t.Setenv("HOME", "/nonexistent-path-that-cannot-be-created-xyz")
	r := loadOrCreateConfig()
	if len(r.errors) == 0 {
		t.Error("expected config errors when home dir is unavailable")
	}
	if !r.idEphemeral {
		t.Error("id_ephemeral should be true when config could not be persisted")
	}
	if r.config.InstallID == "" {
		t.Error("should still have an ephemeral install_id even on failure")
	}
}

// TestIsTruthy covers the truthy/falsy helper.
func TestIsTruthy(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"yes", true},
		{"0", false},
		{"false", false},
		{"", false},
		{"no", false},
	}
	for _, c := range cases {
		if got := isTruthy(c.in); got != c.want {
			t.Errorf("isTruthy(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
