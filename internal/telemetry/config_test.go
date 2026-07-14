package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

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

	setTestHome(t, dir1)
	r1 := loadOrCreateConfig()

	setTestHome(t, dir2)
	r2 := loadOrCreateConfig()

	if r1.config.InstallID == r2.config.InstallID {
		t.Error("different installs should not share an install_id")
	}
}

// TestAtomicWrite verifies that saveConfig writes to a unique temp file and replaces atomically.
func TestAtomicWrite_NoTempFileLeft(t *testing.T) {
	home := withTempHome(t)

	cfg := newConfig()
	path, err := configPath()
	if err != nil {
		t.Fatalf("configPath: %v", err)
	}
	if _, err := saveConfig(cfg, path); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}

	temps, err := filepath.Glob(filepath.Join(filepath.Dir(path), "."+configFileName+".tmp-*"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	if len(temps) != 0 {
		t.Errorf("temporary config files left after atomic write: %v", temps)
	}

	// The real config file must exist.
	configDir := filepath.Join(home, configDirName)
	if _, err := os.Stat(filepath.Join(configDir, configFileName)); err != nil {
		t.Errorf("config file not found: %v", err)
	}
}

func TestAtomicWrite_CleansTempFileOnFailure(t *testing.T) {
	home := withTempHome(t)
	configDir := filepath.Join(home, configDirName)
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	destination := filepath.Join(configDir, "destination-directory")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatalf("create invalid destination: %v", err)
	}

	if _, err := saveConfig(newConfig(), destination); err == nil {
		t.Fatal("saveConfig succeeded with a directory as its destination")
	}
	temps, err := filepath.Glob(filepath.Join(configDir, "."+filepath.Base(destination)+".tmp-*"))
	if err != nil {
		t.Fatalf("glob temporary files: %v", err)
	}
	if len(temps) != 0 {
		t.Errorf("temporary config files left after failed save: %v", temps)
	}
}

// TestConfigDir_Permissions verifies the config dir is created with mode 0700.
func TestConfigDir_Permissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix directory permission bits")
	}
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

	result := updateConfig(func(cfg *persistedConfig) {
		cfg.FirstRunNoticeShown = true
	})
	if !result.updated {
		t.Fatalf("update config: %v", result.errors)
	}

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
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
		t.Fatalf("create blocking file: %v", err)
	}
	setTestHome(t, filepath.Join(blocker, "home"))
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

func TestConcurrentFirstLoadConvergesAcrossProcesses(t *testing.T) {
	home := t.TempDir()
	const processCount = 8

	commands := make([]*exec.Cmd, processCount)
	outputs := make([]bytes.Buffer, processCount)
	for i := range commands {
		cmd := configHelperCommand(t, home, "load")
		cmd.Stdout = &outputs[i]
		commands[i] = cmd
		if err := cmd.Start(); err != nil {
			t.Fatalf("start helper %d: %v", i, err)
		}
	}
	for i, cmd := range commands {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("wait for helper %d: %v; output=%q", i, err, outputs[i].String())
		}
	}

	want := firstOutputLine(outputs[0].String())
	if want == "" {
		t.Fatal("first helper returned an empty install ID")
	}
	for i := 1; i < processCount; i++ {
		if got := firstOutputLine(outputs[i].String()); got != want {
			t.Errorf("helper %d install ID = %q, want %q", i, got, want)
		}
	}

	setTestHome(t, home)
	persisted := loadOrCreateConfig()
	if persisted.config.InstallID != want {
		t.Errorf("persisted install ID = %q, want %q", persisted.config.InstallID, want)
	}
}

func TestTargetedUpdatePreservesUnknownFields(t *testing.T) {
	home := withTempHome(t)
	configDir := filepath.Join(home, configDirName)
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	path := filepath.Join(configDir, configFileName)
	const original = `{"install_id":"stable","telemetry_enabled":false,"future_setting":{"value":42}}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result := updateConfig(func(cfg *persistedConfig) {
		cfg.FirstRunNoticeShown = true
	})
	if !result.updated {
		t.Fatalf("targeted update: %v", result.errors)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	var futureSetting struct {
		Value int `json:"value"`
	}
	if err := json.Unmarshal(document["future_setting"], &futureSetting); err != nil {
		t.Fatalf("parse unknown field: %v", err)
	}
	if futureSetting.Value != 42 {
		t.Errorf("unknown field value = %d, want 42", futureSetting.Value)
	}
}

func TestNoticeUpdatePreservesNewerOptOut(t *testing.T) {
	withTempHome(t)
	if result := loadOrCreateConfig(); len(result.errors) != 0 {
		t.Fatalf("initialize config: %v", result.errors)
	}
	disabled := false
	optOut := updateConfig(func(cfg *persistedConfig) {
		cfg.TelemetryEnabled = &disabled
	})
	if !optOut.updated {
		t.Fatalf("persist opt-out: %v", optOut.errors)
	}

	client := &Client{enabled: true, firstRun: true}
	client.MaybeShowFirstRunNotice()

	got := loadOrCreateConfig()
	if got.config.TelemetryEnabled == nil || *got.config.TelemetryEnabled {
		t.Error("notice update overwrote newer telemetry opt-out")
	}
	if !got.config.FirstRunNoticeShown {
		t.Error("notice flag was not persisted")
	}
}

func TestConcurrentUpdatesLeaveNoTemporaryFiles(t *testing.T) {
	home := withTempHome(t)
	if result := loadOrCreateConfig(); len(result.errors) != 0 {
		t.Fatalf("initialize config: %v", result.errors)
	}

	const updateCount = 20
	var wg sync.WaitGroup
	errs := make(chan []string, updateCount)
	for i := 0; i < updateCount; i++ {
		wg.Add(1)
		go func(shown bool) {
			defer wg.Done()
			result := updateConfig(func(cfg *persistedConfig) {
				cfg.FirstRunNoticeShown = shown
			})
			if !result.updated {
				errs <- result.errors
			}
		}(i%2 == 0)
	}
	wg.Wait()
	close(errs)
	for updateErrs := range errs {
		t.Errorf("concurrent update failed: %v", updateErrs)
	}

	configDir := filepath.Join(home, configDirName)
	temps, err := filepath.Glob(filepath.Join(configDir, "."+configFileName+".tmp-*"))
	if err != nil {
		t.Fatalf("glob temporary files: %v", err)
	}
	if len(temps) != 0 {
		t.Errorf("temporary config files left behind: %v", temps)
	}
}

func TestLoadOrCreate_CorruptConfigRemainsUntouched(t *testing.T) {
	home := withTempHome(t)
	configDir := filepath.Join(home, configDirName)
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	path := filepath.Join(configDir, configFileName)
	const corrupt = `{"install_id":`
	if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
		t.Fatalf("write corrupt config: %v", err)
	}

	result := loadOrCreateConfig()
	if !containsString(result.errors, "config_parse_failed") {
		t.Errorf("errors = %v, want config_parse_failed", result.errors)
	}
	if !result.idEphemeral {
		t.Error("corrupt config should produce an ephemeral install ID")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corrupt config: %v", err)
	}
	if string(data) != corrupt {
		t.Errorf("corrupt config was overwritten: %q", data)
	}
}

func TestConfigPathUsesIsolatedHome(t *testing.T) {
	home := withTempHome(t)
	path, err := configPath()
	if err != nil {
		t.Fatalf("configPath: %v", err)
	}
	want := filepath.Join(home, configDirName, configFileName)
	if path != want {
		t.Errorf("config path = %q, want %q", path, want)
	}
}

func TestConfigHelperProcess(t *testing.T) {
	if os.Getenv("TELEMETRY_CONFIG_HELPER") != "1" {
		return
	}

	switch os.Getenv("TELEMETRY_CONFIG_ACTION") {
	case "load":
		result := loadOrCreateConfig()
		if len(result.errors) != 0 {
			t.Fatalf("load errors: %v", result.errors)
		}
		_, _ = fmt.Fprintln(os.Stdout, result.config.InstallID)
	default:
		t.Fatalf("unknown helper action %q", os.Getenv("TELEMETRY_CONFIG_ACTION"))
	}
}

func configHelperCommand(t *testing.T, home, action string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestConfigHelperProcess$")
	cmd.Env = append(os.Environ(),
		"TELEMETRY_CONFIG_HELPER=1",
		"TELEMETRY_CONFIG_ACTION="+action,
		"HOME="+home,
		"USERPROFILE="+home,
	)
	return cmd
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func firstOutputLine(output string) string {
	line, _, _ := strings.Cut(output, "\n")
	return strings.TrimSpace(line)
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
