package telemetry

import "testing"

func setTestHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

func withTempHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	setTestHome(t, dir)
	return dir
}
