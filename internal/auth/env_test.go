package auth

import (
	"context"
	"os"
	"testing"
)

// TestLoadAndApplyToEnv_None verifies that with nothing configured,
// LoadAndApplyToEnv is a no-op that reports MethodNone.
func TestLoadAndApplyToEnv_None(t *testing.T) {
	os.Clearenv()

	method, err := LoadAndApplyToEnv(context.Background())
	if err != nil {
		t.Fatalf("LoadAndApplyToEnv() error = %v, want nil", err)
	}
	if method != MethodNone {
		t.Errorf("method = %q, want %q", method, MethodNone)
	}
}

// TestLoadAndApplyToEnv_EnvVar verifies that when the user has already set
// DD_API_KEY/DD_APP_KEY, LoadAndApplyToEnv reports MethodEnvVar.
func TestLoadAndApplyToEnv_EnvVar(t *testing.T) {
	os.Clearenv()
	t.Setenv("DD_API_KEY", "test-api-key")
	t.Setenv("DD_APP_KEY", "test-app-key")

	method, err := LoadAndApplyToEnv(context.Background())
	if err != nil {
		t.Fatalf("LoadAndApplyToEnv() error = %v, want nil", err)
	}
	if method != MethodEnvVar {
		t.Errorf("method = %q, want %q", method, MethodEnvVar)
	}
}

// TestLoadAndApplyToEnv_DDAuthMethodSurvivesApplyFailure is the regression
// guard for the CLI's "detect before mutate" pattern: even when resolving
// credentials fails (e.g. the dd-auth binary isn't installed, as in this test
// environment), the method must already reflect the original config — read
// before any credential resolution was attempted — so a caller that discards
// the error (as loadAuthToEnv does) still gets an accurate auth_method rather
// than an empty string.
func TestLoadAndApplyToEnv_DDAuthMethodSurvivesApplyFailure(t *testing.T) {
	os.Clearenv()
	t.Setenv("DD_AUTH_DOMAIN", "app.datadoghq.com")
	t.Setenv("PATH", "") // ensure the dd-auth binary cannot be found

	method, err := LoadAndApplyToEnv(context.Background())
	if err == nil {
		t.Fatal("expected an error since the dd-auth binary is not on PATH")
	}
	if method != MethodAuthProvider {
		t.Errorf("method = %q, want %q even though ApplyToEnv failed", method, MethodAuthProvider)
	}
}
