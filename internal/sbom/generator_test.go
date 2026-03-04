package sbom

import (
	"context"
	"strings"
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

func TestValidateArgs_EmptyPath(t *testing.T) {
	args := types.SBOMArgs{
		WorkingDir: ".",
		Path:       "",
	}

	err := validateArgs(&args)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Should default to "."
	if args.Path != "." {
		t.Errorf("Expected path to default to '.', got: %s", args.Path)
	}
}

func TestValidateArgs_InvalidWorkingDir(t *testing.T) {
	args := types.SBOMArgs{
		WorkingDir: "/nonexistent/directory/that/does/not/exist",
		Path:       ".",
	}

	err := validateArgs(&args)
	if err == nil {
		t.Error("Expected error for invalid working directory, got nil")
	}
}

func TestValidateArgs_InvalidPath(t *testing.T) {
	args := types.SBOMArgs{
		WorkingDir: ".",
		Path:       "/nonexistent/path/to/nowhere",
	}

	err := validateArgs(&args)
	if err == nil {
		t.Error("Expected error for invalid path, got nil")
	}
}

func TestBuildSummary_Empty(t *testing.T) {
	libraries := []types.Library{}
	summary := buildSummary(libraries)

	if summary.TotalComponents != 0 {
		t.Errorf("Expected TotalComponents=0, got %d", summary.TotalComponents)
	}

	if len(summary.ByLanguage) != 0 {
		t.Errorf("Expected empty ByLanguage map, got %d entries", len(summary.ByLanguage))
	}

	if len(summary.ByType) != 0 {
		t.Errorf("Expected empty ByType map, got %d entries", len(summary.ByType))
	}
}

func TestBuildSummary_MultipleComponents(t *testing.T) {
	libraries := []types.Library{
		{Name: "lib1", Version: "1.0", Language: "golang", Type: "library"},
		{Name: "lib2", Version: "2.0", Language: "golang", Type: "library"},
		{Name: "lib3", Version: "3.0", Language: "python", Type: "framework"},
		{Name: "lib4", Version: "4.0", Language: "python", Type: "library"},
	}

	summary := buildSummary(libraries)

	if summary.TotalComponents != 4 {
		t.Errorf("Expected TotalComponents=4, got %d", summary.TotalComponents)
	}

	if summary.ByLanguage["golang"] != 2 {
		t.Errorf("Expected 2 golang components, got %d", summary.ByLanguage["golang"])
	}

	if summary.ByLanguage["python"] != 2 {
		t.Errorf("Expected 2 python components, got %d", summary.ByLanguage["python"])
	}

	if summary.ByType["library"] != 3 {
		t.Errorf("Expected 3 library components, got %d", summary.ByType["library"])
	}

	if summary.ByType["framework"] != 1 {
		t.Errorf("Expected 1 framework component, got %d", summary.ByType["framework"])
	}
}

func TestRetryHintFromError_BinaryNotFound(t *testing.T) {
	err := &fakeError{msg: "binary not found in PATH"}
	hint := retryHintFromError(err)

	if hint == "" {
		t.Error("Expected a hint for 'not found in PATH' error")
	}

	if hint != "Install datadog-sbom-generator using the instructions above" {
		t.Errorf("Unexpected hint: %s", hint)
	}
}

func TestRetryHintFromError_PermissionDenied(t *testing.T) {
	err := &fakeError{msg: "permission denied accessing file"}
	hint := retryHintFromError(err)

	if hint == "" {
		t.Error("Expected a hint for 'permission denied' error")
	}

	if hint != "Check file permissions and ensure you have access to the scan path" {
		t.Errorf("Unexpected hint: %s", hint)
	}
}

func TestRetryHintFromError_OtherError(t *testing.T) {
	err := &fakeError{msg: "some other error"}
	hint := retryHintFromError(err)

	if hint != "" {
		t.Errorf("Expected empty hint for generic error, got: %s", hint)
	}
}

func TestCreateContext_WithDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultSBOMTimeout)
	defer cancel()

	newCtx, newCancel := createContext(ctx)

	// Should return the same context when it already has a deadline
	if newCancel != nil {
		t.Error("Expected nil cancel func when context already has deadline")
	}

	// Verify context still has deadline
	if _, ok := newCtx.Deadline(); !ok {
		t.Error("Expected context to have deadline")
	}
}

func TestCreateContext_WithoutDeadline(t *testing.T) {
	ctx := context.Background()

	newCtx, newCancel := createContext(ctx)
	if newCancel != nil {
		defer newCancel()
	}

	if newCancel == nil {
		t.Error("Expected non-nil cancel func for new timeout context")
	}

	// Verify new context has deadline
	if _, ok := newCtx.Deadline(); !ok {
		t.Error("Expected new context to have deadline")
	}
}

func TestGetManualSBOMSuggestion(t *testing.T) {
	suggestion := getManualSBOMSuggestion()

	if suggestion == "" {
		t.Error("Expected non-empty manual SBOM suggestion")
	}

	// Should mention supported package managers
	if !containsAny(suggestion, []string{"NuGet", "Go", "Python", "NPM"}) {
		t.Error("Expected suggestion to mention supported package managers")
	}
}

// Helper types and functions

type fakeError struct {
	msg string
}

func (e *fakeError) Error() string {
	return e.msg
}

func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}
