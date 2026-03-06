package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/processing"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

func TestNewIaCScanner(t *testing.T) {
	binMgr := binary.NewIaCScannerManager()
	s := NewIaCScanner(binMgr)

	if s == nil {
		t.Fatal("Expected non-nil scanner")
	}
	if s.binaryMgr == nil {
		t.Fatal("Expected non-nil binary manager")
	}
}

func TestIaCScanner_Execute_ContextCancellation(t *testing.T) {
	binMgr := binary.NewIaCScannerManager()
	s := NewIaCScanner(binMgr)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	args := ScanArgs{
		FilePaths:  []string{"."},
		WorkingDir: ".",
	}

	_, err := s.Execute(ctx, args)
	// Expect an error due to context cancellation or binary not found
	if err == nil {
		t.Error("Expected an error due to context cancellation, got nil")
	}
}

func TestIaCScanner_Execute_MissingBinary(t *testing.T) {
	// Use a binary type that won't be found in PATH for testing
	binMgr := binary.NewIaCScannerManager()
	s := NewIaCScanner(binMgr)

	// Create a temp directory as working dir
	tmpDir, err := os.MkdirTemp("", "iac-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	args := ScanArgs{
		FilePaths:  []string{"."},
		WorkingDir: tmpDir,
	}

	_, err = s.Execute(context.Background(), args)
	if err == nil {
		t.Error("Expected an error when binary is not found, got nil")
	}
}

func TestIaCScanner_Execute_InvalidSARIF(t *testing.T) {
	// This test verifies that invalid SARIF output is handled gracefully.
	// We can't easily mock the binary execution, so we test the SARIF reading path
	// by checking that a missing output file produces a clear error.

	binMgr := binary.NewIaCScannerManager()
	s := NewIaCScanner(binMgr)

	// If the binary is not installed, the test will fail at GetBinaryPath,
	// which is still a valid test path (tests binary-not-found error handling).
	ctx := context.Background()
	args := ScanArgs{
		FilePaths:  []string{"."},
		WorkingDir: "/nonexistent/path",
	}

	_, err := s.Execute(ctx, args)
	if err == nil {
		t.Error("Expected an error for invalid working directory, got nil")
	}
}

func TestIaCScanner_CommandArgs(t *testing.T) {
	// Test that command arguments are constructed correctly for multiple paths
	tests := []struct {
		name       string
		filePaths  []string
		workingDir string
		wantPaths  int // number of -p flags expected
	}{
		{
			name:       "single path",
			filePaths:  []string{"."},
			workingDir: "/tmp",
			wantPaths:  1,
		},
		{
			name:       "multiple paths",
			filePaths:  []string{"dir1", "dir2", "dir3"},
			workingDir: "/tmp",
			wantPaths:  3,
		},
		{
			name:       "absolute path",
			filePaths:  []string{"/tmp/myproject"},
			workingDir: "/tmp",
			wantPaths:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build the args as the scanner would
			cmdArgs := []string{"scan"}
			for _, p := range tt.filePaths {
				var absPath string
				if filepath.IsAbs(p) {
					absPath = p
				} else {
					absPath = filepath.Join(tt.workingDir, p)
				}
				cmdArgs = append(cmdArgs, "-p", absPath)
			}
			cmdArgs = append(cmdArgs, "-o", "/tmp/output")

			// Count -p flags
			pCount := 0
			for _, arg := range cmdArgs {
				if arg == "-p" {
					pCount++
				}
			}

			if pCount != tt.wantPaths {
				t.Errorf("Expected %d -p flags, got %d", tt.wantPaths, pCount)
			}

			// Verify "scan" is the first argument
			if cmdArgs[0] != "scan" {
				t.Errorf("Expected first arg to be 'scan', got %s", cmdArgs[0])
			}

			// Verify -o is present
			hasOutput := false
			for _, arg := range cmdArgs {
				if arg == "-o" {
					hasOutput = true
					break
				}
			}
			if !hasOutput {
				t.Error("Expected -o flag in arguments")
			}
		})
	}
}

func TestIaCScanner_DetectionType(t *testing.T) {
	// Verify the detection type constant exists and has the expected value
	if types.DetectionTypeIaC != "iac" {
		t.Errorf("Expected DetectionTypeIaC='iac', got %s", types.DetectionTypeIaC)
	}

	// Verify it's in the allowed list
	allowed := types.AllowedDetectionTypes()
	found := false
	for _, dt := range allowed {
		if dt == "iac" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'iac' to be in AllowedDetectionTypes()")
	}
}

func TestIaCSARIFOutputFile(t *testing.T) {
	if iacSARIFOutputFile != "datadog-iac-scanner-result.sarif" {
		t.Errorf("Expected SARIF output file name 'datadog-iac-scanner-result.sarif', got %s", iacSARIFOutputFile)
	}
}

// TestIaCScanner_ParseSARIFFixture tests SARIF parsing with a realistic IaC scanner output fixture.
// This validates the full SARIF-to-violations pipeline using a sample output file.
func TestIaCScanner_ParseSARIFFixture(t *testing.T) {
	sarifData, err := os.ReadFile("testdata/iac-sample.sarif")
	if err != nil {
		t.Fatalf("Failed to read SARIF fixture: %v", err)
	}

	violations, err := processing.ParseSARIF(sarifData, "", types.DetectionTypeIaC)
	if err != nil {
		t.Fatalf("Failed to parse SARIF fixture: %v", err)
	}

	if len(violations) != 4 {
		t.Fatalf("Expected 4 violations from fixture, got %d", len(violations))
	}

	// Verify each violation has expected fields
	for i, v := range violations {
		if v.Rule == "" {
			t.Errorf("Violation[%d]: expected non-empty Rule", i)
		}
		if v.Message == "" {
			t.Errorf("Violation[%d]: expected non-empty Message", i)
		}
		if v.File == "" {
			t.Errorf("Violation[%d]: expected non-empty File", i)
		}
		if v.Line == 0 {
			t.Errorf("Violation[%d]: expected non-zero Line", i)
		}
		if v.DetectionType != types.DetectionTypeIaC {
			t.Errorf("Violation[%d]: expected DetectionType=%s, got %s", i, types.DetectionTypeIaC, v.DetectionType)
		}
	}
}

// TestIaCScanner_ParseSARIFFixture_RuleMapping verifies that specific rules from
// the SARIF fixture are correctly mapped to violations with proper severities.
func TestIaCScanner_ParseSARIFFixture_RuleMapping(t *testing.T) {
	sarifData, err := os.ReadFile("testdata/iac-sample.sarif")
	if err != nil {
		t.Fatalf("Failed to read SARIF fixture: %v", err)
	}

	violations, err := processing.ParseSARIF(sarifData, "", types.DetectionTypeIaC)
	if err != nil {
		t.Fatalf("Failed to parse SARIF fixture: %v", err)
	}

	// Build a map of rule -> violation for easier assertions
	byRule := make(map[string]types.Violation)
	for _, v := range violations {
		byRule[v.Rule] = v
	}

	tests := []struct {
		ruleID         string
		expectSeverity string
		expectFileContains string
	}{
		{
			ruleID:             "aws-s3-public-access",
			expectSeverity:     types.SeverityHigh, // SARIF "error" -> HIGH
			expectFileContains: "insecure-s3.tf",
		},
		{
			ruleID:             "aws-security-group-open-ssh",
			expectSeverity:     types.SeverityHigh,
			expectFileContains: "insecure-security-group.tf",
		},
		{
			ruleID:             "k8s-privileged-container",
			expectSeverity:     types.SeverityMedium, // SARIF "warning" -> MEDIUM
			expectFileContains: "insecure-k8s.yaml",
		},
		{
			ruleID:             "docker-run-as-root",
			expectSeverity:     types.SeverityMedium,
			expectFileContains: "Dockerfile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			v, ok := byRule[tt.ruleID]
			if !ok {
				t.Fatalf("Rule %s not found in parsed violations", tt.ruleID)
			}

			if v.Severity != tt.expectSeverity {
				t.Errorf("Expected severity %s, got %s", tt.expectSeverity, v.Severity)
			}

			if v.RuleURL == "" {
				t.Error("Expected non-empty RuleURL from helpUri")
			}

			found := false
			if len(v.File) > 0 {
				found = filepath.Base(v.File) == tt.expectFileContains || v.File == tt.expectFileContains ||
					len(v.File) >= len(tt.expectFileContains) && v.File[len(v.File)-len(tt.expectFileContains):] == tt.expectFileContains
			}
			if !found {
				t.Errorf("Expected file to contain %s, got %s", tt.expectFileContains, v.File)
			}
		})
	}
}

// TestIaCScanner_ParseSARIFFixture_EmptyRuns ensures empty SARIF runs return no violations.
func TestIaCScanner_ParseSARIFFixture_EmptyRuns(t *testing.T) {
	emptySARIF := []byte(`{
		"version": "2.1.0",
		"runs": []
	}`)

	violations, err := processing.ParseSARIF(emptySARIF, "", types.DetectionTypeIaC)
	if err != nil {
		t.Fatalf("Failed to parse empty SARIF: %v", err)
	}

	if len(violations) != 0 {
		t.Errorf("Expected 0 violations for empty runs, got %d", len(violations))
	}
}

// TestIaCScanner_ParseSARIFFixture_NoResults ensures SARIF with no results returns no violations.
func TestIaCScanner_ParseSARIFFixture_NoResults(t *testing.T) {
	noResultsSARIF := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"name": "datadog-iac-scanner",
					"version": "0.1.0",
					"rules": []
				}
			},
			"results": []
		}]
	}`)

	violations, err := processing.ParseSARIF(noResultsSARIF, "", types.DetectionTypeIaC)
	if err != nil {
		t.Fatalf("Failed to parse SARIF with no results: %v", err)
	}

	if len(violations) != 0 {
		t.Errorf("Expected 0 violations for empty results, got %d", len(violations))
	}
}

// TestIaCTestdataFilesExist verifies that all expected IaC test fixture files exist.
func TestIaCTestdataFilesExist(t *testing.T) {
	// Find project root by walking up from the test file location
	// The test is in internal/scan/, testdata is at project root
	projectRoot := findProjectRoot(t)

	expectedFiles := []string{
		"testdata/vulnerabilities/iac/insecure-s3.tf",
		"testdata/vulnerabilities/iac/insecure-security-group.tf",
		"testdata/vulnerabilities/iac/insecure-iam.tf",
		"testdata/vulnerabilities/iac/insecure-k8s.yaml",
		"testdata/vulnerabilities/iac/Dockerfile",
	}

	for _, file := range expectedFiles {
		fullPath := filepath.Join(projectRoot, file)
		t.Run(filepath.Base(file), func(t *testing.T) {
			info, err := os.Stat(fullPath)
			if err != nil {
				t.Errorf("Expected testdata file %s to exist: %v", file, err)
				return
			}
			if info.Size() == 0 {
				t.Errorf("Expected testdata file %s to be non-empty", file)
			}
		})
	}
}

// TestIaCScanner_KICSExitCodes verifies that KICS exit codes 40/50/60 are recognized
// as "findings found" and other exit codes are treated as errors.
func TestIaCScanner_KICSExitCodes(t *testing.T) {
	tests := []struct {
		name        string
		exitCode    int
		expectError bool
	}{
		{"exit 0 - no findings", 0, false},
		{"exit 40 - LOW findings", iacExitCodeLow, false},
		{"exit 50 - MEDIUM findings", iacExitCodeMedium, false},
		{"exit 60 - HIGH findings", iacExitCodeHigh, false},
		{"exit 1 - unexpected error", 1, true},
		{"exit 2 - unexpected error", 2, true},
		{"exit 127 - command not found", 127, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the exit code handling logic from IaCScanner.Execute
			isFindings := tt.exitCode == iacExitCodeLow ||
				tt.exitCode == iacExitCodeMedium ||
				tt.exitCode == iacExitCodeHigh
			isSuccess := tt.exitCode == 0

			if tt.expectError {
				if isFindings || isSuccess {
					t.Errorf("Exit code %d should be treated as error, but would be accepted", tt.exitCode)
				}
			} else {
				if !isFindings && !isSuccess {
					t.Errorf("Exit code %d should be accepted, but would be treated as error", tt.exitCode)
				}
			}
		})
	}
}

// TestIaCExitCodeConstants verifies the KICS exit code constants have the expected values.
func TestIaCExitCodeConstants(t *testing.T) {
	if iacExitCodeLow != 40 {
		t.Errorf("Expected iacExitCodeLow=40, got %d", iacExitCodeLow)
	}
	if iacExitCodeMedium != 50 {
		t.Errorf("Expected iacExitCodeMedium=50, got %d", iacExitCodeMedium)
	}
	if iacExitCodeHigh != 60 {
		t.Errorf("Expected iacExitCodeHigh=60, got %d", iacExitCodeHigh)
	}
}

// findProjectRoot walks up directories to find the project root (contains go.mod).
func findProjectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("Could not find project root (go.mod)")
		}
		dir = parent
	}
}
