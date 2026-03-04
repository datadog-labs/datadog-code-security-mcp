package scan

import (
	"context"
	"testing"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

func TestNewSecretsScanner_DefaultConfig(t *testing.T) {
	binMgr := binary.NewBinaryManager()
	s := NewSecretsScanner(binMgr)

	if s.base.config.ScanType != "secrets" {
		t.Errorf("Expected ScanType=secrets, got %s", s.base.config.ScanType)
	}
	if !s.base.config.EnableSecrets {
		t.Error("Expected EnableSecrets=true")
	}
	if s.base.config.EnableSAST {
		t.Error("Expected EnableSAST=false")
	}
	if s.base.config.DefaultDetection != types.DetectionTypeSecrets {
		t.Errorf("Expected DefaultDetection=%s, got %s", types.DetectionTypeSecrets, s.base.config.DefaultDetection)
	}
}

func TestSecretsScanner_Execute_ContextCancellation(t *testing.T) {
	binMgr := binary.NewBinaryManager()
	s := NewSecretsScanner(binMgr)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	args := ScanArgs{
		FilePaths:  []string{"."},
		WorkingDir: ".",
	}

	_, err := s.Execute(ctx, args)
	if err == nil {
		t.Error("Expected an error due to context cancellation, got nil")
	}
}

func TestSecretsScanner_Execute_InvalidWorkingDir(t *testing.T) {
	binMgr := binary.NewBinaryManager()
	s := NewSecretsScanner(binMgr)

	ctx := context.Background()
	args := ScanArgs{
		FilePaths:  []string{"."},
		WorkingDir: "/nonexistent/directory/that/does/not/exist",
	}

	_, err := s.Execute(ctx, args)
	if err == nil {
		t.Error("Expected an error, got nil")
	}
}
