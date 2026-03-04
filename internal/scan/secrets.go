package scan

import (
	"context"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/binary"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

type SecretsScanner struct {
	base *BaseStaticAnalyzerScanner
}

func NewSecretsScanner(binMgr *binary.BinaryManager) *SecretsScanner {
	return &SecretsScanner{
		base: &BaseStaticAnalyzerScanner{
			binaryMgr: binMgr,
			config: StaticAnalyzerConfig{
				ScanType:         "secrets",
				TempDirPrefix:    "secrets-scan-",
				EnableSAST:       false,
				EnableSecrets:    true,
				DefaultDetection: types.DetectionTypeSecrets,
			},
		},
	}
}

// Execute runs Secrets scan
func (s *SecretsScanner) Execute(ctx context.Context, args ScanArgs) ([]types.Violation, error) {
	// In the future, we can add secrets-specific filtering here
	return s.base.Execute(ctx, args)
}
