// Package scan provides orchestration for security scanning operations.
//
// Type definitions are centralized in internal/types and re-exported here
// to maintain clean API boundaries. The scan package serves as the public
// API for security scanning, while internal/types contains shared type definitions.
//
// See: internal/types/types.go, internal/types/detection.go, internal/types/severity.go
package scan

import "github.com/datadog-labs/datadog-code-security-mcp/internal/types"

// Re-export types as part of the scan package's public API
type (
	ScanArgs         = types.ScanArgs
	ScanSummary      = types.ScanSummary
	ScanResult       = types.ScanResult
	ScanError        = types.ScanError
	GenerateSBOMArgs = types.SBOMArgs
	SBOMSummary      = types.SBOMSummary
	SBOMResult       = types.SBOMResult
	SCAArgs          = types.SCAArgs
	SCASummary       = types.SCASummary
	SCAResult        = types.SCAResult
)

// Re-export constants as part of the scan package's public API
const (
	SupportedPackageManagers = types.SupportedPackageManagers
	ManualSBOMSuggestion     = types.ManualSBOMSuggestion
)
