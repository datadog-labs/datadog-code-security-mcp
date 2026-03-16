package libraryscan

import (
	"fmt"

	packageurl "github.com/package-url/packageurl-go"
)

// Library represents a single library to scan, identified by its PURL.
type Library struct {
	Purl             string   `json:"purl"`
	IsDev            bool     `json:"is_dev"`
	IsDirect         bool     `json:"is_direct"`
	PackageManager   string   `json:"package_manager"`
	TargetFrameworks []string `json:"target_frameworks"`
	Exclusions       []string `json:"exclusions"`
}

// ScanRequest holds the parameters for a library vulnerability scan.
type ScanRequest struct {
	Libraries    []Library
	ResourceName string
	CommitHash   string
}

// VulnerabilityFinding represents a single vulnerability found in a library.
type VulnerabilityFinding struct {
	GHSAID         string
	CVEAliases     []string
	Summary        string
	Details        string
	LibraryPURL    string
	LibraryName    string
	LibraryVersion string
	Severity       string // Title-case: "Critical", "High", "Medium", "Low" (from Datadog SCORE_ENRICHER)
	// Note: the formatter uses strings.ToUpper when passing to severityToEmoji
	CVSSScore         float64
	Remediation       string
	ClosestFixVersion string
	LatestFixVersion  string
	ExploitAvailable  bool
}

// ScanResult holds the result of a library vulnerability scan.
type ScanResult struct {
	Findings    []VulnerabilityFinding
	RawResponse string // raw JSON body as received from the API
}

// ValidatePURL returns an error if purl is not a valid Package URL per the PURL spec.
func ValidatePURL(purl string) error {
	if purl == "" {
		return fmt.Errorf("purl must not be empty")
	}
	if _, err := packageurl.FromString(purl); err != nil {
		return fmt.Errorf("invalid purl %q: %w", purl, err)
	}
	return nil
}
