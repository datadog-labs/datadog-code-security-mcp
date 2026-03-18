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

// VulnerabilityFinding represents a single vulnerability found in a library,
// combining data from the library result, vulnerability reference, and vulnerability definition.
type VulnerabilityFinding struct {
	// Advisory/vulnerability info (from vulnerability definition)
	GHSAID         string
	CVE            string
	Summary        string
	Severity       string // Title-case: "Critical", "High", "Medium", "Low"
	CVSSScore      float64
	CVSSVector     string
	CWEs           []string
	EPSSScore      *float64
	EPSSPercentile *float64
	ExploitSources []string
	ExploitURLs    []string
	CISAAdded      *string

	// Library info
	LibraryPURL    string
	LibraryName    string
	LibraryVersion string
	Ecosystem      string
	LicenseID      string
	LatestVersion  string
	EolDate        *string
	Relation       string  // "direct" or "transitive"
	RootParent     *string // PURL of the root dependency that pulled this in

	// Risk info from vulnerability reference
	DatadogScore     float64
	Reachability     string
	ExploitAvailable *bool
	ExploitPoC       *bool

	// Fix info from vulnerability reference
	FixVersion        string
	HasRemediation    bool
	FixType           string
	ClosestFixVersion string
	LatestFixVersion  string
}

// ScanResult holds the result of a library vulnerability scan.
type ScanResult struct {
	Findings           []VulnerabilityFinding
	RawResponse        string // raw JSON body as received from the API
	UnsupportedVersion int    // non-zero when the response version is newer than this client supports
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
