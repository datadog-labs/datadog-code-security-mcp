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

// VulnerabilityDetail represents a vulnerability found in a library.
// It combines the per-library vulnerability reference with the deduplicated advisory definition.
type VulnerabilityDetail struct {
	// Advisory info (from the deduplicated vulnerability definition)
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

	// Risk info (from the per-library vulnerability reference)
	DatadogScore     float64
	Reachability     string
	ExploitAvailable *bool
	ExploitPoC       *bool

	// Fix info (from the per-library vulnerability reference)
	FixVersion        string
	HasRemediation    bool
	FixType           string
	ClosestFixVersion string
	LatestFixVersion  string
}

// LibraryInfo holds metadata about a scanned library and all vulnerabilities found in it.
type LibraryInfo struct {
	PURL          string
	Name          string
	Version       string
	Ecosystem     string
	LicenseID     string
	OpenSSFLevel  string
	Popularity    string
	LatestVersion string
	EolDate       *string
	Relation      string   // "direct" or "transitive"
	RootParent    *string  // PURL of the root dependency that pulled this in
	TraversalPath *string
	Risks         []string // risk flags, e.g. UNMAINTAINED, MALICIOUS_PACKAGE, EOL_NOW, …

	Vulnerabilities []VulnerabilityDetail
}

// ScanResult holds the result of a library vulnerability scan.
type ScanResult struct {
	Libraries          []LibraryInfo // all scanned libraries, including those with no vulnerabilities
	RawResponse        string        // raw JSON body as received from the API
	UnsupportedVersion int           // non-zero when the response version is newer than this client supports
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
