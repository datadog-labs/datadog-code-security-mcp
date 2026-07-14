package types

// Violation contains essential information about a security violation from a scanner
// Lightweight version of SARIF parsing done in dd-go for ci-sarif-processor
type Violation struct {
	Severity      string        `json:"severity" jsonschema:"description=Severity level: CRITICAL/HIGH/MEDIUM/LOW"`
	Rule          string        `json:"rule" jsonschema:"description=Rule ID that was violated"`
	RuleURL       string        `json:"rule_url,omitempty" jsonschema:"description=URL to rule documentation"`
	File          string        `json:"file" jsonschema:"description=File path relative to working directory"`
	Line          int           `json:"line" jsonschema:"description=Line number where violation occurs"`
	Message       string        `json:"message" jsonschema:"description=Brief description of the violation"`
	DetectionType DetectionType `json:"detection_type" jsonschema:"description=Type of detection (sast, secrets)"`
}

// Library represents a software component found in an SBOM scan
type Library struct {
	Name       string `json:"name" jsonschema:"description=Component name"`
	Version    string `json:"version" jsonschema:"description=Component version"`
	File       string `json:"file,omitempty" jsonschema:"description=File where the component was detected"`
	PackageURL string `json:"package_url,omitempty" jsonschema:"description=Package URL (purl) identifier"`
	Type       string `json:"type,omitempty" jsonschema:"description=Component type (e.g., library, framework)"`
	Language   string `json:"language,omitempty" jsonschema:"description=Programming language or package manager"`
}

// Vulnerability represents a security vulnerability found in a software component
type Vulnerability struct {
	CVE           string        `json:"cve" jsonschema:"description=CVE identifier (e.g., CVE-2021-44228)"`
	Severity      string        `json:"severity" jsonschema:"description=Severity level: CRITICAL/HIGH/MEDIUM/LOW"`
	Component     string        `json:"component" jsonschema:"description=Affected component name"`
	Version       string        `json:"version" jsonschema:"description=Affected component version"`
	FixedVersion  string        `json:"fixed_version,omitempty" jsonschema:"description=Version that fixes the vulnerability"`
	Description   string        `json:"description" jsonschema:"description=Vulnerability description"`
	CVSS          float64       `json:"cvss,omitempty" jsonschema:"description=CVSS score (0-10)"`
	References    []string      `json:"references,omitempty" jsonschema:"description=URLs to vulnerability details"`
	PackageURL    string        `json:"package_url,omitempty" jsonschema:"description=Package URL (purl) of affected component"`
	DetectionType DetectionType `json:"detection_type" jsonschema:"description=Type of detection (sca)"`
}

// ScanArgs contains the input parameters for a security scan
type ScanArgs struct {
	FilePaths  []string `json:"file_paths" jsonschema:"description=Paths to files or directories to scan. Relative paths are resolved against working_dir"`
	WorkingDir string   `json:"working_dir,omitempty" jsonschema:"description=Working directory for the scan. Default: current directory"`
	ScanTypes  []string `json:"scan_types,omitempty" jsonschema:"description=Types of scans to run: sast, secrets. Default: all scan types"`
}

// ScanSummary provides aggregated statistics about scan results
type ScanSummary struct {
	Total           int            `json:"total" jsonschema:"description=Total number of violations found"`
	Critical        int            `json:"critical" jsonschema:"description=Number of critical severity violations"`
	High            int            `json:"high" jsonschema:"description=Number of high severity violations"`
	Medium          int            `json:"medium" jsonschema:"description=Number of medium severity violations"`
	Low             int            `json:"low" jsonschema:"description=Number of low severity violations"`
	BySeverity      map[string]int `json:"by_severity,omitempty" jsonschema:"description=Violations grouped by severity"`
	ByDetectionType map[string]int `json:"by_detection_type,omitempty" jsonschema:"description=Violations grouped by detection type"`
}

// ScanResult contains the complete output of a security scan
type ScanResult struct {
	Summary       ScanSummary                   `json:"summary" jsonschema:"description=Summary statistics of all detections"`
	Results       map[DetectionType][]Violation `json:"results" jsonschema:"description=Results from each detection type"`
	Errors        []ScanError                   `json:"errors,omitempty" jsonschema:"description=Any errors encountered during scanning"`
	PartialResult bool                          `json:"partial_result,omitempty" jsonschema:"description=True if some scans failed but others succeeded"`
}

// ScanError represents an error that occurred during scanning
type ScanError struct {
	DetectionType string `json:"detection_type" jsonschema:"description=The detection type that encountered an error"`
	Error         string `json:"error" jsonschema:"description=Error message"`
	Hint          string `json:"hint,omitempty" jsonschema:"description=Suggestion for how to resolve the error"`
}

// SBOMArgs represents arguments for SBOM generation
type SBOMArgs struct {
	Path       string `json:"path,omitempty" jsonschema:"description=Path to repository or directory to analyze. Default: current directory"`
	WorkingDir string `json:"working_dir,omitempty" jsonschema:"description=Working directory for the scan. Default: current directory"`
}

// SBOMSummary provides statistics about the SBOM scan
type SBOMSummary struct {
	TotalComponents int            `json:"total_components" jsonschema:"description=Total number of software components found"`
	ByLanguage      map[string]int `json:"by_language,omitempty" jsonschema:"description=Components grouped by language/package manager"`
	ByType          map[string]int `json:"by_type,omitempty" jsonschema:"description=Components grouped by type (library, framework, etc.)"`
}

// SBOMResult represents the result of an SBOM scan
type SBOMResult struct {
	Summary    SBOMSummary `json:"summary" jsonschema:"description=Summary statistics of SBOM scan"`
	Components []Library   `json:"components" jsonschema:"description=List of software components found"`
	Error      *ScanError  `json:"error,omitempty" jsonschema:"description=Error encountered during SBOM generation"`
}

// SCAArgs represents arguments for Software Composition Analysis (vulnerability scanning)
type SCAArgs struct {
	SBOMFile   string `json:"sbom_file" jsonschema:"description=Path to SBOM file (CycloneDX JSON format). Can be absolute or relative to working_dir"`
	WorkingDir string `json:"working_dir,omitempty" jsonschema:"description=Working directory for the scan. Default: current directory"`
	EntityType string `json:"entity_type,omitempty" jsonschema:"description=Entity type for SBOM scan. Options: UNSPECIFIED, CONTAINER_IMAGE_LAYERS, CONTAINER_FILE_SYSTEM, HOST_FILE_SYSTEM, CI_PIPELINE, HOST_IMAGE. Default: CI_PIPELINE"`
	EntityID   string `json:"entity_id,omitempty" jsonschema:"description=Entity ID for SBOM scan. If not provided, it will be computed from artifact reference"`
}

// SCASummary provides statistics about vulnerabilities found
type SCASummary struct {
	TotalVulnerabilities int            `json:"total_vulnerabilities" jsonschema:"description=Total number of vulnerabilities found"`
	Critical             int            `json:"critical" jsonschema:"description=Number of critical severity vulnerabilities"`
	High                 int            `json:"high" jsonschema:"description=Number of high severity vulnerabilities"`
	Medium               int            `json:"medium" jsonschema:"description=Number of medium severity vulnerabilities"`
	Low                  int            `json:"low" jsonschema:"description=Number of low severity vulnerabilities"`
	BySeverity           map[string]int `json:"by_severity,omitempty" jsonschema:"description=Vulnerabilities grouped by severity"`
	AffectedComponents   int            `json:"affected_components" jsonschema:"description=Number of components with vulnerabilities"`
}

// SCAResult represents the result of a vulnerability scan
type SCAResult struct {
	Summary         SCASummary      `json:"summary" jsonschema:"description=Summary statistics of vulnerability scan"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities" jsonschema:"description=List of vulnerabilities found"`
	Error           *ScanError      `json:"error,omitempty" jsonschema:"description=Error encountered during vulnerability scan"`
}
