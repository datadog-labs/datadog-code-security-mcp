package processing

import (
	"encoding/json"
	"fmt"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/types"
)

// SCAOutput represents the JSON output structure from datadog-security-cli
type SCAOutput struct {
	Resource struct {
		Type string `json:"type"`
	} `json:"resource"`
	Vulnerabilities []struct {
		ID       string   `json:"id"`       // GO-2025-4009, CVE-2021-44228
		Severity string   `json:"severity"` // critical, high, medium, low
		Affects  []string `json:"affects"`  // Array of package URLs
	} `json:"vulnerabilities"`
}

// ParseSCAJSON parses SCA vulnerability scan output
func ParseSCAJSON(data []byte) ([]types.Vulnerability, error) {
	if len(data) == 0 {
		return []types.Vulnerability{}, nil
	}

	// Clean output - skip any lines before the JSON starts
	// datadog-security-cli outputs "SBOM saved to..." before the JSON
	jsonStart := -1
	for i := 0; i < len(data); i++ {
		if data[i] == '{' {
			jsonStart = i
			break
		}
	}

	if jsonStart == -1 {
		return nil, fmt.Errorf("no JSON found in output")
	}

	cleanData := data[jsonStart:]

	var output SCAOutput
	if err := json.Unmarshal(cleanData, &output); err != nil {
		return nil, fmt.Errorf("failed to parse SCA output as JSON: %w", err)
	}

	vulnerabilities := make([]types.Vulnerability, 0)
	for _, vuln := range output.Vulnerabilities {
		// Each vulnerability can affect multiple packages
		for _, purl := range vuln.Affects {
			// Parse purl to extract component and version
			// Format: pkg:golang/stdlib@v1.25.1 or pkg:maven/group/artifact@version
			component, version := parsePurl(purl)

			v := types.Vulnerability{
				CVE:           vuln.ID,
				Severity:      normalizeSeverity(vuln.Severity),
				Component:     component,
				Version:       version,
				Description:   fmt.Sprintf("Vulnerability %s affects %s", vuln.ID, component),
				PackageURL:    purl,
				DetectionType: types.DetectionTypeSCA,
			}
			vulnerabilities = append(vulnerabilities, v)
		}
	}

	return vulnerabilities, nil
}

// parsePurl extracts component name and version from a package URL
// Examples:
//   - pkg:golang/stdlib@v1.25.1 -> ("stdlib", "v1.25.1")
//   - pkg:maven/com.group/artifact@1.0.0 -> ("com.group/artifact", "1.0.0")
func parsePurl(purl string) (component, version string) {
	// Remove "pkg:" prefix
	if len(purl) > 4 && purl[:4] == "pkg:" {
		purl = purl[4:]
	}

	// Find @ separator for version
	atIndex := -1
	for i := len(purl) - 1; i >= 0; i-- {
		if purl[i] == '@' {
			atIndex = i
			break
		}
	}

	if atIndex == -1 {
		// No version found
		return purl, ""
	}

	version = purl[atIndex+1:]
	remainder := purl[:atIndex]

	// Remove ecosystem prefix (e.g., "golang/", "maven/")
	slashIndex := -1
	for i := 0; i < len(remainder); i++ {
		if remainder[i] == '/' {
			slashIndex = i
			break
		}
	}

	if slashIndex != -1 {
		component = remainder[slashIndex+1:]
	} else {
		component = remainder
	}

	return component, version
}

// normalizeSeverity converts severity to uppercase
func normalizeSeverity(severity string) string {
	switch severity {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	default:
		return severity
	}
}
