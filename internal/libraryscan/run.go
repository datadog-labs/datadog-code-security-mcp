package libraryscan

import "context"

const defaultSite = "datadoghq.com"

// Run is the shared library-scan orchestration used by both the CLI and MCP
// paths. It detects the git context for workingDir, constructs a client for the
// given credentials, submits the scan, and returns the result along with the
// total vulnerability count across all scanned libraries.
//
// Callers are responsible for parsing and validating their libraries (and PURLs)
// and for supplying credentials. site and workingDir may be empty; sensible
// defaults ("datadoghq.com" and ".") are applied here.
func Run(ctx context.Context, apiKey, appKey, site, workingDir string, libs []Library) (*ScanResult, int, error) {
	if site == "" {
		site = defaultSite
	}
	if workingDir == "" {
		workingDir = "."
	}

	repoName, commitHash := DetectGitContext(ctx, workingDir)

	client := NewClient(apiKey, appKey, site)
	result, err := client.Scan(ctx, ScanRequest{
		Libraries:    libs,
		ResourceName: repoName,
		CommitHash:   commitHash,
	})
	if err != nil {
		return nil, 0, err
	}

	totalVulns := 0
	for _, lib := range result.Libraries {
		totalVulns += len(lib.Vulnerabilities)
	}
	return result, totalVulns, nil
}
