// Package update tells the MCP server whether a newer release of
// datadog-code-security-mcp is available.
//
// The server reads a small cache synchronously at start, so start never waits
// on the network, and refreshes it in the background at most once a day. A
// newer release found by one session is therefore announced from the next one.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/constants"
)

const (
	// LatestReleaseURL is the GitHub API endpoint for the latest stable release.
	LatestReleaseURL = "https://api.github.com/repos/datadog-labs/datadog-code-security-mcp/releases/latest"

	cacheDirName  = ".datadog-code-security-mcp"
	cacheFileName = "update-check.json"

	// checkInterval is how long a check, successful or not, stays fresh.
	checkInterval = 24 * time.Hour
	// requestTimeout bounds the background request.
	requestTimeout = 3 * time.Second
	// maxResponseBytes bounds how much of the response body is read.
	maxResponseBytes = 1 << 20
)

// cacheEntry is the on-disk state in ~/.datadog-code-security-mcp/update-check.json.
type cacheEntry struct {
	LatestVersion string    `json:"latest_version,omitempty"`
	CheckedAt     time.Time `json:"checked_at"`
}

// Checker compares the running version with the latest published release.
type Checker struct {
	// CurrentVersion is the running version, as injected at build time.
	CurrentVersion string
	// CachePath is the cache file. Empty disables caching and checking.
	CachePath string
	// URL is the latest-release endpoint.
	URL string
	// HTTPClient performs the request.
	HTTPClient *http.Client
	// Now returns the current time.
	Now func() time.Time
}

// NewChecker returns a Checker for the running version that caches under the
// user's home directory. A missing home directory leaves CachePath empty.
func NewChecker(currentVersion string) *Checker {
	c := &Checker{
		CurrentVersion: currentVersion,
		URL:            LatestReleaseURL,
		HTTPClient:     &http.Client{Timeout: requestTimeout},
		Now:            time.Now,
	}
	if home, err := os.UserHomeDir(); err == nil {
		c.CachePath = filepath.Join(home, cacheDirName, cacheFileName)
	}
	return c
}

// Disabled reports whether the check is turned off: by its own environment
// variable, by the telemetry opt-outs, or because the running build has no
// release version (for example a development build).
func (c *Checker) Disabled() bool {
	for _, name := range []string{
		constants.EnvUpdateCheckDisabled,
		constants.EnvDoNotTrack,
		constants.EnvTelemetryDisabled,
	} {
		if isTruthy(os.Getenv(name)) {
			return true
		}
	}
	_, ok := parseVersion(c.CurrentVersion)
	return !ok || c.CachePath == ""
}

// NewerVersion returns the cached latest release when it is newer than the
// running version. It never touches the network.
func (c *Checker) NewerVersion() (string, bool) {
	if c.Disabled() {
		return "", false
	}
	entry, err := c.readCache()
	if err != nil || entry.LatestVersion == "" {
		return "", false
	}
	if !isNewer(entry.LatestVersion, c.CurrentVersion) {
		return "", false
	}
	return entry.LatestVersion, true
}

// RefreshIfStale queries the latest release when the cache is missing or older
// than a day, and records the attempt. Failures are silent: a failed request
// keeps the previous latest version and still waits a day before retrying.
func (c *Checker) RefreshIfStale(ctx context.Context) {
	if c.Disabled() {
		return
	}
	entry, err := c.readCache()
	now := c.Now()
	if err == nil && now.Sub(entry.CheckedAt) < checkInterval && !entry.CheckedAt.After(now) {
		return
	}
	if latest, fetchErr := c.fetchLatest(ctx); fetchErr == nil {
		entry.LatestVersion = latest
	}
	entry.CheckedAt = now
	_ = c.writeCache(entry)
}

func (c *Checker) fetchLatest(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "datadog-code-security-mcp/"+c.CurrentVersion)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("latest release: HTTP %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&release); err != nil {
		return "", fmt.Errorf("decode latest release: %w", err)
	}
	if _, ok := parseVersion(release.TagName); !ok {
		return "", fmt.Errorf("latest release has no semantic version tag")
	}
	return strings.TrimPrefix(release.TagName, "v"), nil
}

func (c *Checker) readCache() (cacheEntry, error) {
	var entry cacheEntry
	data, err := os.ReadFile(c.CachePath)
	if err != nil {
		return entry, err
	}
	err = json.Unmarshal(data, &entry)
	return entry, err
}

// writeCache replaces the cache atomically so concurrent servers never read a
// partial file. Concurrent writers are last-writer-wins, which is harmless.
func (c *Checker) writeCache(entry cacheEntry) error {
	dir := filepath.Dir(c.CachePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+cacheFileName+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, c.CachePath)
}

var versionPattern = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

// parseVersion accepts a stable MAJOR.MINOR.PATCH version with an optional
// leading v. Prereleases, development builds and snapshots are rejected, so
// they never trigger a notice.
func parseVersion(v string) ([3]int, bool) {
	var parts [3]int
	m := versionPattern.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return parts, false
	}
	for i := range parts {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return parts, false
		}
		parts[i] = n
	}
	return parts, true
}

// isNewer reports whether candidate is a later stable version than current.
func isNewer(candidate, current string) bool {
	a, okA := parseVersion(candidate)
	b, okB := parseVersion(current)
	if !okA || !okB {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes":
		return true
	}
	return false
}
