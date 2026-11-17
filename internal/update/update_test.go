package update

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/constants"
)

var fixedNow = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

// clearOptOuts unsets every opt-out variable for the duration of the test, so
// the developer's or CI's environment cannot change the outcome.
func clearOptOuts(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		constants.EnvUpdateCheckDisabled,
		constants.EnvDoNotTrack,
		constants.EnvTelemetryDisabled,
	} {
		t.Setenv(name, "")
	}
}

// newTestChecker returns a Checker on a temp cache and a fake release server
// that answers with tag and counts requests.
func newTestChecker(t *testing.T, current, tag string, status int) (*Checker, *atomic.Int32) {
	t.Helper()
	clearOptOuts(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if got := r.Header.Get("User-Agent"); got != "datadog-code-security-mcp/"+current {
			t.Errorf("User-Agent = %q", got)
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"tag_name": tag})
	}))
	t.Cleanup(srv.Close)
	return &Checker{
		CurrentVersion: current,
		CachePath:      filepath.Join(t.TempDir(), "sub", cacheFileName),
		URL:            srv.URL,
		HTTPClient:     srv.Client(),
		Now:            func() time.Time { return fixedNow },
	}, &hits
}

func writeEntry(t *testing.T, c *Checker, entry cacheEntry) {
	t.Helper()
	if err := c.writeCache(entry); err != nil {
		t.Fatalf("write cache: %v", err)
	}
}

func TestRefreshThenNewerVersion(t *testing.T) {
	c, hits := newTestChecker(t, "0.6.0", "v0.7.0", http.StatusOK)

	if v, ok := c.NewerVersion(); ok {
		t.Fatalf("NewerVersion before any check = %q, want none", v)
	}
	c.RefreshIfStale(context.Background())
	if hits.Load() != 1 {
		t.Fatalf("requests = %d, want 1", hits.Load())
	}
	v, ok := c.NewerVersion()
	if !ok || v != "0.7.0" {
		t.Fatalf("NewerVersion = %q, %v; want 0.7.0, true", v, ok)
	}
}

func TestNoNoticeWhenCurrentOrAhead(t *testing.T) {
	for _, tag := range []string{"v0.6.0", "0.5.9", "v0.6.0-rc.1"} {
		t.Run(tag, func(t *testing.T) {
			c, _ := newTestChecker(t, "0.6.0", tag, http.StatusOK)
			c.RefreshIfStale(context.Background())
			if v, ok := c.NewerVersion(); ok {
				t.Errorf("NewerVersion = %q, want none", v)
			}
		})
	}
}

func TestRefreshSkipsFreshCache(t *testing.T) {
	c, hits := newTestChecker(t, "0.6.0", "v0.7.0", http.StatusOK)
	writeEntry(t, c, cacheEntry{LatestVersion: "0.6.0", CheckedAt: fixedNow.Add(-23 * time.Hour)})

	c.RefreshIfStale(context.Background())
	if hits.Load() != 0 {
		t.Fatalf("requests = %d, want 0 for a fresh cache", hits.Load())
	}
}

func TestRefreshQueriesStaleOrFutureCache(t *testing.T) {
	for name, checkedAt := range map[string]time.Time{
		"stale":  fixedNow.Add(-25 * time.Hour),
		"future": fixedNow.Add(48 * time.Hour),
	} {
		t.Run(name, func(t *testing.T) {
			c, hits := newTestChecker(t, "0.6.0", "v0.7.0", http.StatusOK)
			writeEntry(t, c, cacheEntry{LatestVersion: "0.6.0", CheckedAt: checkedAt})

			c.RefreshIfStale(context.Background())
			if hits.Load() != 1 {
				t.Fatalf("requests = %d, want 1", hits.Load())
			}
			if v, ok := c.NewerVersion(); !ok || v != "0.7.0" {
				t.Errorf("NewerVersion = %q, %v; want 0.7.0, true", v, ok)
			}
		})
	}
}

func TestFailedRefreshKeepsPreviousVersionAndWaits(t *testing.T) {
	c, hits := newTestChecker(t, "0.6.0", "", http.StatusInternalServerError)
	writeEntry(t, c, cacheEntry{LatestVersion: "0.7.0", CheckedAt: fixedNow.Add(-25 * time.Hour)})

	c.RefreshIfStale(context.Background())
	c.RefreshIfStale(context.Background())
	if hits.Load() != 1 {
		t.Fatalf("requests = %d, want 1: a failed attempt must also wait a day", hits.Load())
	}
	if v, ok := c.NewerVersion(); !ok || v != "0.7.0" {
		t.Errorf("NewerVersion = %q, %v; want the previous 0.7.0", v, ok)
	}
}

func TestOfflineRefreshIsSilent(t *testing.T) {
	c, _ := newTestChecker(t, "0.6.0", "v0.7.0", http.StatusOK)
	c.URL = "http://127.0.0.1:1/unreachable"

	c.RefreshIfStale(context.Background())
	if v, ok := c.NewerVersion(); ok {
		t.Errorf("NewerVersion = %q, want none when offline", v)
	}
	if _, err := os.Stat(c.CachePath); err != nil {
		t.Errorf("offline attempt was not recorded: %v", err)
	}
}

func TestDisabled(t *testing.T) {
	for _, name := range []string{
		constants.EnvUpdateCheckDisabled,
		constants.EnvDoNotTrack,
		constants.EnvTelemetryDisabled,
	} {
		t.Run(name, func(t *testing.T) {
			c, hits := newTestChecker(t, "0.6.0", "v0.7.0", http.StatusOK)
			writeEntry(t, c, cacheEntry{LatestVersion: "0.7.0", CheckedAt: fixedNow.Add(-25 * time.Hour)})
			t.Setenv(name, "1")

			c.RefreshIfStale(context.Background())
			if hits.Load() != 0 {
				t.Errorf("requests = %d, want 0 with %s=1", hits.Load(), name)
			}
			if v, ok := c.NewerVersion(); ok {
				t.Errorf("NewerVersion = %q, want none with %s=1", v, name)
			}
		})
	}
}

func TestNonReleaseBuildsNeverCheck(t *testing.T) {
	for _, current := range []string{"dev", "", "0.6.0-SNAPSHOT-abc123", "0.6.0-rc.1"} {
		t.Run(current, func(t *testing.T) {
			c, hits := newTestChecker(t, current, "v0.7.0", http.StatusOK)
			c.RefreshIfStale(context.Background())
			if hits.Load() != 0 {
				t.Errorf("requests = %d, want 0 for version %q", hits.Load(), current)
			}
		})
	}
}

func TestEmptyCachePathDisables(t *testing.T) {
	c, hits := newTestChecker(t, "0.6.0", "v0.7.0", http.StatusOK)
	c.CachePath = ""
	c.RefreshIfStale(context.Background())
	if hits.Load() != 0 {
		t.Errorf("requests = %d, want 0 without a cache path", hits.Load())
	}
}

func TestIsNewer(t *testing.T) {
	tests := []struct {
		candidate, current string
		want               bool
	}{
		{"0.7.0", "0.6.0", true},
		{"v1.0.0", "0.9.9", true},
		{"0.6.1", "v0.6.0", true},
		{"0.10.0", "0.9.0", true},
		{"0.6.0", "0.6.0", false},
		{"0.5.0", "0.6.0", false},
		{"0.7.0-rc.1", "0.6.0", false},
		{"garbage", "0.6.0", false},
		{"0.7.0", "dev", false},
	}
	for _, tt := range tests {
		if got := isNewer(tt.candidate, tt.current); got != tt.want {
			t.Errorf("isNewer(%q, %q) = %v, want %v", tt.candidate, tt.current, got, tt.want)
		}
	}
}
