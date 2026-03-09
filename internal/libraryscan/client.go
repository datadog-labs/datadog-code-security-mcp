package libraryscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

const (
	defaultPollInterval = 2 * time.Second
	defaultPollTimeout  = 60 * time.Second
)

// Client calls the Datadog SCA API to scan libraries for known vulnerabilities.
type Client struct {
	apiKey       string
	appKey       string
	baseURLValue string // overridable for tests; normally derived from site
	http         *http.Client
	pollInterval time.Duration
}

// NewClient creates a new library scan client for the given Datadog site.
func NewClient(apiKey, appKey, site string) *Client {
	return &Client{
		apiKey:       apiKey,
		appKey:       appKey,
		baseURLValue: fmt.Sprintf("https://app.%s/api/v2/static-analysis-sca", site),
		http:         &http.Client{Timeout: 30 * time.Second},
		pollInterval: defaultPollInterval,
	}
}

// newClientWithBaseURL creates a client with an explicit base URL (for tests).
func newClientWithBaseURL(apiKey, appKey, baseURL string) *Client {
	return &Client{
		apiKey:       apiKey,
		appKey:       appKey,
		baseURLValue: baseURL,
		http:         &http.Client{Timeout: 30 * time.Second},
		pollInterval: defaultPollInterval,
	}
}

// Scan submits a library scan and polls until complete or context expires.
func (c *Client) Scan(ctx context.Context, req ScanRequest) (*ScanResult, error) {
	jobID, err := c.submitScan(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to submit scan: %w", err)
	}

	pollCtx, cancel := context.WithTimeout(ctx, defaultPollTimeout)
	defer cancel()

	return c.pollResult(pollCtx, jobID)
}

// submitScan posts the scan request and returns the job ID from the 202 response.
func (c *Client) submitScan(ctx context.Context, req ScanRequest) (string, error) {
	// Normalize nil slices to empty slices before marshalling to avoid JSON null
	libs := make([]Library, 0, len(req.Libraries))
	for _, lib := range req.Libraries {
		if lib.TargetFrameworks == nil {
			lib.TargetFrameworks = []string{}
		}
		if lib.Exclusions == nil {
			lib.Exclusions = []string{}
		}
		libs = append(libs, lib)
	}

	payload := map[string]any{
		"data": map[string]any{
			"type": "mcpscanrequest",
			"attributes": map[string]any{
				"id":            uuid.New().String(),
				"resource_name": req.ResourceName,
				"commit_hash":   req.CommitHash,
				"libraries":     libs,
			},
		},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	url := c.baseURLValue + "/dependencies/scan"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	c.setAuthHeaders(httpReq)
	httpReq.Header.Set("Content-Type", "application/vnd.api+json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("scan request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("scan request returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var scanResp struct {
		Data struct {
			Attributes struct {
				JobID string `json:"job_id"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &scanResp); err != nil {
		return "", fmt.Errorf("failed to parse scan response: %w", err)
	}
	if scanResp.Data.Attributes.JobID == "" {
		return "", fmt.Errorf("scan response missing job_id")
	}

	return scanResp.Data.Attributes.JobID, nil
}

// pollResult polls GET /dependencies/scan/{jobID} until it returns 200 or the
// context expires. A 404 response indicates the job is still processing.
func (c *Client) pollResult(ctx context.Context, jobID string) (*ScanResult, error) {
	url := fmt.Sprintf("%s/dependencies/scan/%s", c.baseURLValue, jobID)
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timed out waiting for scan job %s: %w", jobID, ctx.Err())
		case <-ticker.C:
			result, done, err := c.fetchResult(ctx, url)
			if err != nil {
				return nil, err
			}
			if done {
				return result, nil
			}
		}
	}
}

// fetchResult makes one GET request. Returns (result, true, nil) when done,
// (nil, false, nil) when still processing (404), or (nil, false, err) on error.
func (c *Client) fetchResult(ctx context.Context, url string) (*ScanResult, bool, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create poll request: %w", err)
	}
	c.setAuthHeaders(httpReq)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, false, fmt.Errorf("poll request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil // still processing
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read poll response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("poll returned unexpected status %d: %s", resp.StatusCode, string(body))
	}

	result, err := parseResponse(body)
	if err != nil {
		return nil, false, err
	}

	return result, true, nil
}

func (c *Client) setAuthHeaders(req *http.Request) {
	req.Header.Set("DD-API-KEY", c.apiKey)
	req.Header.Set("DD-APPLICATION-KEY", c.appKey)
	req.Header.Set("Accept", "application/json")
}
