package libraryscan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient_BaseURL(t *testing.T) {
	c := NewClient("api-key", "app-key", "datadoghq.eu")
	expected := "https://app.datadoghq.eu/api/v2/static-analysis-sca"
	if c.baseURLValue != expected {
		t.Errorf("expected baseURLValue %q, got %q", expected, c.baseURLValue)
	}
}

func TestClient_SubmitScan_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/dependencies/scan") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("DD-API-KEY") != "test-api-key" {
			t.Errorf("missing DD-API-KEY header")
		}
		if r.Header.Get("DD-APPLICATION-KEY") != "test-app-key" {
			t.Errorf("missing DD-APPLICATION-KEY header")
		}

		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"attributes": map[string]any{
					"job_id": "test-job-123",
				},
			},
		})
	}))
	defer srv.Close()

	client := newClientWithBaseURL("test-api-key", "test-app-key", srv.URL)
	jobID, err := client.submitScan(context.Background(), ScanRequest{
		Libraries: []Library{{Purl: "pkg:npm/lodash@4.17.20"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jobID != "test-job-123" {
		t.Errorf("expected job ID test-job-123, got %s", jobID)
	}
}

func TestClient_SubmitScan_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "invalid purl"}`))
	}))
	defer srv.Close()

	client := newClientWithBaseURL("key", "appkey", srv.URL)
	_, err := client.submitScan(context.Background(), ScanRequest{
		Libraries: []Library{{Purl: "invalid"}},
	})
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
}

func TestClient_PollResult_NotFoundThenOK(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusNotFound) // still processing
			return
		}
		// Second call: return results
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"VULNERABILITY_DETECTION": {"advisories": []}}`))
	}))
	defer srv.Close()

	client := newClientWithBaseURL("key", "appkey", srv.URL)
	// Override poll interval to speed up test
	client.pollInterval = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := client.pollResult(ctx, "job-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if callCount < 2 {
		t.Errorf("expected at least 2 poll calls, got %d", callCount)
	}
}

func TestClient_PollResult_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // always not found
	}))
	defer srv.Close()

	client := newClientWithBaseURL("key", "appkey", srv.URL)
	client.pollInterval = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.pollResult(ctx, "job-timeout")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestClient_RequestBody_WrapsInJSONAPI(t *testing.T) {
	var receivedBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"attributes": map[string]any{"job_id": "x"}},
		})
	}))
	defer srv.Close()

	client := newClientWithBaseURL("k", "a", srv.URL)
	_, _ = client.submitScan(context.Background(), ScanRequest{ // nolint: errcheck — testing captured body, not return value
		Libraries:    []Library{{Purl: "pkg:npm/lodash@4.0.0", IsDirect: true}},
		ResourceName: "github.com/owner/repo",
		CommitHash:   "abc123",
	})

	data, ok := receivedBody["data"].(map[string]any)
	if !ok {
		t.Fatal("expected top-level 'data' key")
	}
	if data["type"] != "mcpscanrequest" {
		t.Errorf("expected type=mcpscanrequest, got %v", data["type"])
	}
	attrs, ok := data["attributes"].(map[string]any)
	if !ok {
		t.Fatal("expected 'attributes' in data")
	}
	if attrs["resource_name"] != "github.com/owner/repo" {
		t.Errorf("unexpected resource_name: %v", attrs["resource_name"])
	}
}

func TestClient_Scan_EndToEnd(t *testing.T) {
	postCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			postCalled = true
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"attributes": map[string]any{"job_id": "end-to-end-job"},
				},
			})
			return
		}
		// GET poll — return result immediately
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"VULNERABILITY_DETECTION": {"advisories": []}}`))
	}))
	defer srv.Close()

	client := newClientWithBaseURL("key", "appkey", srv.URL)
	client.pollInterval = 10 * time.Millisecond

	result, err := client.Scan(context.Background(), ScanRequest{
		Libraries: []Library{{Purl: "pkg:npm/lodash@4.17.20"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !postCalled {
		t.Error("expected POST to be called")
	}
}
