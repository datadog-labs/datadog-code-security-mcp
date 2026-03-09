package main

import (
	"context"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// makeLibraryScanRequest builds a CallToolRequest with the given arguments map.
func makeLibraryScanRequest(args any) mcp.CallToolRequest {
	var req mcp.CallToolRequest
	req.Params.Arguments = args
	return req
}

func TestHandleLibraryVulnerabilityScan_InvalidArguments(t *testing.T) {
	req := makeLibraryScanRequest("not-a-map")
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result for invalid arguments type")
	}
}

func TestHandleLibraryVulnerabilityScan_MissingLibraries(t *testing.T) {
	req := makeLibraryScanRequest(map[string]any{})
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result when 'libraries' key is absent")
	}
}

func TestHandleLibraryVulnerabilityScan_EmptyLibraries(t *testing.T) {
	req := makeLibraryScanRequest(map[string]any{
		"libraries": []any{},
	})
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result for empty libraries array")
	}
}

func TestHandleLibraryVulnerabilityScan_LibraryNotAnObject(t *testing.T) {
	req := makeLibraryScanRequest(map[string]any{
		"libraries": []any{"not-an-object"},
	})
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result when a library item is not an object")
	}
}

func TestHandleLibraryVulnerabilityScan_MissingPURL(t *testing.T) {
	req := makeLibraryScanRequest(map[string]any{
		"libraries": []any{
			map[string]any{"is_dev": true}, // no purl
		},
	})
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result when purl field is missing")
	}
}

func TestHandleLibraryVulnerabilityScan_InvalidPURL(t *testing.T) {
	req := makeLibraryScanRequest(map[string]any{
		"libraries": []any{
			map[string]any{"purl": "npm/lodash@4.17.21"}, // missing "pkg:" prefix
		},
	})
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result for PURL without 'pkg:' prefix")
	}
	if !containsText(result, "invalid purl") {
		t.Errorf("expected error message to mention 'invalid purl', got: %v", result.Content)
	}
}

func TestHandleLibraryVulnerabilityScan_AuthNotConfigured(t *testing.T) {
	// Ensure no credentials are present so auth fails
	t.Setenv("DD_API_KEY", "")
	t.Setenv("DD_APP_KEY", "")

	req := makeLibraryScanRequest(map[string]any{
		"libraries": []any{
			map[string]any{"purl": "pkg:npm/lodash@4.17.21"},
		},
	})
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result when auth is not configured")
	}
}

func TestHandleLibraryVulnerabilityScan_NonExistentWorkingDir(t *testing.T) {
	// Verify that a non-existent working_dir causes a git context miss (empty strings)
	// rather than a crash. The handler falls through to auth validation.
	t.Setenv("DD_API_KEY", "")
	t.Setenv("DD_APP_KEY", "")

	req := makeLibraryScanRequest(map[string]any{
		"libraries": []any{
			map[string]any{"purl": "pkg:npm/lodash@4.17.21"},
		},
		"working_dir": "/tmp/nonexistent",
	})
	result, err := handleLibraryVulnerabilityScan(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	// We expect an auth error (not a panic or nil-deref)
	if !result.IsError {
		t.Error("expected error result (auth not configured)")
	}
}

// containsText checks whether any text content block in the result contains substr.
func containsText(result *mcp.CallToolResult, substr string) bool {
	for _, c := range result.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			if strings.Contains(tc.Text, substr) {
				return true
			}
		}
	}
	return false
}
