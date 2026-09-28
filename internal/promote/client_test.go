package promote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSaveRefusesWithoutConfirmation(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()

	client := newClientWithBaseURL("api", "app", server.URL)
	_, err := client.Save(context.Background(), sampleRequest(false))
	if err == nil {
		t.Fatal("expected an error")
	}
	if called {
		t.Fatal("the API was called without confirmation")
	}
}

func TestSaveCreatesRulesetRuleAndRevision(t *testing.T) {
	var paths []string
	var revisionBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method %s", r.Method)
		}
		if r.Header.Get("DD-API-KEY") != "api" || r.Header.Get("DD-APPLICATION-KEY") != "app" {
			t.Errorf("missing auth headers")
		}
		paths = append(paths, r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/revisions") {
			raw, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(raw, &revisionBody); err != nil {
				t.Fatal(err)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newClientWithBaseURL("api", "app", server.URL)
	result, err := client.Save(context.Background(), sampleRequest(true))
	if err != nil {
		t.Fatal(err)
	}
	if result.RulesetExisted || result.RuleExisted {
		t.Fatalf("new rule reported as existing: %+v", result)
	}
	if result.RulesetName != "variant-hunter" || result.RuleName != "missing-admin" {
		t.Fatalf("names: %+v", result)
	}
	want := []string{
		"/custom/rulesets",
		"/custom/rulesets/variant-hunter/rules",
		"/custom/rulesets/variant-hunter/rules/missing-admin/revisions",
	}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("paths %v", paths)
	}
	attrs := revisionBody["data"].(map[string]any)["attributes"].(map[string]any)
	code, err := base64.StdEncoding.DecodeString(attrs["code"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if string(code) != "function visit() {}" {
		t.Fatalf("code %q", code)
	}
	if attrs["severity"] != "ERROR" || attrs["is_published"] != true {
		t.Fatalf("revision attributes %#v", attrs)
	}
}

func TestSaveContinuesWhenRulesetAndRuleAlreadyExist(t *testing.T) {
	var revisionCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/revisions") {
			revisionCalls++
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()

	client := newClientWithBaseURL("api", "app", server.URL)
	result, err := client.Save(context.Background(), sampleRequest(true))
	if err != nil {
		t.Fatal(err)
	}
	if !result.RulesetExisted || !result.RuleExisted {
		t.Fatalf("expected existing ruleset and rule: %+v", result)
	}
	if revisionCalls != 1 {
		t.Fatalf("revision calls %d", revisionCalls)
	}
}

func TestSaveRejectsABadSlugBeforeCalling(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()

	req := sampleRequest(true)
	req.RuleName = "Bad_Name"
	client := newClientWithBaseURL("api", "app", server.URL)
	if _, err := client.Save(context.Background(), req); err == nil {
		t.Fatal("expected an error")
	}
	if called {
		t.Fatal("the API was called")
	}
}

func sampleRequest(confirmed bool) Request {
	return Request{
		UserConfirmed:   confirmed,
		RuleCode:        "function visit() {}",
		TreeSitterQuery: "(identifier) @name",
		Language:        "TYPESCRIPT",
		RuleName:        "missing-admin",
		RulesetName:     "variant-hunter",
	}
}
