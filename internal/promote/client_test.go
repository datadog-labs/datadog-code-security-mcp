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
			_, _ = io.WriteString(w, `{"data":{"id":"2067","type":"custom_rule_revision"}}`)
			return
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
	if result.RevisionID != "2067" {
		t.Fatalf("revision id %q, want the server id 2067", result.RevisionID)
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
		if r.Method != http.MethodPut {
			t.Errorf("unexpected method %s", r.Method)
		}
		if strings.HasSuffix(r.URL.Path, "/revisions") {
			revisionCalls++
			_, _ = io.WriteString(w, `{"data":{"id":"2068","type":"custom_rule_revision"}}`)
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

func TestSaveReadsTheRevisionIDFromTheRuleWhenTheCreateResponseHasNone(t *testing.T) {
	var gets []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets = append(gets, r.URL.Path)
			_, _ = io.WriteString(w, `{"data":{"id":"missing-admin","attributes":{"last_revision":{"id":"2069"}}}}`)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newClientWithBaseURL("api", "app", server.URL)
	result, err := client.Save(context.Background(), sampleRequest(true))
	if err != nil {
		t.Fatal(err)
	}
	if result.RevisionID != "2069" {
		t.Fatalf("revision id %q, want 2069 from the rule", result.RevisionID)
	}
	if strings.Join(gets, ",") != "/custom/rulesets/variant-hunter/rules/missing-admin" {
		t.Fatalf("gets %v", gets)
	}
}

func TestSaveSucceedsWithAnEmptyRevisionIDWhenTheLookupFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newClientWithBaseURL("api", "app", server.URL)
	result, err := client.Save(context.Background(), sampleRequest(true))
	if err != nil {
		t.Fatalf("a failed lookup after a successful save must not fail the save: %v", err)
	}
	if result.RevisionID != "" {
		t.Fatalf("revision id %q, want empty rather than the request id", result.RevisionID)
	}
}

func TestRawIDAcceptsStringAndNumber(t *testing.T) {
	cases := map[string]string{`"2067"`: "2067", `2067`: "2067", `null`: "", ``: ""}
	for raw, want := range cases {
		if got := rawID(json.RawMessage(raw)); got != want {
			t.Errorf("rawID(%s) = %q, want %q", raw, got, want)
		}
	}
}

func TestSaveKeepsTheRulesetDescriptionGeneric(t *testing.T) {
	var rulesetBody map[string]any
	var revisionBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("unexpected method %s", r.Method)
		}
		raw, _ := io.ReadAll(r.Body)
		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		if r.URL.Path == "/custom/rulesets" {
			rulesetBody = payload
		}
		if strings.HasSuffix(r.URL.Path, "/revisions") {
			revisionBody = payload
			_, _ = io.WriteString(w, `{"data":{"id":"2070","type":"custom_rule_revision"}}`)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req := sampleRequest(true)
	req.ShortDescription = "requireAdmin before privileged user changes"
	req.Description = "After authenticate(req), deleteUser must call requireAdmin(user) before database.deleteUser."
	client := newClientWithBaseURL("api", "app", server.URL)
	if _, err := client.Save(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	rulesetAttrs := rulesetBody["data"].(map[string]any)["attributes"].(map[string]any)
	rulesetDescription := decodeField(t, rulesetAttrs["description"].(string))
	rulesetShort := decodeField(t, rulesetAttrs["short_description"].(string))
	if rulesetDescription != defaultDescription || rulesetShort != defaultShort {
		t.Fatalf("ruleset text short=%q description=%q", rulesetShort, rulesetDescription)
	}

	revisionAttrs := revisionBody["data"].(map[string]any)["attributes"].(map[string]any)
	if decodeField(t, revisionAttrs["description"].(string)) != req.Description {
		t.Fatal("rule description was not stored on the revision")
	}
	if decodeField(t, revisionAttrs["short_description"].(string)) != req.ShortDescription {
		t.Fatal("rule short description was not stored on the revision")
	}
}

func decodeField(t *testing.T, raw string) string {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	return string(decoded)
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

func TestSaveStoresMeasuredTests(t *testing.T) {
	var revisionBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/revisions") {
			raw, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(raw, &revisionBody); err != nil {
				t.Fatal(err)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req := sampleRequest(true)
	req.Tests = []Test{
		{Filename: "compliant.ts", Code: "function ok() { requireAdmin(user); }", AnnotationCount: 0},
		{Filename: "noncompliant.ts", Code: "function bad() { database.deleteUser(id); }", AnnotationCount: 1},
	}
	client := newClientWithBaseURL("api", "app", server.URL)
	if _, err := client.Save(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	attrs := revisionBody["data"].(map[string]any)["attributes"].(map[string]any)
	tests, ok := attrs["tests"].([]any)
	if !ok || len(tests) != 2 {
		t.Fatalf("tests %#v", attrs["tests"])
	}
	first := tests[0].(map[string]any)
	code, err := base64.StdEncoding.DecodeString(first["code"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if first["filename"] != "compliant.ts" || string(code) != req.Tests[0].Code || first["annotation_count"] != float64(0) {
		t.Fatalf("first test %#v", first)
	}
	second := tests[1].(map[string]any)
	if second["annotation_count"] != float64(1) {
		t.Fatalf("second test %#v", second)
	}
}

func TestSaveRejectsANegativeAnnotationCountBeforeCalling(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()

	req := sampleRequest(true)
	req.Tests = []Test{{Filename: "bad.ts", Code: "function bad() {}", AnnotationCount: -1}}
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
