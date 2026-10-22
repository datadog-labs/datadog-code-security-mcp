// Package promote uploads a caller-supplied SAST rule to the existing Static
// Analysis custom-rule API. It does not infer an invariant, edit the rule, or
// scan. The caller decides which source to save.
package promote

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/ephemeral"
)

const (
	defaultRulesetName  = "security-variants"
	defaultShort        = "Variant of a local security fix"
	defaultDescription  = "Custom SAST rule saved from a local variant search."
	defaultCreationMsg  = "Saved from a variant search"
	maxShortDescription = 60
	minSlugLength       = 5
	maxSlugLength       = 32
	maxTests            = 2
)

// Test is one example the Datadog rule page shows.
// AnnotationCount 0 is the compliant example. Any other count is non-compliant.
// This package does not scan the example. The promote command does, before it
// calls Save, and refuses when a count differs.
type Test struct {
	Filename        string
	Code            string
	AnnotationCount int
}

// Request is the rule the caller has already approved.
type Request struct {
	// UserConfirmed must be true. The API is not called otherwise.
	UserConfirmed bool
	// RuleCode is the DDSA JavaScript source, not base64.
	RuleCode string
	// TreeSitterQuery is the tree-sitter query source, not base64.
	TreeSitterQuery string
	// Language is the scanner enum, for example TYPESCRIPT.
	Language string
	// RuleName is the rule slug.
	RuleName string
	// RulesetName is the ruleset slug. Empty becomes security-variants.
	RulesetName string
	// ShortDescription is plain text, at most 60 characters.
	ShortDescription string
	// Description is plain text stored on the revision.
	Description string
	// Tests are measured examples. Empty leaves the rule page without a sample.
	Tests []Test
	// Overwrite must be true to publish a new revision of a rule that already
	// exists. The existing rule may belong to someone else.
	Overwrite bool
}

// Result is what the API accepted.
type Result struct {
	RulesetName    string `json:"ruleset_name"`
	RuleName       string `json:"rule_name"`
	RevisionID     string `json:"revision_id"`
	RulesetExisted bool   `json:"ruleset_existed"`
	RuleExisted    bool   `json:"rule_existed"`
	// Warning is set when the save succeeded but something is missing.
	Warning string `json:"warning,omitempty"`
}

// RuleExistsError means the rule is already saved and Overwrite was false.
type RuleExistsError struct {
	RulesetName string
	RuleName    string
}

func (e *RuleExistsError) Error() string {
	return fmt.Sprintf("rule %q already exists in ruleset %q. Saving would publish a new revision over it. Ask the user, then retry with overwrite set to true (--overwrite in the CLI), or choose another rule name", e.RuleName, e.RulesetName)
}

const missingRevisionWarning = "The rule was saved, but Datadog did not return its revision id. Open the rule page to see the revision."

// Client calls the public Static Analysis custom-rule API.
type Client struct {
	apiKey  string
	appKey  string
	baseURL string
	http    *http.Client
	now     func() time.Time
}

// NewClient uses https://api.{site}/api/v2/static-analysis.
func NewClient(apiKey, appKey, site string) *Client {
	if site == "" {
		site = "datadoghq.com"
	}
	return &Client{
		apiKey:  apiKey,
		appKey:  appKey,
		baseURL: "https://api." + site + "/api/v2/static-analysis",
		http:    &http.Client{Timeout: 30 * time.Second},
		now:     time.Now,
	}
}

func newClientWithBaseURL(apiKey, appKey, baseURL string) *Client {
	return &Client{
		apiKey:  apiKey,
		appKey:  appKey,
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 30 * time.Second},
		now:     func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
}

// Save creates the ruleset and the rule when they are missing, then stores a
// new revision of the exact source it was given.
func (c *Client) Save(ctx context.Context, req Request) (Result, error) {
	if !req.UserConfirmed {
		return Result{}, fmt.Errorf("user_confirmed must be true before saving a custom rule")
	}
	if c.apiKey == "" || c.appKey == "" {
		return Result{}, fmt.Errorf("DD_API_KEY and DD_APP_KEY are required to save a custom rule")
	}
	prepared, err := prepare(req)
	if err != nil {
		return Result{}, err
	}
	prepared.requestID = strconv.FormatInt(c.now().UnixNano(), 10)

	exists, err := c.ruleExists(ctx, prepared)
	if err != nil {
		return Result{}, err
	}
	if exists && !req.Overwrite {
		return Result{}, &RuleExistsError{RulesetName: prepared.rulesetName, RuleName: prepared.ruleName}
	}

	rulesetExisted, err := c.ensureRuleset(ctx, prepared)
	if err != nil {
		return Result{}, err
	}
	ruleExisted, err := c.ensureRule(ctx, prepared)
	if err != nil {
		return Result{}, err
	}
	// Someone else can create the rule between the check above and this call.
	if ruleExisted && !req.Overwrite {
		return Result{}, &RuleExistsError{RulesetName: prepared.rulesetName, RuleName: prepared.ruleName}
	}
	revisionID, err := c.createRevision(ctx, prepared)
	if err != nil {
		return Result{}, err
	}
	result := Result{
		RulesetName:    prepared.rulesetName,
		RuleName:       prepared.ruleName,
		RevisionID:     revisionID,
		RulesetExisted: rulesetExisted,
		RuleExisted:    ruleExisted,
	}
	if revisionID == "" {
		result.Warning = missingRevisionWarning
	}
	return result, nil
}

// ruleExists reports whether the rule is already saved. A missing ruleset
// also returns 404. Any other status stops the save, because the overwrite
// check cannot be trusted.
func (c *Client) ruleExists(ctx context.Context, req preparedRequest) (bool, error) {
	status, resp, err := c.do(ctx, http.MethodGet, rulePath(req), nil)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("check existing rule returned status %d: %s", status, resp)
	}
}

func rulePath(req preparedRequest) string {
	return "/custom/rulesets/" + url.PathEscape(req.rulesetName) + "/rules/" + url.PathEscape(req.ruleName)
}

type preparedRequest struct {
	rulesetName      string
	ruleName         string
	language         string
	code             string
	query            string
	shortDescription string
	description      string
	requestID        string
	tests            []any
}

func prepare(req Request) (preparedRequest, error) {
	rulesetName := strings.TrimSpace(req.RulesetName)
	if rulesetName == "" {
		rulesetName = defaultRulesetName
	}
	ruleName := strings.TrimSpace(req.RuleName)
	if err := validateSlug(rulesetName); err != nil {
		return preparedRequest{}, fmt.Errorf("ruleset name: %w", err)
	}
	if err := validateSlug(ruleName); err != nil {
		return preparedRequest{}, fmt.Errorf("rule name: %w", err)
	}
	if _, err := ephemeral.BuildRulesJSON(ephemeral.Input{
		RuleCode:        req.RuleCode,
		TreeSitterQuery: req.TreeSitterQuery,
		Language:        req.Language,
		RuleName:        ruleName,
		RulesetName:     rulesetName,
	}); err != nil {
		return preparedRequest{}, err
	}

	short := strings.TrimSpace(req.ShortDescription)
	if short == "" {
		short = defaultShort
	}
	if utf8.RuneCountInString(short) > maxShortDescription {
		return preparedRequest{}, fmt.Errorf("short description is longer than %d characters", maxShortDescription)
	}
	description := strings.TrimSpace(req.Description)
	if description == "" {
		description = defaultDescription
	}
	tests, err := encodeTests(req.Tests)
	if err != nil {
		return preparedRequest{}, err
	}

	return preparedRequest{
		rulesetName:      rulesetName,
		ruleName:         ruleName,
		language:         strings.ToUpper(strings.TrimSpace(req.Language)),
		code:             base64.StdEncoding.EncodeToString([]byte(req.RuleCode)),
		query:            base64.StdEncoding.EncodeToString([]byte(req.TreeSitterQuery)),
		shortDescription: base64.StdEncoding.EncodeToString([]byte(short)),
		description:      base64.StdEncoding.EncodeToString([]byte(description)),
		tests:            tests,
	}, nil
}

func encodeTests(tests []Test) ([]any, error) {
	if len(tests) > maxTests {
		return nil, fmt.Errorf("at most %d tests", maxTests)
	}
	encoded := make([]any, 0, len(tests))
	for _, test := range tests {
		filename := strings.TrimSpace(test.Filename)
		if filename == "" || strings.ContainsAny(filename, `/\`) {
			return nil, fmt.Errorf("test filename must be a single path segment")
		}
		code := test.Code
		if strings.TrimSpace(code) == "" {
			return nil, fmt.Errorf("test code is empty")
		}
		if test.AnnotationCount < 0 {
			return nil, fmt.Errorf("annotation_count must be >= 0")
		}
		encoded = append(encoded, map[string]any{
			"filename":         filename,
			"code":             base64.StdEncoding.EncodeToString([]byte(code)),
			"annotation_count": test.AnnotationCount,
		})
	}
	return encoded, nil
}

func (c *Client) ensureRuleset(ctx context.Context, req preparedRequest) (bool, error) {
	// The ruleset is shared by every rule saved into it. Its text stays generic.
	// A ruleset that already exists is left as it is. The detailed description
	// is stored on the rule revision.
	body, err := jsonAPI("custom_ruleset", req.rulesetName, map[string]any{
		"name":              req.rulesetName,
		"short_description": base64.StdEncoding.EncodeToString([]byte(defaultShort)),
		"description":       base64.StdEncoding.EncodeToString([]byte(defaultDescription)),
	})
	if err != nil {
		return false, err
	}
	status, resp, err := c.put(ctx, "/custom/rulesets", body)
	if err != nil {
		return false, err
	}
	if status == http.StatusConflict {
		return true, nil
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("create ruleset returned status %d: %s", status, resp)
	}
	return false, nil
}

func (c *Client) ensureRule(ctx context.Context, req preparedRequest) (bool, error) {
	body, err := jsonAPI("custom_rule", req.ruleName, map[string]any{
		"name": req.ruleName,
	})
	if err != nil {
		return false, err
	}
	path := "/custom/rulesets/" + url.PathEscape(req.rulesetName) + "/rules"
	status, resp, err := c.put(ctx, path, body)
	if err != nil {
		return false, err
	}
	if status == http.StatusConflict {
		return true, nil
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("create rule returned status %d: %s", status, resp)
	}
	return false, nil
}

func (c *Client) createRevision(ctx context.Context, req preparedRequest) (string, error) {
	body, err := jsonAPI("custom_rule_revision", req.requestID, map[string]any{
		"creation_message":  base64.StdEncoding.EncodeToString([]byte(defaultCreationMsg)),
		"short_description": req.shortDescription,
		"description":       req.description,
		"code":              req.code,
		"language":          req.language,
		"tree_sitter_query": req.query,
		"severity":          "ERROR",
		"category":          "SECURITY",
		"arguments":         []any{},
		"tests":             req.tests,
		"tags":              []string{"security"},
		"is_published":      true,
		"should_use_ai_fix": false,
		"is_testing":        false,
	})
	if err != nil {
		return "", err
	}
	status, resp, err := c.put(ctx, rulePath(req)+"/revisions", body)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("create rule revision returned status %d: %s", status, resp)
	}
	if id := jsonAPIID(resp); id != "" {
		return id, nil
	}
	return c.lastRevisionID(ctx, req), nil
}

// lastRevisionID reads the server-assigned id of the rule's latest revision.
// The id sent in the create request is not the one Datadog stores. An empty
// result means the lookup failed after a successful save.
func (c *Client) lastRevisionID(ctx context.Context, req preparedRequest) string {
	status, resp, err := c.do(ctx, http.MethodGet, rulePath(req), nil)
	if err != nil || status != http.StatusOK {
		return ""
	}
	var payload struct {
		Data struct {
			Attributes struct {
				LastRevision struct {
					ID json.RawMessage `json:"id"`
				} `json:"last_revision"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(resp), &payload) != nil {
		return ""
	}
	return rawID(payload.Data.Attributes.LastRevision.ID)
}

func (c *Client) put(ctx context.Context, path string, body []byte) (int, string, error) {
	return c.do(ctx, http.MethodPut, path, body)
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) (int, string, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return 0, "", fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("DD-API-KEY", c.apiKey)
	httpReq.Header.Set("DD-APPLICATION-KEY", c.appKey)
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/vnd.api+json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return 0, "", fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, "", fmt.Errorf("read response: %w", err)
	}
	return resp.StatusCode, strings.TrimSpace(string(respBody)), nil
}

func jsonAPI(resourceType, id string, attributes map[string]any) ([]byte, error) {
	payload := map[string]any{
		"data": map[string]any{
			"type":       resourceType,
			"id":         id,
			"attributes": attributes,
		},
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	return encoded, nil
}

func jsonAPIID(body string) string {
	var payload struct {
		Data struct {
			ID json.RawMessage `json:"id"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(body), &payload) != nil {
		return ""
	}
	return rawID(payload.Data.ID)
}

// rawID accepts a JSON:API id sent as a string or as a number.
func rawID(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		return number.String()
	}
	return ""
}

func validateSlug(name string) error {
	if len(name) < minSlugLength || len(name) > maxSlugLength {
		return fmt.Errorf("%q must be %d to %d characters", name, minSlugLength, maxSlugLength)
	}
	if name[0] == '-' || name[len(name)-1] == '-' {
		return fmt.Errorf("%q cannot start or end with a hyphen", name)
	}
	previousDash := false
	for _, r := range name {
		if r == '-' {
			if previousDash {
				return fmt.Errorf("%q cannot contain a double hyphen", name)
			}
			previousDash = true
			continue
		}
		previousDash = false
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return fmt.Errorf("%q contains %q", name, string(r))
		}
		if unicode.IsLetter(r) && unicode.IsUpper(r) {
			return fmt.Errorf("%q must be lowercase", name)
		}
	}
	return nil
}
