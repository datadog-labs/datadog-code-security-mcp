// Package promote uploads a caller-supplied SAST rule to the existing Static
// Analysis custom-rule API. It does not infer an invariant, edit the rule, or
// scan. The caller decides which source to save.
package promote

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
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
	// Tests are the two examples ValidateTests requires.
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

// APIError means a custom rule API call failed. Status is 0 when no response
// arrived. Body is the start of the response, which can echo the request.
type APIError struct {
	Op     string
	Status int
	Body   string
	Err    error
}

func (e *APIError) Error() string {
	if e.Status == 0 {
		return fmt.Sprintf("%s failed: %v", e.Op, e.Err)
	}
	summary := fmt.Sprintf("%s returned status %d", e.Op, e.Status)
	if detail := apiErrorDetails(e.Body); detail != "" {
		return summary + ": " + detail + "\n" + e.Body
	}
	return summary + ": " + e.Body
}

// apiErrorDetails returns the human-readable sentences from a JSON:API error
// body. The raw body stays in the error either way, because it names the field.
func apiErrorDetails(body string) string {
	var payload struct {
		Errors []struct {
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if json.Unmarshal([]byte(body), &payload) != nil {
		return ""
	}
	var details []string
	for _, item := range payload.Errors {
		detail := strings.TrimSpace(item.Detail)
		if detail != "" {
			details = append(details, detail)
		}
	}
	return strings.Join(details, "; ")
}

func (e *APIError) Unwrap() error { return e.Err }

// maxErrorBody bounds the response text an APIError keeps.
const maxErrorBody = 1000

func apiStatusError(op string, status int, body string) error {
	if len(body) > maxErrorBody {
		cut := maxErrorBody
		for cut > 0 && !utf8.RuneStart(body[cut]) {
			cut--
		}
		body = body[:cut] + "…"
	}
	return &APIError{Op: op, Status: status, Body: body}
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
		return Result{}, errNotConfirmed
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
		if !ruleExisted {
			return Result{}, fmt.Errorf("%w\n%s", err, emptyRuleHint(prepared, err))
		}
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

// emptyRuleHint explains the rule shell left behind when creating its first
// revision fails. A rejected request fails again with the same body, so the
// hint says to fix it before replacing the shell. Other failures can succeed
// on a retry with overwrite.
func emptyRuleHint(req preparedRequest, err error) string {
	created := fmt.Sprintf("This call created the rule %s in the ruleset %s, but it has no revision, so it is empty.", req.ruleName, req.rulesetName)
	if revisionRejected(err) {
		return created + " Saving the same request again will fail the same way. Fix the request, then save with overwrite to replace this empty rule (--overwrite in the CLI)."
	}
	return created + " To retry, save again with overwrite (--overwrite in the CLI)."
}

// revisionRejected reports a response that refuses this request. Auth, conflict,
// and rate-limit responses are left out: those can succeed on a later try.
func revisionRejected(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status < 400 || apiErr.Status >= 500 {
		return false
	}
	switch apiErr.Status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict, http.StatusTooManyRequests:
		return false
	default:
		return true
	}
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
		return false, apiStatusError("check existing rule", status, resp)
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
	if reason := validateSlug(rulesetName); reason != "" {
		return preparedRequest{}, &InvalidNameError{Field: "ruleset name", Name: rulesetName, Reason: reason}
	}
	if reason := validateSlug(ruleName); reason != "" {
		return preparedRequest{}, &InvalidNameError{Field: "rule name", Name: ruleName, Reason: reason}
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
		return preparedRequest{}, ephemeral.InvalidInput("short description too long", "short description is longer than %d characters", maxShortDescription)
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

var errNotConfirmed = ephemeral.InvalidInput("user_confirmed is not true", "user_confirmed must be true before saving a custom rule")

// Validate checks everything Save checks before it calls the API, except the
// credentials: confirmation, names, descriptions, and tests.
func Validate(req Request) error {
	if !req.UserConfirmed {
		return errNotConfirmed
	}
	_, err := prepare(req)
	return err
}

// ValidateTests requires the two examples the pre-save check runs: one with
// annotation_count 0 and one with a positive count. Without a positive count,
// a rule that never reports would pass that check.
func ValidateTests(tests []Test) error {
	zero, positive := 0, 0
	for _, test := range tests {
		switch {
		case test.AnnotationCount == 0:
			zero++
		case test.AnnotationCount > 0:
			positive++
		}
	}
	if len(tests) != maxTests || zero != 1 || positive != 1 {
		return ephemeral.InvalidInput("examples must be one clean and one flagged", "tests must be exactly %d examples: the fixed code with annotation_count 0, and the code before the fix with a positive annotation_count", maxTests)
	}
	return nil
}

func encodeTests(tests []Test) ([]any, error) {
	if err := ValidateTests(tests); err != nil {
		return nil, err
	}
	encoded := make([]any, 0, len(tests))
	for _, test := range tests {
		filename := test.Filename
		if strings.TrimSpace(filename) != filename || filename == "" || filename == "." || filename == ".." ||
			strings.ContainsAny(filename, `/\`) {
			return nil, ephemeral.InvalidInput("invalid example filename", "test filename must be a file name without directories or surrounding spaces")
		}
		code := test.Code
		if strings.TrimSpace(code) == "" {
			return nil, ephemeral.InvalidInput("example code is empty", "test code is empty")
		}
		if test.AnnotationCount < 0 {
			return nil, ephemeral.InvalidInput("negative annotation_count", "annotation_count must be >= 0")
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
		return false, apiStatusError("create ruleset", status, resp)
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
		return false, apiStatusError("create rule", status, resp)
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
		return "", apiStatusError("create rule revision", status, resp)
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
		return 0, "", &APIError{Op: method + " request", Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, "", &APIError{Op: "read response", Err: err}
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

// InvalidNameError means a rule or ruleset name is not a valid slug.
type InvalidNameError struct {
	Field  string
	Name   string
	Reason string
}

func (e *InvalidNameError) Error() string {
	return fmt.Sprintf("%s: %q %s", e.Field, e.Name, e.Reason)
}

// validateSlug returns why name is not a valid slug, or "" when it is.
func validateSlug(name string) string {
	if len(name) < minSlugLength || len(name) > maxSlugLength {
		return fmt.Sprintf("must be %d to %d characters", minSlugLength, maxSlugLength)
	}
	if name[0] == '-' || name[len(name)-1] == '-' {
		return "cannot start or end with a hyphen"
	}
	previousDash := false
	for _, r := range name {
		if r == '-' {
			if previousDash {
				return "cannot contain a double hyphen"
			}
			previousDash = true
			continue
		}
		previousDash = false
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
			return "must be lowercase"
		default:
			return fmt.Sprintf("contains %q; use only a-z, 0-9, and hyphens", string(r))
		}
	}
	return ""
}
