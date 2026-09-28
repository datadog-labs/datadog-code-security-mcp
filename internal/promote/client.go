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

	"github.com/datadog-labs/datadog-code-security-mcp/internal/ephemeral"
)

const (
	defaultRulesetName  = "variant-hunter"
	defaultShort        = "Variant of a local security fix"
	defaultDescription  = "Custom SAST rule saved from a local variant search."
	defaultCreationMsg  = "Saved from a variant search"
	maxShortDescription = 60
	minSlugLength       = 5
	maxSlugLength       = 32
)

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
	// RulesetName is the ruleset slug. Empty becomes variant-hunter.
	RulesetName string
	// ShortDescription is plain text, at most 60 characters.
	ShortDescription string
	// Description is plain text stored on the revision.
	Description string
}

// Result is what the API accepted.
type Result struct {
	RulesetName    string `json:"ruleset_name"`
	RuleName       string `json:"rule_name"`
	RevisionID     string `json:"revision_id"`
	RulesetExisted bool   `json:"ruleset_existed"`
	RuleExisted    bool   `json:"rule_existed"`
}

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
	prepared.revisionID = strconv.FormatInt(c.now().UnixNano(), 10)

	rulesetExisted, err := c.ensureRuleset(ctx, prepared)
	if err != nil {
		return Result{}, err
	}
	ruleExisted, err := c.ensureRule(ctx, prepared)
	if err != nil {
		return Result{}, err
	}
	revisionID, err := c.createRevision(ctx, prepared)
	if err != nil {
		return Result{}, err
	}
	return Result{
		RulesetName:    prepared.rulesetName,
		RuleName:       prepared.ruleName,
		RevisionID:     revisionID,
		RulesetExisted: rulesetExisted,
		RuleExisted:    ruleExisted,
	}, nil
}

type preparedRequest struct {
	rulesetName      string
	ruleName         string
	language         string
	code             string
	query            string
	shortDescription string
	description      string
	revisionID       string
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
	if len(short) > maxShortDescription {
		return preparedRequest{}, fmt.Errorf("short description is longer than %d characters", maxShortDescription)
	}
	description := strings.TrimSpace(req.Description)
	if description == "" {
		description = defaultDescription
	}

	return preparedRequest{
		rulesetName:      rulesetName,
		ruleName:         ruleName,
		language:         strings.ToUpper(strings.TrimSpace(req.Language)),
		code:             base64.StdEncoding.EncodeToString([]byte(req.RuleCode)),
		query:            base64.StdEncoding.EncodeToString([]byte(req.TreeSitterQuery)),
		shortDescription: base64.StdEncoding.EncodeToString([]byte(short)),
		description:      base64.StdEncoding.EncodeToString([]byte(description)),
	}, nil
}

func (c *Client) ensureRuleset(ctx context.Context, req preparedRequest) (bool, error) {
	body, err := jsonAPI("custom_ruleset", req.rulesetName, map[string]any{
		"name":              req.rulesetName,
		"short_description": req.shortDescription,
		"description":       req.description,
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
	body, err := jsonAPI("custom_rule_revision", req.revisionID, map[string]any{
		"creation_message":  defaultCreationMsg,
		"short_description": req.shortDescription,
		"description":       req.description,
		"code":              req.code,
		"language":          req.language,
		"tree_sitter_query": req.query,
		"severity":          "ERROR",
		"category":          "SECURITY",
		"arguments":         []any{},
		"tests":             []any{},
		"tags":              []string{"security"},
		"is_published":      true,
		"should_use_ai_fix": false,
		"is_testing":        false,
	})
	if err != nil {
		return "", err
	}
	path := "/custom/rulesets/" + url.PathEscape(req.rulesetName) + "/rules/" + url.PathEscape(req.ruleName) + "/revisions"
	status, resp, err := c.put(ctx, path, body)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("create rule revision returned status %d: %s", status, resp)
	}
	return req.revisionID, nil
}

func (c *Client) put(ctx context.Context, path string, body []byte) (int, string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+path, bytes.NewReader(body))
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
