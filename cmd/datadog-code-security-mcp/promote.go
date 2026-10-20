package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/spf13/cobra"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/auth"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/constants"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/promote"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/telemetry"
)

func newPromoteSASTRuleCmd() *cobra.Command {
	var (
		codeFile         string
		queryFile        string
		language         string
		ruleName         string
		rulesetName      string
		testsFile        string
		descriptionFile  string
		shortDescription string
		confirmed        bool
		overwrite        bool
	)

	cmd := &cobra.Command{
		Use:   "promote-sast-rule",
		Short: "Save a caller-supplied SAST rule as a custom rule",
		Long: `Upload the exact JavaScript and tree-sitter query the caller supplies.
The command does not infer an invariant and does not edit the rule.
It requires --user-confirmed. Credentials are DD_API_KEY and DD_APP_KEY, or DD_AUTH_DOMAIN so dd-auth can supply a short-lived token.

Example:
  datadog-code-security-mcp promote-sast-rule --called-by-skill --user-confirmed \
    --language TYPESCRIPT --rule-name missing-admin \
    --code-file rule.js --query-file rule.scm`,
		RunE: func(cmd *cobra.Command, args []string) error {
			code, err := os.ReadFile(codeFile)
			if err != nil {
				return fmt.Errorf("rule code: %w", err)
			}
			query, err := os.ReadFile(queryFile)
			if err != nil {
				return fmt.Errorf("tree-sitter query: %w", err)
			}
			tests, err := readTestsFile(testsFile)
			if err != nil {
				return err
			}
			description, err := readOptionalFile(descriptionFile)
			if err != nil {
				return err
			}
			result, err := runPromote(cmd.Context(), promote.Request{
				UserConfirmed:    confirmed,
				RuleCode:         string(code),
				TreeSitterQuery:  string(query),
				Language:         language,
				RuleName:         ruleName,
				RulesetName:      rulesetName,
				ShortDescription: shortDescription,
				Description:      description,
				Tests:            tests,
				Overwrite:        overwrite,
			}, telemetry.InterfaceCLI, cliCaller())
			if err != nil {
				return err
			}
			encoded, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(encoded))
			return nil
		},
	}

	cmd.Flags().StringVar(&codeFile, "code-file", "", "Path to the rule JavaScript source")
	cmd.Flags().StringVar(&queryFile, "query-file", "", "Path to the tree-sitter query")
	cmd.Flags().StringVar(&language, "language", "", "Scanner language enum, for example TYPESCRIPT")
	cmd.Flags().StringVar(&ruleName, "rule-name", "", "Rule slug")
	cmd.Flags().StringVar(&rulesetName, "ruleset-name", "", "Ruleset slug (default: security-variants)")
	cmd.Flags().StringVar(&testsFile, "tests-file", "", "Optional JSON array of measured examples: filename, code, annotation_count")
	cmd.Flags().StringVar(&descriptionFile, "description-file", "", "Plain-text file. States the guard, where it must run, and every operation the rule flags")
	cmd.Flags().StringVar(&shortDescription, "short-description", "", "One line, at most 60 characters, naming the guard and the operation")
	cmd.Flags().BoolVar(&confirmed, "user-confirmed", false, "Required. The user has agreed to save this exact rule")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Publish a new revision when the rule already exists. Only after the user agrees to replace it")
	_ = cmd.MarkFlagRequired("code-file")
	_ = cmd.MarkFlagRequired("query-file")
	_ = cmd.MarkFlagRequired("language")
	_ = cmd.MarkFlagRequired("rule-name")
	return cmd
}

func handlePromoteSASTRule(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	argsMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return errorResult(fmt.Errorf(constants.ErrInvalidArguments)), nil
	}
	req, err := parsePromoteArgs(argsMap)
	if err != nil {
		return errorResult(err), nil
	}
	result, err := runPromote(ctx, req, telemetry.InterfaceMCP, mcpCaller(argsMap))
	if err != nil {
		return errorResult(err), nil
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return errorResult(err), nil
	}
	return mcp.NewToolResultText(string(encoded)), nil
}

func parsePromoteArgs(arguments map[string]any) (promote.Request, error) {
	confirmed, _ := arguments["user_confirmed"].(bool)
	overwrite, _ := arguments["overwrite"].(bool)
	ruleCode, err := requiredArg(arguments, "rule_code")
	if err != nil {
		return promote.Request{}, err
	}
	query, err := requiredArg(arguments, "tree_sitter_query")
	if err != nil {
		return promote.Request{}, err
	}
	language, err := requiredArg(arguments, "language")
	if err != nil {
		return promote.Request{}, err
	}
	ruleName, err := requiredArg(arguments, "rule_name")
	if err != nil {
		return promote.Request{}, err
	}
	req := promote.Request{
		UserConfirmed:   confirmed,
		Overwrite:       overwrite,
		RuleCode:        ruleCode,
		TreeSitterQuery: query,
		Language:        language,
		RuleName:        ruleName,
	}
	if name, ok := arguments["ruleset_name"].(string); ok {
		req.RulesetName = name
	}
	if text, ok := arguments["short_description"].(string); ok {
		req.ShortDescription = text
	}
	if text, ok := arguments["description"].(string); ok {
		req.Description = text
	}
	if raw, ok := arguments["tests"]; ok {
		tests, err := parseTestArgs(raw)
		if err != nil {
			return promote.Request{}, err
		}
		req.Tests = tests
	}
	return req, nil
}

func readOptionalFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("description file: %w", err)
	}
	return string(raw), nil
}

func readTestsFile(path string) ([]promote.Test, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tests file: %w", err)
	}
	var decoded []struct {
		Filename        string `json:"filename"`
		Code            string `json:"code"`
		AnnotationCount int    `json:"annotation_count"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("tests file: %w", err)
	}
	tests := make([]promote.Test, 0, len(decoded))
	for _, test := range decoded {
		tests = append(tests, promote.Test{
			Filename:        test.Filename,
			Code:            test.Code,
			AnnotationCount: test.AnnotationCount,
		})
	}
	return tests, nil
}

func parseTestArgs(raw any) ([]promote.Test, error) {
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("tests must be an array")
	}
	tests := make([]promote.Test, 0, len(items))
	for _, item := range items {
		fields, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("tests must be objects")
		}
		filename, _ := fields["filename"].(string)
		code, _ := fields["code"].(string)
		count, err := annotationCount(fields["annotation_count"])
		if err != nil {
			return nil, err
		}
		tests = append(tests, promote.Test{
			Filename:        filename,
			Code:            code,
			AnnotationCount: count,
		})
	}
	return tests, nil
}

func annotationCount(raw any) (int, error) {
	switch value := raw.(type) {
	case float64:
		if value < 0 || value != float64(int(value)) {
			return 0, fmt.Errorf("annotation_count must be a non-negative integer")
		}
		return int(value), nil
	case int:
		if value < 0 {
			return 0, fmt.Errorf("annotation_count must be a non-negative integer")
		}
		return value, nil
	default:
		return 0, fmt.Errorf("annotation_count must be a non-negative integer")
	}
}

func runPromote(ctx context.Context, req promote.Request, iface telemetry.Interface, caller telemetry.Caller) (promote.Result, error) {
	event := telemetry.OperationEvent{
		Interface: iface,
		Operation: "promote_sast_rule",
		StartedAt: time.Now(),
		Caller:    caller,
	}
	defer func() { trackOperation(ctx, event) }()

	method, err := preparePromoteAuth(ctx, iface)
	event.AuthMethod = method
	if err != nil {
		event.Failure = err
		return promote.Result{}, err
	}

	client := promote.NewClient(os.Getenv(constants.EnvAPIKey), os.Getenv(constants.EnvAPPKey), os.Getenv(constants.EnvSite))
	result, err := client.Save(ctx, req)
	if err != nil {
		event.Failure = err
		return promote.Result{}, err
	}
	return result, nil
}

// preparePromoteAuth resolves Datadog credentials the same way the other API
// calls do. Permanent keys in the environment win. Otherwise DD_AUTH_DOMAIN
// makes the server run dd-auth, which prints a short-lived DD_API_KEY and
// DD_APP_KEY. The HTTP call still sends those two headers.
func preparePromoteAuth(ctx context.Context, iface telemetry.Interface) (string, error) {
	if iface == telemetry.InterfaceMCP {
		if err := setAuthCredentials(ctx); err != nil {
			return detectAuthMethod(), authRequiredError(err)
		}
		if os.Getenv(constants.EnvAPIKey) == "" || os.Getenv(constants.EnvAPPKey) == "" {
			return detectAuthMethod(), promoteCredentialsError(iface)
		}
		return detectAuthMethod(), nil
	}

	method, err := auth.LoadAndApplyToEnv(ctx)
	if err != nil {
		return method, authRequiredError(err)
	}
	if os.Getenv(constants.EnvAPIKey) == "" || os.Getenv(constants.EnvAPPKey) == "" {
		return method, promoteCredentialsError(iface)
	}
	return method, nil
}

// promoteCredentialsError explains how to provide credentials where they are
// read: the MCP server env for MCP calls, the shell for the CLI.
func promoteCredentialsError(iface telemetry.Interface) error {
	if iface == telemetry.InterfaceMCP {
		return fmt.Errorf("%s.\n\n%s\n\n%s",
			constants.ErrPromoteCredentialsRequired,
			constants.AuthInstructionDDAuth,
			constants.AuthInstructionAPIKey)
	}
	return fmt.Errorf("%s.\n\n%s\n\n%s",
		constants.ErrPromoteCredentialsRequired,
		constants.AuthInstructionDDAuthShell,
		constants.AuthInstructionAPIKeyShell)
}
