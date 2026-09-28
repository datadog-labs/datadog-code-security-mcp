package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/spf13/cobra"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/constants"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/promote"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/telemetry"
)

func newPromoteSASTRuleCmd() *cobra.Command {
	var (
		codeFile    string
		queryFile   string
		language    string
		ruleName    string
		rulesetName string
		confirmed   bool
	)

	cmd := &cobra.Command{
		Use:   "promote-sast-rule",
		Short: "Save a caller-supplied SAST rule as a custom rule",
		Long: `Upload the exact JavaScript and tree-sitter query the caller supplies.
The command does not infer an invariant and does not edit the rule.
It requires --user-confirmed, plus DD_API_KEY and DD_APP_KEY.

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
			result, err := runPromote(cmd.Context(), promote.Request{
				UserConfirmed:   confirmed,
				RuleCode:        string(code),
				TreeSitterQuery: string(query),
				Language:        language,
				RuleName:        ruleName,
				RulesetName:     rulesetName,
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
	cmd.Flags().StringVar(&rulesetName, "ruleset-name", "", "Ruleset slug (default: variant-hunter)")
	cmd.Flags().BoolVar(&confirmed, "user-confirmed", false, "Required. The user has agreed to save this exact rule")
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
		RuleCode:        ruleCode,
		TreeSitterQuery: query,
		Language:        language,
		RuleName:        ruleName,
	}
	if name, ok := arguments["ruleset_name"].(string); ok {
		req.RulesetName = name
	}
	if text, ok := arguments["description"].(string); ok {
		req.Description = text
	}
	return req, nil
}

func runPromote(ctx context.Context, req promote.Request, iface telemetry.Interface, caller telemetry.Caller) (promote.Result, error) {
	event := telemetry.OperationEvent{
		Interface:  iface,
		Operation:  "promote_sast_rule",
		StartedAt:  time.Now(),
		AuthMethod: "api_key",
		Caller:     caller,
	}
	defer func() { trackOperation(ctx, event) }()

	client := promote.NewClient(os.Getenv(constants.EnvAPIKey), os.Getenv(constants.EnvAPPKey), os.Getenv(constants.EnvSite))
	result, err := client.Save(ctx, req)
	if err != nil {
		event.Failure = err
		return promote.Result{}, err
	}
	return result, nil
}
