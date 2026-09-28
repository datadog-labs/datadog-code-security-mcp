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
	"github.com/datadog-labs/datadog-code-security-mcp/internal/ephemeral"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/telemetry"
)

func newEphemeralScanCmd() *cobra.Command {
	var (
		codeFile  string
		queryFile string
		language  string
		directory string
		ruleName  string
		paths     []string
	)

	cmd := &cobra.Command{
		Use:   "ephemeral-scan",
		Short: "Run one local SAST rule without publishing it",
		Long: `Pack a JavaScript rule and a tree-sitter query into the scanner envelope
and run datadog-static-analyzer -r rules.json -b. No Datadog API key is required.
The caller supplies the rule source. This command does not infer it.

Example:
  datadog-code-security-mcp ephemeral-scan --called-by-skill \
    --language TYPESCRIPT --directory . \
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
			findings, err := runEphemeralScan(cmd.Context(), ephemeral.ScanRequest{
				Input: ephemeral.Input{
					RuleCode:        string(code),
					TreeSitterQuery: string(query),
					Language:        language,
					RuleName:        ruleName,
					Description:     "Ephemeral rule supplied by the caller",
				},
				Directory: directory,
				Paths:     paths,
			}, telemetry.InterfaceCLI, cliCaller())
			if err != nil {
				return err
			}
			fmt.Println(string(findings))
			return nil
		},
	}

	cmd.Flags().StringVar(&codeFile, "code-file", "", "Path to the rule JavaScript source")
	cmd.Flags().StringVar(&queryFile, "query-file", "", "Path to the tree-sitter query")
	cmd.Flags().StringVar(&language, "language", "", "Scanner language enum, for example TYPESCRIPT")
	cmd.Flags().StringVar(&directory, "directory", "", "Directory passed to the scanner -i flag (default: cwd)")
	cmd.Flags().StringVar(&ruleName, "rule-name", "", "Rule name inside the ephemeral ruleset")
	cmd.Flags().StringArrayVar(&paths, "path", nil, "Subdirectory to scan (repeatable). Omit to scan the whole directory")
	_ = cmd.MarkFlagRequired("code-file")
	_ = cmd.MarkFlagRequired("query-file")
	_ = cmd.MarkFlagRequired("language")
	return cmd
}

func handleEphemeralScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	argsMap, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return errorResult(fmt.Errorf(constants.ErrInvalidArguments)), nil
	}
	req, err := parseEphemeralArgs(argsMap)
	if err != nil {
		return errorResult(err), nil
	}
	findings, err := runEphemeralScan(ctx, req, telemetry.InterfaceMCP, mcpCaller(argsMap))
	if err != nil {
		return errorResult(err), nil
	}
	return mcp.NewToolResultText(string(findings)), nil
}

func parseEphemeralArgs(arguments map[string]any) (ephemeral.ScanRequest, error) {
	ruleCode, err := requiredArg(arguments, "rule_code")
	if err != nil {
		return ephemeral.ScanRequest{}, err
	}
	query, err := requiredArg(arguments, "tree_sitter_query")
	if err != nil {
		return ephemeral.ScanRequest{}, err
	}
	language, err := requiredArg(arguments, "language")
	if err != nil {
		return ephemeral.ScanRequest{}, err
	}
	req := ephemeral.ScanRequest{
		Input: ephemeral.Input{
			RuleCode:        ruleCode,
			TreeSitterQuery: query,
			Language:        language,
			Description:     "Ephemeral rule supplied by the caller",
		},
	}
	if directory, ok := arguments["directory"].(string); ok {
		req.Directory = directory
	}
	if name, ok := arguments["rule_name"].(string); ok {
		req.RuleName = name
	}
	if paths, ok := arguments["paths"].([]any); ok {
		for _, path := range paths {
			if s, ok := path.(string); ok {
				req.Paths = append(req.Paths, s)
			}
		}
	}
	return req, nil
}

func requiredArg(arguments map[string]any, key string) (string, error) {
	value, ok := arguments[key].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return value, nil
}

func runEphemeralScan(ctx context.Context, req ephemeral.ScanRequest, iface telemetry.Interface, caller telemetry.Caller) (json.RawMessage, error) {
	event := telemetry.OperationEvent{
		Interface:  iface,
		Operation:  "ephemeral_sast_scan",
		StartedAt:  time.Now(),
		AuthMethod: "none",
		Caller:     caller,
		ScanType:   "sast",
	}
	defer func() { trackOperation(ctx, event) }()

	result, err := ephemeral.Scan(ctx, req)
	if err != nil {
		event.Failure = err
		return nil, err
	}
	var findings []json.RawMessage
	if err := json.Unmarshal(result.Findings, &findings); err == nil {
		count := len(findings)
		event.FindingsCount = &count
	}
	return result.Findings, nil
}
