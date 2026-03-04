package main

import (
	"fmt"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"

	"github.com/datadog-labs/datadog-code-security-mcp/internal/auth"
	"github.com/datadog-labs/datadog-code-security-mcp/internal/scan"
)

func newStartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the MCP server",
		Long: `Start the MCP server with STDIO transport for AI assistants.

This command starts a Model Context Protocol (MCP) server that communicates via
standard input/output. It's designed to be used with AI coding assistants like:
- Claude Desktop
- Cursor
- Zed
- Any MCP-compatible AI assistant

The server provides five security scanning tools:
1. datadog_code_security_scan - Run comprehensive security scan (SAST + Secrets + SCA)
2. datadog_sast_scan - Run SAST (Static Application Security Testing) only
3. datadog_secrets_scan - Run Secrets detection only
4. datadog_generate_sbom - Generate Software Bill of Materials (SBOM)
5. datadog_sca_scan - Run Software Composition Analysis (dependency vulnerability scanning)

Configuration:
Add to your Claude Desktop config (~/.claude/config.json):
{
  "mcpServers": {
    "datadog": {
      "command": "datadog-code-security-mcp",
      "args": ["start"]
    }
  }
}

Example Usage:
  datadog-code-security-mcp start

The server will run until terminated with Ctrl+C or SIGTERM.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer()
		},
	}

	return cmd
}

var authProvider *auth.Provider

func runServer() error {
	// Load authentication configuration
	authConfig, err := auth.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load auth config: %w", err)
	}

	// Create auth provider
	authProvider, err = auth.NewProvider(authConfig)
	if err != nil {
		return fmt.Errorf("failed to create auth provider: %w", err)
	}

	// Create MCP server
	s := server.NewMCPServer(
		"datadog-code-security-mcp",
		version,
		server.WithLogging(),
	)

	// Register security scanning tools
	registerSecurityTools(s)

	// Log startup info
	fmt.Fprintf(os.Stderr, "Starting Datadog Code Security MCP server v%s...\n", version)
	fmt.Fprintf(os.Stderr, "%s\n", authConfig.String())
	if !authConfig.IsConfigured() {
		fmt.Fprintf(os.Stderr, "Note: Running in local-only mode. Set DD_API_KEY/DD_APP_KEY or DD_AUTH_DOMAIN for cloud features.\n")
	}
	fmt.Fprintf(os.Stderr, "Server ready. Listening on STDIO...\n")

	// Start STDIO server (handles signal context internally)
	return server.ServeStdio(s)
}

func registerSecurityTools(s *server.MCPServer) {
	s.AddTool(
		mcp.Tool{
			Name:        "datadog_code_security_scan",
			Description: "Run comprehensive code security scan (SAST + Secrets detection + SCA vulnerability scanning) - scans in parallel for maximum performance",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]any{
					"file_paths": map[string]any{
						"type":        "array",
						"items":       map[string]string{"type": "string"},
						"description": "Array of file paths or directories to scan (relative to working_dir)",
					},
					"working_dir": map[string]any{
						"type":        "string",
						"description": "Base directory for resolving relative paths (defaults to current directory)",
					},
				},
				Required: []string{"file_paths"},
			},
		},
		handleCodeSecurityScan,
	)

	// Tool 2: SAST only
	s.AddTool(
		mcp.Tool{
			Name:        "datadog_sast_scan",
			Description: "Run SAST (Static Application Security Testing) scan only to detect security vulnerabilities in code",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]any{
					"file_paths": map[string]any{
						"type":        "array",
						"items":       map[string]string{"type": "string"},
						"description": "Array of file paths or directories to scan",
					},
					"working_dir": map[string]any{
						"type":        "string",
						"description": "Base directory for resolving relative paths",
					},
				},
				Required: []string{"file_paths"},
			},
		},
		handleSASTScan,
	)

	// Tool 3: Secrets only
	s.AddTool(
		mcp.Tool{
			Name:        "datadog_secrets_scan",
			Description: "Run secrets detection scan only to find hardcoded credentials, API keys, passwords, and tokens",
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]any{
					"file_paths": map[string]any{
						"type":        "array",
						"items":       map[string]string{"type": "string"},
						"description": "Array of file paths or directories to scan",
					},
					"working_dir": map[string]any{
						"type":        "string",
						"description": "Base directory for resolving relative paths",
					},
				},
				Required: []string{"file_paths"},
			},
		},
		handleSecretsScan,
	)

	// Tool 4: SBOM generation
	s.AddTool(
		mcp.Tool{
			Name: "datadog_generate_sbom",
			Description: fmt.Sprintf(`Generate a comprehensive Software Bill of Materials (SBOM) listing all software components, dependencies, versions, and licenses in a repository. Requires datadog-sbom-generator binary in PATH; if not found, returns step-by-step installation commands.

When to use: When asked to generate SBOM, list dependencies, audit components, check licenses, or inventory software packages.

Parameters:
• path (string, optional) - Path to repository or directory to analyze. Defaults to current directory. Must be a directory.
• working_dir (string, optional) - Base directory for the scan. Defaults to current directory.

Supported Package Managers:
%s

IMPORTANT: If the repository uses package managers NOT listed above, or if the tool returns 0 components, Claude should perform manual SBOM generation by:
1. Identifying lock files and manifests (package.json, requirements.txt, go.mod, pom.xml, Gemfile.lock, Cargo.lock, composer.lock, etc.)
2. Reading and parsing these files to extract dependencies
3. Creating a structured component list with names, versions, and package URLs (purl format)
4. Formatting results in the same structure as this tool would return

Output: Returns JSON with:
- Summary: Total components found, breakdown by language/package manager, license statistics
- Components: Detailed list with name, version, type, license, package URL (purl), and language

The tool automatically:
1. Detects system architecture (x86_64, aarch64, darwin, linux)
2. Checks if datadog-sbom-generator is installed
3. If not installed, provides OS-specific installation commands
4. Scans for supported package managers and generates CycloneDX 1.5 format SBOM

Installation process:
- Downloads latest release from GitHub (DataDog/datadog-sbom-generator)
- Installs to ~/.local/bin (no sudo required)
- Updates PATH if needed
- Verifies installation`, scan.SupportedPackageManagers),
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Path to repository or directory to analyze (defaults to current directory)",
					},
					"working_dir": map[string]any{
						"type":        "string",
						"description": "Base directory for the scan (defaults to current directory)",
					},
				},
				Required: []string{},
			},
		},
		handleGenerateSBOM,
	)

	// Tool 5: SCA (Software Composition Analysis)
	s.AddTool(
		mcp.Tool{
			Name: "datadog_sca_scan",
			Description: `Run Software Composition Analysis to detect vulnerabilities in dependencies.

Takes directories as input, automatically generates SBOM, then scans for known CVEs using datadog-security-cli.

Parameters:
• file_paths (array, required) - Directories to scan for dependencies
• working_dir (string, optional) - Base directory for resolving paths

Output: Returns vulnerabilities with CVE ID, severity, component, version, description.

The tool automatically:
1. Generates SBOM from specified directories
2. Converts to CycloneDX format
3. Scans SBOM for known vulnerabilities using Datadog's vulnerability database
4. Returns comprehensive vulnerability report

Works just like SAST/Secrets - same interface, runs in parallel with other scans.`,
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]any{
					"file_paths": map[string]any{
						"type":        "array",
						"items":       map[string]string{"type": "string"},
						"description": "Array of file paths or directories to scan",
					},
					"working_dir": map[string]any{
						"type":        "string",
						"description": "Base directory for resolving relative paths",
					},
				},
				Required: []string{"file_paths"},
			},
		},
		handleSCAScan,
	)
}
