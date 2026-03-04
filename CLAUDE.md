# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

An MCP (Model Context Protocol) server providing local security scanning (SAST, Secrets, SBOM) to AI coding assistants. Written in Go, distributed via Homebrew and GitHub releases.

**Key Distinction**: This is a standalone tool that wraps Datadog security binaries (`datadog-static-analyzer` and `datadog-sbom-generator`)

## Essential Commands

```bash
# Build & Development
make build          # Build to bin/datadog-code-security-mcp
make test           # Run tests with race detector and coverage
make lint           # Run golangci-lint (must be installed)
make fmt            # Format code with gofmt/goimports
make clean          # Remove build artifacts
make mod            # Tidy and verify Go modules

# Run locally for testing
go run ./cmd/datadog-code-security-mcp version
go run ./cmd/datadog-code-security-mcp scan all ./
go run ./cmd/datadog-code-security-mcp start  # MCP server mode

# Test specific package
go test -v ./internal/auth/
go test -v -run TestName ./internal/scan/

# Release (creates binaries for all platforms)
make build-all      # Outputs to dist/
```

## Testing Local Changes

When working on a feature branch, test your changes with Claude Desktop before pushing:

### ⚠️ IMPORTANT: Prefer MCP Tools Over CLI

**When the user asks you to run scans or test functionality, ALWAYS use the MCP tools if available, NOT the CLI commands.** The MCP tools are the primary interface for this project and represent the actual user experience.

**Available MCP Tools (use these first):**
- `mcp__datadog-code-security__datadog_code_security_scan` - Comprehensive scan (SAST + Secrets + SCA)
- `mcp__datadog-code-security__datadog_sast_scan` - SAST only
- `mcp__datadog-code-security__datadog_secrets_scan` - Secrets only
- `mcp__datadog-code-security__datadog_sca_scan` - SCA only
- `mcp__datadog-code-security__datadog_generate_sbom` - Generate SBOM

**CLI Commands (for development/debugging only):**

Use CLI commands (`go run ./cmd/datadog-code-security-mcp ...`) ONLY when:
- Testing the CLI interface specifically
- Debugging binary execution issues
- MCP tools are not working or not available
- Running in CI/CD pipelines

**Example:**
- ❌ Wrong: `go run ./cmd/datadog-code-security-mcp scan all ./`
- ✅ Correct: Use `mcp__datadog-code-security__datadog_code_security_scan` tool

### Step 1: Build the binary

```bash
# Build to bin/ directory
make build

# Or install to $GOPATH/bin
make install
```

### Step 2: Configure Claude Desktop to use your local build

**Option A: Using Claude CLI**

```bash
# Remove existing MCP server if configured
claude mcp remove datadog-code-security

# Add using absolute path to your local binary
claude mcp add datadog-code-security \
  -e DD_API_KEY=<your-api-key> \
  -e DD_APP_KEY=<your-app-key> \
  -e DD_SITE=datadoghq.com \
  -- $(pwd)/bin/datadog-code-security-mcp start

# Verify configuration
claude mcp list | grep datadog-code-security
```

**Option B: Manually edit `~/.claude/config.json`**

```json
{
  "mcpServers": {
    "datadog-code-security": {
      "command": "/absolute/path/to/datadog-code-security-mcp/bin/datadog-code-security-mcp",
      "args": ["start"],
      "env": {
        "DD_API_KEY": "<your-api-key>",
        "DD_APP_KEY": "<your-app-key>",
        "DD_SITE": "datadoghq.com"
      }
    }
  }
}
```

### Step 3: Restart Claude Desktop

Quit and reopen Claude Desktop to pick up the new configuration.

### Step 4: Test your changes

In Claude Desktop, try prompts relevant to your changes:

```
# For SBOM changes
"Generate an SBOM for this project"
"What dependencies does this project have?"

# For SAST/Secrets changes
"Scan this directory for security vulnerabilities"
"Check if there are any hardcoded secrets"

# For general testing
"Scan this directory for vulnerabilities and dependencies"
```

### Step 5: Direct CLI testing (optional)

Test without MCP integration:

```bash
# Test SBOM generation
./bin/datadog-code-security-mcp generate-sbom .

# Test with JSON output
./bin/datadog-code-security-mcp generate-sbom . --json

# Test all scan types
./bin/datadog-code-security-mcp scan all ./internal

# Test SAST only
./bin/datadog-code-security-mcp scan sast ./cmd

# Test Secrets only
./bin/datadog-code-security-mcp scan secrets ./config
```

### Step 6: Check MCP server logs (if issues occur)

```bash
# macOS
tail -f ~/Library/Logs/Claude/mcp*.log

# Linux
tail -f ~/.claude/logs/mcp*.log
```

## Architecture

### High-Level Flow

**SAST/Secrets Scanning Path:**
```
AI Assistant (Claude/Cursor)
  ↓ STDIO (MCP Protocol)
cmd/start.go (MCP Server)
  ↓
internal/scan/scan.go (Orchestration)
  ↓
internal/scan/executor.go (Parallel Execution)
  ↓
Specialized Scanners (sast.go, secrets.go)
  ↓ extends
BaseStaticAnalyzerScanner (base_static_analyzer.go)
  ↓ shells out to
datadog-static-analyzer
  ↓ parses results via
internal/processing/sarif.go
  ↓
Returns []types.Violation
```

**SCA Scanning Path (Two-Step Process):**
```
AI Assistant (Claude/Cursor)
  ↓ STDIO (MCP Protocol)
cmd/start.go (MCP Server)
  ↓
internal/scan/scan.go (Orchestration)
  ↓
internal/scan/executor.go (Parallel Execution)
  ↓
internal/scan/sca.go (SCA Scanner)
  ↓ Step 1: Generate SBOM
internal/sbom/generator.go
  ↓ shells out to
datadog-sbom-generator
  ↓ writes to temp file
CycloneDX JSON file
  ↓ Step 2: Scan SBOM for vulnerabilities
datadog-security-cli sbom <file>
  ↓ parses results via
internal/processing/sca.go
  ↓
Returns []types.Violation
```

**Standalone SBOM Generation Path:**
```
AI Assistant (Claude/Cursor)
  ↓ STDIO (MCP Protocol)
cmd/start.go (MCP Server) or cmd/generate-sbom.go (CLI)
  ↓
internal/sbom/generator.go
  ↓ shells out to
datadog-sbom-generator
  ↓ parses CycloneDX JSON
internal/sbom/generator.go (internal parsing)
  ↓
Returns component list (name, version, license)
```

**Key Insight:** SCA scanning internally generates an SBOM first (using `internal/sbom/generator.go`), then scans it for vulnerabilities using `datadog-security-cli`.

### Key Components

**`cmd/datadog-code-security-mcp/`** - CLI entry point
- `main.go`: Cobra setup, routes to subcommands
- `start.go`: MCP server mode (STDIO transport), registers MCP tools
- `scan.go`: Direct scan CLI mode (no MCP)
- `generate-sbom.go`: SBOM generation CLI mode
- `version.go`: Version info injected at build time via ldflags

**`internal/types/`** - Centralized type definitions
- `detection.go`: `DetectionType` constants (SAST, Secrets, SCA, SBOM)
- `severity.go`: Severity types and filtering logic
- `types.go`: Shared types (`Violation`, `ScanResult`, `ScanArgs`, etc.)

**`internal/scan/`** - Core scan orchestration
- `scan.go`: Main entry point, input validation, coordinates scanners
- `executor.go`: **Parallel scan execution** with goroutines, error aggregation
- `base_static_analyzer.go`: **Template method pattern** for SAST/Secrets scanners
- `sast.go`: SAST scanner with severity filtering (extends base)
- `secrets.go`: Secrets scanner with confidence filtering (extends base)
- `sca.go`: **SCA scanner (two-step process)**:
  - Step 1: Calls `internal/sbom/generator.go` to generate SBOM
  - Step 2: Runs `datadog-security-cli` on SBOM to find vulnerabilities
- `types.go`: Re-exports from `internal/types` for backward compatibility

**`internal/processing/`** - Result processing
- `sarif.go`: SARIF parser (for static analyzer output)
- `sca.go`: SCA result processing (CVE parsing, severity mapping)

**`internal/sbom/`** - SBOM generation
- `generator.go`: Wraps datadog-sbom-generator binary
- `generator_test.go`: Unit tests for SBOM generation
- **Used by**: Both standalone SBOM generation and SCA scanner (internal step)

**`internal/binary/`** - Binary discovery and execution
- `manager.go`: **Binary Naming Convention System** (see below), PATH lookup, installation instructions
- `executor.go`: Command execution with timeout and context
- `validation.go`: Binary prerequisite validation (fail-fast checks)

**`internal/auth/`** - Authentication
- `config.go`: Load from `DD_API_KEY`, `DD_APP_KEY`, `DD_SITE`
- `provider.go`: Credential management with caching

### Binary Naming Convention System

The codebase supports multiple Datadog binaries with **different GitHub release naming conventions**:

- **Static Analyzer**: Uses Rust target triple format
  - Example: `datadog-static-analyzer-aarch64-apple-darwin.zip`
  - Pattern: `{name}-{arch}-{platform-suffix}.zip`

- **SBOM Generator**: Uses simple Go convention
  - Example: `datadog-sbom-generator_darwin_arm64.zip`
  - Pattern: `{name}_{os}_{arch}.zip`

**Implementation** (`internal/binary/manager.go`):
1. `NamingConvention` enum: `rust-triple` vs `simple`
2. `BinaryConfig` specifies convention per binary
3. `mapArchitecture()` is convention-aware (returns `x86_64`/`aarch64` for Rust, `amd64`/`arm64` for Go)
4. Filename generation conditionally uses correct pattern

**Validation** (`internal/binary/validation.go`):
- Binary validation logic validates prerequisites before scan execution
- Called early in `scan.ExecuteScan()` to fail fast if binaries are missing
- Provides platform-specific installation instructions when binaries not found

**When adding new binaries**: Specify the `NamingConvention` in `BinaryConfigs` and ensure `SupportedPlatforms` use the correct arch names for that convention.

## Code Patterns

### Adding New Detection Types

1. Add constant to `internal/types/detection.go`: `DetectionTypeFoo DetectionType = "foo"`
2. Update `AllowedDetectionTypes()` in same file
3. Create scanner implementation in `internal/scan/`:
   - **For static-analyzer scans**: Extend `BaseStaticAnalyzerScanner` with custom config
   - **For other binaries**: Implement `Scanner` interface directly in new file (e.g., `foo.go`)
4. Register scanner in `internal/scan/executor.go` → `getScannerFor()` switch statement
5. Add CLI flag in `cmd/scan.go`
6. Add MCP tool in `cmd/start.go` → `registerSecurityTools()`

**Example: Modular Scanner Pattern**
```go
// internal/scan/foo.go
func NewFooScanner(binMgr *binary.BinaryManager) Scanner {
    return &BaseStaticAnalyzerScanner{
        config: ScannerConfig{
            DetectionType: types.DetectionTypeFoo,
            FilterViolations: func(v types.Violation) bool {
                return v.Severity != types.SeverityLow
            },
        },
        binaryManager: binMgr,
    }
}
```

### Adding MCP Tools

1. In `cmd/start.go` → `registerSecurityTools()`, call `s.AddTool()`
2. Define tool schema with `mcp.Tool{Name, Description, InputSchema}`
3. Create handler: `func handleFoo(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)`
4. Parse arguments from `request.Params.Arguments`
5. Call `scan.ExecuteScan()` or relevant function
6. Return `mcp.NewToolResultText()` or `mcp.NewToolResultError()`

### Security Validation

**ALWAYS validate user input**:
- Use `filepath.Clean()` on all paths from users/MCP
- Validate paths are within working directory (prevent traversal)
- Whitelist environment variables (see `auth/config.go` regex patterns)
- Never shell out with unsanitized input
- Example: `internal/auth/config.go` has comprehensive input validation for `DD_SITE`

## Testing Requirements

- Place tests next to source: `foo.go` → `foo_test.go`
- Use table-driven tests for multiple scenarios
- Test both success and error paths
- Coverage target: 70%+ for new code, 90%+ for auth/scan logic
- Run with race detector: `go test -race ./...`
- Mock external dependencies (binaries, filesystem)

## Authentication

**API Keys**: Set `DD_API_KEY`, `DD_APP_KEY`, `DD_SITE`

**SBOM scanning** works without authentication. SAST/Secrets require credentials to fetch rules from Datadog.

Configuration is loaded in `internal/auth/config.go` with strict validation (whitelist for DD_SITE, regex checks for invalid characters).

## Common Gotchas

1. **Binary not found**: `manager.go` generates installation instructions when binary is missing. Binaries must be in PATH.

2. **Naming conventions**: When adding/updating binaries, ensure you use the correct naming convention and arch names. See "Binary Naming Convention System" above.

3. **MCP STDIO protocol**: Server communicates via stdin/stdout. DO NOT use `fmt.Println` for debugging in MCP mode (use `fmt.Fprintf(os.Stderr, ...)` instead).

4. **Version injection**: Version info is set at build time via `-ldflags`. Use `make build` (not `go build`) to get proper version info.

5. **Context propagation**: Always pass `context.Context` through the call chain. Binary executor respects context cancellation.

6. **Path handling**: Always use `filepath.Clean()` and validate paths are within the working directory. Never trust user input.

## CI/CD

- `.github/workflows/ci.yml`: Tests on Linux, macOS, Windows for all PRs
- `.github/workflows/release.yml`: Builds cross-platform binaries on tag push
- Release process documented in `docs/RELEASE.md`

## External Dependencies

**Required for scanning**:
- `datadog-static-analyzer` binary (SAST/Secrets)
- `datadog-sbom-generator` binary (SBOM)

Binaries are discovered in PATH. If not found, installation instructions are generated based on the platform and binary's naming convention.

**Go Dependencies**:
- `github.com/spf13/cobra` - CLI framework
- `github.com/mark3labs/mcp-go` - MCP protocol implementation
- `github.com/owenrumney/go-sarif/v2` - SARIF parsing

## Do NOT

- Add dependencies internal Datadog repositories
- Use `panic()` in production code (return errors instead)
- Skip input validation for paths or environment variables
- Use `fmt.Println` in MCP server mode (breaks STDIO protocol)
- Commit credentials or API keys
- Create test files in the root (like `test_naming.go`) and leave them committed

## Do

- Use `filepath.Clean()` on all user-provided paths
- Return structured errors with context
- Add tests for new functionality
- Use bazel (aliased to `bzl` per user's global CLAUDE.md) if needed
- Follow Go conventions: `gofmt`, `goimports`, error wrapping with `%w`
- Document complex functions
- Check AGENTS.md for additional development patterns
- Before pushing changes run a SAST, SCA scan for vulnerabilities
