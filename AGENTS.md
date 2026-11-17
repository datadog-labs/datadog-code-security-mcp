# Agent Guidance for datadog-code-security-mcp

Guidance for AI coding agents (Claude Code, Codex, Cursor and others) working on this repository. `CLAUDE.md` only imports this file, so keep every instruction here.

## Project Overview

An MCP (Model Context Protocol) server that gives AI coding assistants local security scanning: SAST, Secrets, SCA (vulnerable dependencies), IaC and SBOM generation. It also works as a plain CLI.

- **Language**: Go (see `go.mod`, currently 1.25.5)
- **Build system**: Go modules and Makefile
- **Distribution**: Homebrew (`datadog-labs/pack`) and GitHub releases

**Key distinction**: this is a standalone tool that wraps Datadog security binaries (`datadog-static-analyzer`, `datadog-sbom-generator`, `datadog-security-cli`, `datadog-iac-scanner`). It does not implement the scanners itself.

## Essential Commands

```bash
# Build and development
make build          # Build to bin/datadog-code-security-mcp (injects version via ldflags)
make install        # Install the binary to $GOPATH/bin
make test           # Run tests with race detector and coverage
make lint           # Run golangci-lint (must be installed; CI uses v2.14.0)
make fmt            # Format code with gofmt/goimports
make clean          # Remove build artifacts
make mod            # Tidy and verify Go modules
make build-all      # Cross-platform binaries in dist/

# Run locally
go run ./cmd/datadog-code-security-mcp version
go run ./cmd/datadog-code-security-mcp scan all ./
go run ./cmd/datadog-code-security-mcp start  # MCP server mode
go run ./cmd/datadog-code-security-mcp setup --dry-run

# Test one package or one test
go test -v ./internal/auth/
go test -v -run TestName ./internal/scan/
```

## Project Structure

```
cmd/datadog-code-security-mcp/  # CLI entry point (Cobra)
  ├── main.go           # Cobra setup, routes to subcommands
  ├── start.go          # MCP server mode (STDIO transport), registers MCP tools
  ├── scan.go           # Direct scan CLI mode (no MCP)
  ├── setup.go          # Detects AI clients and installs embedded skills
  ├── generate-sbom.go  # SBOM generation CLI mode
  ├── ephemeral.go      # ephemeral-scan: run one unpublished SAST rule
  ├── promote.go        # promote-sast-rule: save an approved rule as a custom rule
  └── version.go        # Version info injected at build time via ldflags

internal/
  ├── types/            # Centralized type definitions
  │   ├── detection.go  # DetectionType constants (SAST, Secrets, SCA, IaC, SBOM)
  │   ├── severity.go   # Severity types and filtering logic
  │   └── types.go      # Shared types (Violation, ScanResult, ScanArgs, etc.)
  ├── scan/             # Core scan orchestration
  │   ├── scan.go                  # Main entry point, input validation, coordinates scanners
  │   ├── executor.go              # Parallel scan execution with goroutines, error aggregation
  │   ├── base_static_analyzer.go  # Template method pattern for SAST/Secrets scanners
  │   ├── sast.go                  # SAST scanner, configurable severity filter (LOW by default)
  │   ├── secrets.go               # Secrets scanner with confidence filtering
  │   ├── sca.go                   # SCA scanner (two-step: SBOM, then datadog-security-cli)
  │   └── types.go                 # Re-exports from internal/types for backward compatibility
  ├── processing/       # Result processing
  │   ├── sarif.go      # SARIF parser (static analyzer output)
  │   └── sca.go        # SCA result processing (CVE parsing, severity mapping)
  ├── sbom/             # SBOM generation (wraps datadog-sbom-generator); used standalone and by SCA
  ├── libraryscan/      # Library vulnerability scan by package URL (cloud API)
  ├── ephemeral/        # Local run of one caller-supplied SAST rule
  │   ├── ruleset.go    # Builds the ruleset JSON the analyzer reads with -r
  │   ├── run.go        # Runs the analyzer with --rules-with-config and validates paths
  │   ├── failures.go   # Reads rule failures from the analyzer's --debug output
  │   └── examples.go   # Checks a rule against its examples before it is saved
  ├── promote/          # Custom rule API client (ruleset, rule, revision)
  ├── setup/            # AI client detection and skill lifecycle
  │   ├── clients.go    # Declarative shared Agent Skills, Claude Code and Codex destination registry
  │   ├── detect.go     # Testable PATH and user-home marker detection
  │   ├── skills.go     # Recursive embedded-skill installation and marker-safe pruning
  │   └── setup.go      # Per-client plan-then-execute reconcile and structured results
  ├── binary/           # Binary discovery and execution
  │   ├── manager.go    # Binary naming conventions, PATH lookup, installation instructions
  │   ├── executor.go   # Command execution with timeout and context
  │   └── validation.go # Binary prerequisite validation (fail-fast checks)
  ├── auth/             # Authentication
  │   ├── config.go     # Load from DD_API_KEY, DD_APP_KEY, DD_SITE, DD_AUTH_DOMAIN
  │   └── provider.go   # Credential management with caching
  ├── telemetry/        # Anonymous usage telemetry (see Telemetry below)
  ├── update/           # Daily background check for a newer release; adds a notice to the MCP instructions
  └── constants/        # Shared constants (environment variable names, argument names)

skills/                         # Skills embedded into release binaries
  ├── embed.go                  # go:embed dd-codesec-* trees
  ├── dd-codesec-scan-and-fix/           # Scan/fix/verify workflow and domain playbooks
  ├── dd-codesec-verify-findings/        # Datadog platform enrichment workflow
  ├── dd-codesec-setup-toolchain/        # Scanner install, update and diagnosis guidance
  └── dd-codesec-find-security-variants/ # Variant search from an uncommitted security fix
```

## Architecture

### High-Level Flow

**SAST/Secrets scanning path:**

```
AI Assistant (Claude/Cursor/Codex)
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

**SCA scanning path (two steps):**

```
AI Assistant (Claude/Cursor/Codex)
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

**Standalone SBOM generation path:**

```
AI Assistant (Claude/Cursor/Codex)
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

SCA scanning generates an SBOM first (with `internal/sbom/generator.go`), then scans it for vulnerabilities with `datadog-security-cli`.

### Scanner Design

The codebase uses a **template method pattern** for scanners that share logic:

- **`BaseStaticAnalyzerScanner`** (`internal/scan/base_static_analyzer.go`)
  - Shared logic for SAST and Secrets (both use the `datadog-static-analyzer` binary)
  - Configurable via `ScannerConfig` (detection type, violation filters, parsing)
  - Handles binary execution, SARIF parsing and error handling
- **Specialized scanners** (extend the base or implement the `Scanner` interface)
  - `SASTScanner`: applies the requested severity threshold (LOW by default)
  - `SecretsScanner`: filters by confidence level
  - `SCAScanner`: uses a different binary (`datadog-security-cli`) and custom parsing

### Parallel Execution

`ExecuteParallelScans()` in `internal/scan/executor.go`:

- Launches scan types concurrently with goroutines, coordinated by `sync.WaitGroup`
- A buffered channel sized to the scan count keeps goroutines from blocking
- Failures in one scan do not block the others; partial results are returned when some scans succeed
- Propagates context for cancellation

```go
// Buffered channel ensures goroutines never block on send
results := make(chan scanResult, len(args.ScanTypes))

// Each scan runs independently
for _, scanType := range args.ScanTypes {
    wg.Add(1)
    go func(st string) {
        defer wg.Done()
        scanner := getScannerFor(st, binaryMgr)
        findings, err := scanner.Execute(ctx, args)
        results <- scanResult{st, findings, err}
    }(scanType)
}
```

### Binary Naming Convention System

The wrapped binaries use **different GitHub release naming conventions**:

- **Static Analyzer**: Rust target triple, for example `datadog-static-analyzer-aarch64-apple-darwin.zip` (pattern `{name}-{arch}-{platform-suffix}.zip`)
- **SBOM Generator**: simple Go convention, for example `datadog-sbom-generator_darwin_arm64.zip` (pattern `{name}_{os}_{arch}.zip`)

Implementation (`internal/binary/manager.go`):

1. `NamingConvention` enum: `rust-triple` vs `simple`
2. `BinaryConfig` specifies the convention per binary
3. `mapArchitecture()` is convention-aware (`x86_64`/`aarch64` for Rust, `amd64`/`arm64` for Go)
4. Filename generation uses the matching pattern

Validation (`internal/binary/validation.go`) checks prerequisites early in `scan.ExecuteScan()`, fails fast when a binary is missing, and returns platform-specific installation instructions.

**When adding a binary**: set its `NamingConvention` in `BinaryConfigs` and make sure `SupportedPlatforms` use the arch names of that convention.

### Managed Skills Contract

The root `skills/` package embeds every `dd-codesec-*` directory recursively. `internal/setup/` always installs those trees into the shared `~/.agents/skills/` directory, and also into the native Claude Code and Codex skill directories when those clients are detected.

Every installed skill root carries `.datadog-managed.json`. That marker, not the directory name, is the **only** authority for updates and deletion:

- Never overwrite an existing skill directory without a valid marker owned by `datadog-code-security-mcp`.
- Never prune by the `datadog-` name prefix.
- Skip dot-directories such as Codex's `.system/`.
- Prune only direct child directories marked as managed by `datadog-code-security-mcp`.
- Treat nested content such as `references/` as part of the marked skill tree.

## Code Patterns

### Adding New Detection Types

1. Add a constant to `internal/types/detection.go`: `DetectionTypeFoo DetectionType = "foo"`
2. Update `AllowedDetectionTypes()` in the same file
3. Create the scanner in `internal/scan/foo.go`:
   - **Static-analyzer scans**: extend `BaseStaticAnalyzerScanner` with a custom config
   - **Other binaries or logic**: implement the `Scanner` interface directly (`Execute(ctx context.Context, args ScanArgs) ([]types.Violation, error)`), handling binary execution, output parsing and errors
4. Register the scanner in `internal/scan/executor.go` → `getScannerFor()`
5. Add the CLI flag in `cmd/scan.go`
6. Add the MCP tool in `cmd/start.go` → `registerSecurityTools()`

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

**Example: configurable SAST severity threshold**

```go
args := ScanArgs{
    FilePaths:       []string{"./src"},
    MinSASTSeverity: types.SeverityHigh, // Omit for LOW and above.
}
```

### Adding MCP Tools

1. In `cmd/start.go` → `registerSecurityTools()`, register the tool with `addSkillTool(s, ...)` (it wraps `s.AddTool()`) and map its name to the owning skill in `toolSkills`; the start tests fail for a tool without a skill
2. Define the schema with `mcp.Tool{Name, Description, InputSchema}`
3. Create the handler: `func handleFoo(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)`
4. Parse arguments from `request.Params.Arguments`
5. Call `scan.ExecuteScan()` or the relevant function
6. Return `mcp.NewToolResultText()` or `mcp.NewToolResultError()`

### Security Validation

**Always validate user input**:

- Use `filepath.Clean()` on all paths from users or MCP
- Validate that paths are within the working directory (prevent traversal)
- Whitelist environment variables (see the regex checks in `internal/auth/config.go`, which validates `DD_SITE` against a whitelist)
- Never shell out with unsanitized input
- Create temp directories with secure mode (0700)

To fix an injection-style issue: identify the user input that becomes a path or command, add a validation function (whitelist over blacklist) with a regex check for invalid characters, and test it with malicious inputs.

## Testing Requirements

### Unit Tests

- Place tests next to source: `foo.go` → `foo_test.go`
- Use table-driven tests for multiple scenarios
- Test both success and error paths
- Mock external dependencies (scanner binaries, filesystem, network)
- Run with the race detector: `go test -race ./...`
- Coverage targets: 70%+ for new code, 90%+ for auth and scan logic (`go test -cover ./...`)

### E2E Tests

**Run E2E tests before pushing changes** so the full workflow works end to end with the scanners and the MCP protocol.

Prerequisites:

- Scanner binaries in `PATH` (see External Dependencies). On macOS, after `brew tap datadog-labs/pack`: `brew install datadog-static-analyzer` and `brew install --cask datadog-security-cli`. Otherwise use the installation instructions the CLI prints for a missing binary.
- Optional but recommended: `DD_API_KEY`, `DD_APP_KEY` and `DD_SITE` (or `DD_AUTH_DOMAIN`).
- For full mode only: the Claude Code CLI (`claude`).

```bash
# CI mode (headless); this is what GitHub Actions runs
./scripts/test-e2e.sh --ci

# Full mode (also configures the local build in Claude)
./scripts/test-e2e.sh --full
```

What the script tests:

1. Build verification
2. Binary detection (datadog-static-analyzer installed)
3. MCP protocol over STDIO (initialize, tools/list)
4. SAST scanner (SQL injection, XSS, path traversal)
5. Secrets scanner (AWS keys, GitHub tokens, API keys)
6. Negative testing (no false positives on clean code)
7. SBOM generation
8. Setup command (dry-run, installation and `--remove-skills` in an isolated home)
9. IaC scanner
10. Ephemeral SAST rule: runs `testdata/ephemeral/` without API keys; only that rule reports, and the config's ignored paths stay ignored (requires datadog-static-analyzer 0.9.10 or later)
11. Claude integration (full mode only)

CI runs the same script on every PR and push to `main` (`.github/workflows/e2e.yml`, Ubuntu and macOS), uploads test outputs as artifacts, and fails the PR if any step fails.

**Test fixtures** in `testdata/` give reproducible results without external dependencies:

```
testdata/
├── vulnerabilities/
│   ├── sast/      # sql-injection.go, xss.js, path-traversal.py
│   ├── secrets/   # aws-keys.py, github-token.js, api-key.env
│   ├── iac/       # Terraform (IAM, S3, security group), Kubernetes and Dockerfile misconfigurations
│   └── clean/     # safe-code.go: negative test, no findings expected
├── ephemeral/     # Working rule.js, query.scm and tests.json for the ephemeral SAST rule
└── sbom-test/     # Fixture project for SBOM and SCA (intentionally old dependencies)
```

See `testdata/README.md` for the expected detections. Scanner versions can change rule results; when rules improve, update the fixtures and `testdata/README.md`.

**Adding a test case**: add realistic vulnerable code under `testdata/vulnerabilities/<type>/`, document the expected detections in `testdata/README.md`, check it with `./bin/datadog-code-security-mcp scan <type> <file>`, extend `scripts/test-e2e.sh` when adding a scan type, then run `./scripts/test-e2e.sh --ci`.

**When E2E tests fail**: read the failing step's output, check the `/tmp/*-output.json` files, rerun the individual commands by hand, and check scanner versions and authentication.

### Testing Local Changes in an AI Client

Build the wrapper first, configure the client's MCP server to use that local binary, then exercise the MCP path as the primary skill interface. Use the CLI JSON path when testing the CLI fallback or when MCP is not registered.

```bash
make build   # or: make install
```

Claude Code:

```bash
claude mcp remove datadog-code-security
claude mcp add datadog-code-security \
  -e DD_API_KEY=<your-api-key> \
  -e DD_APP_KEY=<your-app-key> \
  -e DD_SITE=datadoghq.com \
  -- $(pwd)/bin/datadog-code-security-mcp start
claude mcp list | grep datadog-code-security
```

Claude Desktop, or any client with a JSON MCP config (`~/.claude/config.json`, Cursor's `mcp.json`):

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

Restart the client (or reconnect the server) to pick up the new configuration, then try prompts such as "Scan this directory for security vulnerabilities", "Check if there are any hardcoded secrets" or "Generate an SBOM for this project".

Direct CLI testing without MCP:

```bash
./bin/datadog-code-security-mcp scan all ./internal
./bin/datadog-code-security-mcp scan sast ./testdata/vulnerabilities/sast
./bin/datadog-code-security-mcp scan secrets ./testdata/vulnerabilities/secrets
./bin/datadog-code-security-mcp scan sast ./testdata/vulnerabilities/clean   # expect 0 findings
./bin/datadog-code-security-mcp generate-sbom . --json
```

### Prefer the Local MCP for Skill Workflows

For remediation and verification workflows, prefer the registered local Code Security MCP scan tools when they are available. Fall back to `datadog-code-security-mcp scan ... --json` only when those tools are missing or a tool call fails. The remote Datadog MCP is for platform context and does not replace a local scan.

The local MCP tools (Claude Code exposes them as `mcp__datadog-code-security__<tool>`):

- `datadog_code_security_scan`: comprehensive scan (SAST + Secrets + SCA + IaC)
- `datadog_sast_scan`: SAST only
- `datadog_secrets_scan`: Secrets only
- `datadog_sca_scan`: SCA only
- `datadog_iac_scan`: IaC only
- `datadog_generate_sbom`: generate an SBOM
- `datadog_library_vulnerability_scan`: scan specific libraries by package URL (cloud API)
- `datadog_ephemeral_sast_scan`: run one unpublished SAST rule (no API keys)
- `datadog_promote_sast_rule`: save an approved rule as a custom rule

## Authentication

- **API keys**: `DD_API_KEY`, `DD_APP_KEY`, `DD_SITE`; or `DD_AUTH_DOMAIN` to obtain credentials through dd-auth.
- **SBOM generation** works without authentication. SAST and Secrets need credentials to fetch rules from Datadog.
- All configuration lives in `internal/auth/`. `LoadConfig()` in `config.go` applies strict validation (whitelist for `DD_SITE`, regex checks for invalid characters); `Provider` caches credentials to avoid repeated auth calls.

## Telemetry

Anonymous usage telemetry lives in `internal/telemetry/` and is sent to the Datadog logs intake with a publicly embeddable client token (RUM-style, not a secret). See `docs/TELEMETRY.md` for the full privacy policy and what is and is not collected.

**Event model**: every scan emits one telemetry event per scan type. For multi-type runs (`scan all` / `datadog_code_security_scan`), an additional aggregate `code_security_scan` event is emitted, so `operation:iac_scan` counts all IaC executions directly, standalone or part of a batch. Typed event shaping lives in `internal/telemetry`; `scan.ScanOutcome` is the canonical source for per-scanner findings, durations and errors.

Key fields:

- `standalone` (bool): `true` for single-type invocations, `false` for per-scan events within a batch.
- `duration_ms`: per-scan wall time on per-scan events; total wall-clock time on the aggregate.
- `scan_durations_breakdown`: map of `{detType: ms}` on the aggregate event.
- `partial_errors_breakdown`: map of `{detType: errorKind}` on the aggregate event; kinds only, no raw messages.

**Privacy contract**: error telemetry includes a categorized kind and a hardcoded, path-free `error.message` description for Error Tracking: a per-kind default (`kindDescriptions`) or a more specific string for known sub-cases (optionally suffixed with the process exit code), never the raw error text. New known errors are added to `errorRules` in `internal/telemetry/event.go`. Stack traces are not collected. Scanner versions are collected once per process for both CLI and MCP and are not persisted. **Any telemetry field change must also update `README.md`, `docs/TELEMETRY.md` and the first-run notice.**

Environment variables:

- `DD_CODE_SECURITY_TELEMETRY_DISABLED=1`: disable telemetry
- `DO_NOT_TRACK=1`: disable telemetry (standard: https://consoledonottrack.com/)
- `DD_CODE_SECURITY_TELEMETRY_TOKEN=<token>`: runtime fallback for the client token (dev use; no rebuild needed)
- `DD_CODE_SECURITY_UPDATE_CHECK_DISABLED=1`: disable the MCP server's daily release check (`internal/update/`, cached in `~/.datadog-code-security-mcp/update-check.json`); the two telemetry opt-outs above also disable it

Build-time ldflags (set via CI secrets):

- `-X main.telemetryClientToken=<token>`: client token (set via `TELEMETRY_CLIENT_TOKEN` in CI)
- `-X main.telemetryEnv=production`: deployment env tag (default: `development`)

**Config file**: `~/.datadog-code-security-mcp/config.json` holds `install_id` (stable anonymous UUID), `telemetry_enabled` and `first_run_notice_shown`.

## Common Gotchas

1. **Binary not found**: binaries must be in `PATH`; `manager.go` generates installation instructions when one is missing.
2. **Naming conventions**: when adding or updating binaries, use the correct naming convention and arch names (see Binary Naming Convention System).
3. **MCP STDIO protocol**: the server talks over stdin/stdout. Never use `fmt.Println` in MCP mode; log with `fmt.Fprintf(os.Stderr, ...)`.
4. **Version injection**: version info is set at build time via `-ldflags`. Use `make build`, not `go build`, to get it.
5. **Context propagation**: always pass `context.Context` through the call chain; the binary executor respects cancellation.
6. **Path handling**: always use `filepath.Clean()` and validate that paths are within the working directory.

## Debugging Tips

```bash
# Scanner not working
which datadog-static-analyzer
datadog-static-analyzer -i . -f sarif --output /tmp/test.sarif
go run ./cmd/datadog-code-security-mcp scan all ./

# MCP server not responding: test the STDIO protocol directly
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | \
  ./bin/datadog-code-security-mcp start | jq '.result.tools'
```

If the server hangs or errors, check that the binary is built for the right architecture, that nothing writes to stdout, and that the JSON-RPC message is valid.

Client logs: Claude Desktop on macOS writes to `~/Library/Logs/Claude/mcp*.log`; on Linux, `~/.claude/logs/mcp*.log`.

## CI/CD and Releases

- `.github/workflows/ci.yml`: tests on Linux, macOS and Windows, plus lint, for all PRs
- `.github/workflows/e2e.yml`: E2E tests on Ubuntu and macOS
- `.github/workflows/release.yml`: builds cross-platform binaries with goreleaser (`.goreleaser.yaml`) when a `v*` tag is pushed

Before pushing:

```bash
make fmt
make lint
make test
./scripts/test-e2e.sh --ci
```

Also run a SAST and an SCA scan for vulnerabilities on your changes before pushing.

### Version Policy

- **v0.x.x**: pre-release, breaking changes allowed
- **v1.0.0**: stable API, semver rules apply
- **Patch (v1.0.x)**: bug fixes only
- **Minor (v1.x.0)**: new features, backward compatible
- **Major (vX.0.0)**: breaking changes

## External Dependencies

Required for scanning (discovered in `PATH`; if one is missing, installation instructions are generated for the platform and the binary's naming convention):

- `datadog-static-analyzer`: SAST and Secrets
- `datadog-sbom-generator`: SBOM generation and the first SCA step
- `datadog-security-cli`: SCA vulnerability matching
- `datadog-iac-scanner`: IaC

Go dependencies:

- `github.com/spf13/cobra`: CLI framework
- `github.com/mark3labs/mcp-go`: MCP protocol implementation
- `github.com/owenrumney/go-sarif/v2`: SARIF parsing

Update them with `go get -u ./...`, `go mod tidy`, then `make test`.

## Do NOT

- Add dependencies on internal Datadog repositories (this tool is standalone)
- Use `panic()` in production code (return errors instead)
- Skip input validation for paths or environment variables
- Use `fmt.Println` in MCP server mode (breaks the STDIO protocol)
- Commit credentials or API keys
- Use release candidate Go versions (`go.mod` must stay on a stable version)
- Create test files in the repository root (like `test_naming.go`) and leave them committed

## Do

- Use `filepath.Clean()` on all user-provided paths
- Return structured errors with context; wrap errors with `%w`
- Add tests for new functionality
- Follow Go conventions: `gofmt`, `goimports`
- Document complex functions
- Run a SAST and an SCA scan before pushing changes

## Getting Help

- **Code questions**: check existing patterns in the codebase
- **MCP protocol**: https://modelcontextprotocol.io/
- **Go conventions**: https://go.dev/doc/effective_go
