# Agent Guidance for datadog-code-security-mcp

Quick reference for AI coding assistants working on this codebase.

## Project Overview

**What**: MCP server providing local security scanning (SAST + Secrets) to AI assistants
**Language**: Go (requires 1.22+)
**Build System**: Go modules + Makefile
**Distribution**: Homebrew, GitHub releases, Docker

## Essential Commands

### Build & Test
```bash
make build          # Build binary → bin/datadog-code-security-mcp
make test           # Run all tests with race detector
make lint           # Run golangci-lint
make clean          # Remove build artifacts
```

### Development
```bash
go run ./cmd/datadog-code-security-mcp version
go run ./cmd/datadog-code-security-mcp scan all ./
go run ./cmd/datadog-code-security-mcp start  # MCP server mode
```

### Release
```bash
make build-all      # Build for all 5 platforms → dist/
# See docs/RELEASE.md for full process
```

## Project Structure

```
cmd/datadog-code-security-mcp/  # CLI entry point (Cobra)
  ├── main.go         # Setup & router
  ├── scan.go         # Direct scan command
  ├── start.go        # MCP server (STDIO transport)
  ├── generate-sbom.go # SBOM generation command
  └── version.go      # Version info

internal/
  ├── types/          # Centralized type definitions
  │   ├── detection.go # DetectionType constants (SAST, Secrets, SCA, SBOM)
  │   ├── severity.go  # Severity types and filtering
  │   └── types.go     # Shared types (Violation, ScanResult, etc.)
  ├── scan/           # Core orchestration & scanners
  │   ├── scan.go              # Main entry point, input validation
  │   ├── executor.go          # Parallel scan execution with goroutines
  │   ├── base_static_analyzer.go  # Template method pattern for SAST/Secrets
  │   ├── sast.go              # SAST scanner (extends base with severity filtering)
  │   ├── secrets.go           # Secrets scanner (extends base with confidence filtering)
  │   ├── sca.go               # SCA scanner (dependency vulnerabilities)
  │   └── types.go             # Re-exports from internal/types
  ├── processing/     # Result processing
  │   ├── sarif.go    # SARIF parser (for static analyzer output)
  │   └── sca.go      # SCA result processing
  ├── sbom/           # SBOM generation
  │   ├── generator.go      # Wraps datadog-sbom-generator
  │   └── generator_test.go
  ├── binary/         # Binary discovery & execution
  │   ├── manager.go      # Binary naming conventions, PATH lookup
  │   ├── executor.go     # Command execution with timeout
  │   └── validation.go   # Binary prerequisite validation
  └── auth/           # Authentication (API keys)
      ├── config.go   # Load from environment (DD_API_KEY, DD_SITE, etc.)
      └── provider.go # Credential management with caching
```

## Code Patterns

### Adding New Scan Types
1. Add constant to `internal/types/detection.go`: `DetectionTypeFoo DetectionType = "foo"`
2. Update `AllowedDetectionTypes()` in same file
3. Create scanner in `internal/scan/foo.go`:
   - For static-analyzer scans: Extend `BaseStaticAnalyzerScanner` with custom config
   - For other scans: Implement `Scanner` interface directly
4. Register scanner in `internal/scan/executor.go` → `getScannerFor()` switch statement
5. Add CLI flag in `cmd/scan.go`
6. Add MCP tool in `cmd/start.go` → `registerSecurityTools()`

**Example: SAST vs Secrets (both use BaseStaticAnalyzerScanner)**
```go
// SAST scanner with severity filtering
func NewSASTScanner(binMgr *binary.BinaryManager) Scanner {
    return &BaseStaticAnalyzerScanner{
        config: ScannerConfig{
            DetectionType: types.DetectionTypeSAST,
            FilterViolations: func(v types.Violation) bool {
                return v.Severity != types.SeverityLow
            },
        },
        binaryManager: binMgr,
    }
}
```

### Adding MCP Tools
1. Add tool definition in `cmd/start.go` → `registerSecurityTools()`
2. Create handler function: `func handle...(ctx, request) (*mcp.CallToolResult, error)`
3. Parse arguments and call `scan.ExecuteScan()` or relevant function
4. Format results as `mcp.CallToolResult`

## Scanner Architecture

### Modular Design
The codebase uses a **template method pattern** for scanners that share common logic:

- **`BaseStaticAnalyzerScanner`** (in `internal/scan/base_static_analyzer.go`)
  - Shared logic for SAST and Secrets (both use datadog-static-analyzer binary)
  - Configurable via `ScannerConfig` (detection type, violation filters, parsing)
  - Handles: binary execution, SARIF parsing, error handling

- **Specialized Scanners** (extend base or implement Scanner interface)
  - `SASTScanner` - Filters out low-severity findings
  - `SecretsScanner` - Filters by confidence level
  - `SCAScanner` - Uses different binary (datadog-security-cli), custom parsing

### Parallel Execution
**`ExecuteParallelScans()`** in `internal/scan/executor.go`:
- Launches multiple scan types concurrently using goroutines
- Coordinated with `sync.WaitGroup` for completion tracking
- Buffered channel sized to scan count prevents goroutine blocking
- **Resilient design**: Failures in one scan don't block others
- Returns partial results if some scans succeed (graceful degradation)
- Context propagation for cancellation

**Goroutine Safety:**
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

### Creating a New Scanner

**Option 1: Extend BaseStaticAnalyzerScanner** (for static-analyzer binary)
1. Create `internal/scan/newscan.go`
2. Define scanner config with custom filtering:
```go
func NewNewScanner(binMgr *binary.BinaryManager) Scanner {
    return &BaseStaticAnalyzerScanner{
        config: ScannerConfig{
            DetectionType: types.DetectionTypeNew,
            FilterViolations: func(v types.Violation) bool {
                return v.Severity == types.SeverityHigh
            },
        },
        binaryManager: binMgr,
    }
}
```
3. Register in `executor.go` → `getScannerFor()`

**Option 2: Implement Scanner Interface** (for custom binaries/logic)
1. Create `internal/scan/newscan.go`
2. Implement: `Execute(ctx context.Context, args ScanArgs) ([]types.Violation, error)`
3. Handle binary execution, output parsing, error handling
4. Register in `executor.go` → `getScannerFor()`

### Security Validation
- **Always** validate user input (paths, scan types)
- Use `filepath.Clean()` for path sanitization
- Check paths are within working directory (prevent traversal)
- Validate environment variables (see `auth/config.go` for example)
- Create temp directories with secure mode (0700)

## Testing Requirements

### Unit Tests
- Place next to source: `foo.go` → `foo_test.go`
- Use table-driven tests for multiple scenarios
- Test both success and error paths
- Mock external dependencies (scanner binary, filesystem)

### Coverage Targets
- New code: aim for 70%+ coverage
- Critical paths (auth, scan logic): 90%+ coverage
- Run: `go test -cover ./...`

### Integration Tests
- Add to `scripts/test-e2e.sh`
- Test full scan workflow end-to-end
- Verify MCP server startup and tool listing
- Test with real datadog-static-analyzer binary

## E2E Testing Workflow

**IMPORTANT:** Always run E2E tests before pushing changes to ensure the full workflow works end-to-end with the scanners and MCP protocol.

### Prerequisites

**1. Claude CLI installed (for full mode):**
```bash
# Install Claude CLI if not present
brew install anthropics/claude/claude

# Verify installation
claude --version
```

**2. Scanner binaries installed:**
```bash
# macOS
brew tap datadog/tap
brew install datadog-static-analyzer

# Linux
# See installation instructions in scripts/test-e2e.sh error output
# or visit https://github.com/DataDog/datadog-static-analyzer

# Verify installation
datadog-static-analyzer --version
```

**3. Authentication configured (optional but recommended):**
```bash
export DD_API_KEY=your-api-key
export DD_APP_KEY=your-app-key
export DD_SITE=datadoghq.com
```

### Running E2E Tests

**Option 1: Automated Script (Recommended)**

```bash
# CI mode (headless, no Claude Desktop required)
# This is what runs in GitHub Actions
./scripts/test-e2e.sh --ci

# Full mode (includes Claude Desktop integration)
./scripts/test-e2e.sh --full
```

**What the E2E script tests:**
1. ✅ **Build verification** - Compiles MCP server binary
2. ✅ **Binary detection** - Verifies datadog-static-analyzer is installed
3. ✅ **MCP protocol** - Tests STDIO communication (initialize, tools/list)
4. ✅ **SAST scanner** - Detects SQL injection, XSS, path traversal
5. ✅ **Secrets scanner** - Detects AWS keys, GitHub tokens, API keys
6. ✅ **Negative testing** - Verifies no false positives on clean code
7. ✅ **Claude Desktop** - Configures local build (full mode only)

**Option 2: Manual Step-by-Step Testing**

```bash
# 1. Build local MCP server
make clean
make build

# 2. Verify build
ls -lh bin/datadog-code-security-mcp
./bin/datadog-code-security-mcp version

# 3. Test MCP protocol directly
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | \
  ./bin/datadog-code-security-mcp start | jq '.result.tools'

# 4. Test individual scan types with fixtures
./bin/datadog-code-security-mcp scan sast ./testdata/vulnerabilities/sast
./bin/datadog-code-security-mcp scan secrets ./testdata/vulnerabilities/secrets

# 5. Test negative case (should find 0 vulnerabilities)
./bin/datadog-code-security-mcp scan sast ./testdata/vulnerabilities/clean

# 6. Configure Claude Desktop
claude mcp remove datadog-code-security 2>/dev/null || true
claude mcp add datadog-code-security \
  -e DD_API_KEY=your-api-key \
  -e DD_APP_KEY=your-app-key \
  -e DD_SITE=datadoghq.com \
  -- $(pwd)/bin/datadog-code-security-mcp start

# 7. Restart Claude Desktop
killall Claude && open -a Claude

# 8. Test in Claude Desktop with prompts like:
#    - "List available security scanning tools"
#    - "Scan testdata/vulnerabilities/sast for security issues"
#    - "Check testdata/vulnerabilities/secrets for hardcoded credentials"
```

### Test Fixtures

Test fixtures in `testdata/` provide reproducible security testing without external dependencies.

**Directory structure:**
```
testdata/
├── vulnerabilities/
│   ├── sast/            # SAST test cases
│   │   ├── sql-injection.go     # SQL injection in Go
│   │   ├── xss.js               # XSS in JavaScript
│   │   └── path-traversal.py    # Path traversal in Python
│   ├── secrets/         # Secrets test cases
│   │   ├── aws-keys.py          # AWS credentials
│   │   ├── github-token.js      # GitHub tokens
│   │   └── api-key.env          # Generic API keys
│   └── clean/           # Negative tests
│       └── safe-code.go         # No vulnerabilities expected
└── expected-results/    # Documentation of expected findings
```

**Expected detections:**

| Test File | Expected Finding | Severity | Count |
|-----------|------------------|----------|-------|
| `sast/sql-injection.go` | SQL injection | High | 2-3 |
| `sast/xss.js` | Cross-Site Scripting | High | 5-7 |
| `sast/path-traversal.py` | Path traversal | High | 5-6 |
| `secrets/aws-keys.py` | AWS credentials | High | 7-10 |
| `secrets/github-token.js` | GitHub tokens | High | 10-15 |
| `secrets/api-key.env` | Various secrets | High/Med | 20-30 |
| `clean/safe-code.go` | None (negative test) | - | 0 |

See `testdata/README.md` and `testdata/expected-results/README.md` for detailed expectations.

### Example: Testing SAST Scanner

```bash
# Run SAST scanner on test fixtures
./bin/datadog-code-security-mcp scan sast ./testdata/vulnerabilities/sast

# Expected output (example):
# ✗ High: SQL injection vulnerability detected
#   File: testdata/vulnerabilities/sast/sql-injection.go:15:2
#   Rule: go-security/sql-injection
#   Message: User input concatenated directly into SQL query
#
# ✗ High: Cross-site scripting (XSS) vulnerability
#   File: testdata/vulnerabilities/sast/xss.js:9:5
#   Rule: javascript/xss-innerhtml
#   Message: User input assigned to innerHTML without sanitization
#
# Summary: 8 vulnerabilities found (7 High, 1 Medium)
```

### Example: Testing Secrets Scanner

```bash
# Run Secrets scanner on test fixtures
./bin/datadog-code-security-mcp scan secrets ./testdata/vulnerabilities/secrets

# Expected output (example):
# ✗ High: AWS Access Key ID
#   File: testdata/vulnerabilities/secrets/aws-keys.py:11
#   Pattern: AKIAIOSFODNN7EXAMPLE
#
# ✗ High: GitHub Personal Access Token
#   File: testdata/vulnerabilities/secrets/github-token.js:7
#   Pattern: ghp_****
#
# ✗ High: Generic API Key
#   File: testdata/vulnerabilities/secrets/api-key.env:4
#
# Summary: 25 secrets found (23 High, 2 Medium)
```

### Troubleshooting E2E Tests

**Binary not found errors:**
```bash
# Check if scanner is installed
which datadog-static-analyzer

# Install missing binaries
# macOS:
brew install datadog/tap/datadog-static-analyzer

# Linux:
# See installation instructions in test output
```

**Claude Desktop not picking up changes:**
```bash
# Verify configuration
claude mcp list | grep datadog-code-security

# Should show:
# datadog-code-security
#   command: /absolute/path/to/bin/datadog-code-security-mcp
#   args: ["start"]

# Restart Claude Desktop after config changes
killall "Claude"
open -a "Claude"

# Check server logs
tail -f ~/Library/Logs/Claude/mcp*.log
```

**MCP server not responding:**
```bash
# Test STDIO protocol directly
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | \
  ./bin/datadog-code-security-mcp start

# Should return JSON with tools list
# If it hangs or errors, check:
#   - Binary is compiled for correct architecture
#   - No stdout pollution (must use stderr for logging in MCP mode)
#   - JSON-RPC message is valid
```

**No vulnerabilities detected in test fixtures:**
```bash
# Verify binaries are working
datadog-static-analyzer --version

# Check authentication (some rules require internet access)
echo $DD_API_KEY      # Should be set

# Test with a known vulnerable pattern
echo "query := \"SELECT * FROM users WHERE id = '\" + userID + \"'\"" > /tmp/test.go
./bin/datadog-code-security-mcp scan sast /tmp/test.go

# If still no detection, scanner may need rule updates
```

**Different findings than expected:**
```bash
# Scanner versions may have different rules - this is normal
datadog-static-analyzer --version > test-scanner-version.txt

# Document your version in test output
# Update testdata/expected-results/README.md if rules have improved
```

**False positives in clean code:**
```bash
# Review the finding - may indicate new detection rule
./bin/datadog-code-security-mcp scan sast ./testdata/vulnerabilities/clean --json

# If genuine false positive:
#   1. Report to Datadog scanner team
#   2. Update clean/safe-code.go to demonstrate safe pattern more clearly
#   3. Document in testdata/expected-results/README.md
```

### CI/CD Integration

E2E tests run automatically in GitHub Actions on every PR and push to main.

**Workflow:** `.github/workflows/e2e.yml`

**What it does:**
- Runs on Ubuntu and macOS
- Installs datadog-static-analyzer binary
- Builds MCP server from source
- Runs `./scripts/test-e2e.sh --ci`
- Uploads test outputs as artifacts
- Fails PR if any E2E test fails

**Viewing CI results:**
1. Go to PR → "Checks" tab → "E2E Tests"
2. Expand matrix job (Ubuntu or macOS)
3. Review step outputs
4. Download artifacts if tests failed (test outputs saved as JSON)

**Local pre-commit check:**
```bash
# Run same tests that CI runs
./scripts/test-e2e.sh --ci

# Should complete in 1-2 minutes
# Exit code 0 = all tests passed
# Exit code 1 = tests failed (review output)
```

### Adding New Test Cases

When adding new vulnerability detection or scanner features:

**1. Create test fixture:**
```bash
# For SAST vulnerabilities
touch testdata/vulnerabilities/sast/new-vulnerability.{ext}

# For Secrets
touch testdata/vulnerabilities/secrets/new-secret-type.{ext}
```

**2. Add realistic vulnerable code:**
```go
// Example: Command injection vulnerability
package main
import "os/exec"

func runCommand(userInput string) error {
    // VULNERABLE: Command injection
    cmd := exec.Command("sh", "-c", "echo " + userInput)
    return cmd.Run()
}
```

**3. Document expected behavior:**
```bash
# Update testdata/README.md with:
#   - File name and description
#   - Expected detections
#   - Severity and rule ID

# Update testdata/expected-results/README.md with:
#   - Expected findings count
#   - Sample output
```

**4. Test detection:**
```bash
./bin/datadog-code-security-mcp scan sast ./testdata/vulnerabilities/sast/new-vulnerability.go

# Verify it detects the vulnerability
```

**5. Update E2E script if needed:**
```bash
# If adding new scan type, update scripts/test-e2e.sh
# Add detection checks similar to existing ones
```

**6. Run full E2E suite:**
```bash
./scripts/test-e2e.sh --ci

# Should pass with new test case
```

### Best Practices

**Before pushing code:**
1. ✅ Run `./scripts/test-e2e.sh --ci` locally
2. ✅ Verify all 7 test steps pass
3. ✅ Check test outputs in `/tmp/*-output.json`
4. ✅ Test with Claude Desktop (`--full` mode) for MCP changes
5. ✅ Review any warnings in test output

**When tests fail:**
1. 🔍 Review test output for specific error
2. 🔍 Check `/tmp/*-output.json` files for details
3. 🔍 Run individual test commands manually
4. 🔍 Verify binary versions match expectations
5. 🔍 Check authentication is configured if needed

**Maintaining test fixtures:**
- Keep patterns realistic (use actual vulnerability patterns)
- Update when scanner rules improve
- Add variety (different variations of same vulnerability type)
- Document changes in `testdata/expected-results/README.md`
- Test after updates: `./scripts/test-e2e.sh --ci`

## Common Tasks

### Fixing Security Issues
```bash
# Example: Path injection vulnerability
# 1. Identify user input that becomes a path/command
# 2. Add validation function (whitelist > blacklist)
# 3. Add regex check for invalid characters
# 4. Test with malicious inputs in test file
# See internal/auth/config.go for reference
```

### Adding Authentication Support
```bash
# All auth config in internal/auth/
# Load from environment: DD_API_KEY, DD_APP_KEY, DD_SITE
# Validate in LoadConfig(), use whitelist for DD_SITE
# Cache credentials in Provider to avoid repeated auth calls
```

### Updating Dependencies
```bash
go get -u ./...       # Update all deps
go mod tidy           # Clean up
make test             # Verify nothing broke
```

## CI/CD

### GitHub Actions Workflows
- `.github/workflows/ci.yml` - Test on push/PR (Linux, macOS, Windows)
- `.github/workflows/release.yml` - Build binaries on tag push

### Pre-commit Checks
```bash
make fmt              # Format code
make lint             # Lint check
make test             # Run tests
```

## External Dependencies

### Required for Scanning
- `datadog-static-analyzer` binary in PATH
  - Auto-downloaded: Not yet implemented (v0.1.0)
  - Manual install: Instructions in `binary/manager.go`

### Go Dependencies
- `github.com/spf13/cobra` - CLI framework
- `github.com/owenrumney/go-sarif` - SARIF parsing
- `github.com/mark3labs/mcp-go` - MCP protocol

## Debugging Tips

### Scanner Not Working
```bash
# Check if binary exists
which datadog-static-analyzer

# Test scanner directly
datadog-static-analyzer -i . -f sarif --output /tmp/test.sarif

# Check our wrapper
go run ./cmd/datadog-code-security-mcp scan all ./ --verbose
```

### MCP Server Issues
```bash
# Test STDIO protocol manually
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | \
  go run ./cmd/datadog-code-security-mcp start

# Check Claude Desktop logs
# macOS: ~/Library/Logs/Claude/mcp*.log
# Linux: ~/.claude/logs/mcp*.log
```

## Important Notes

### Do NOT
- ❌ Add dependencies on dd-source (this is standalone)
- ❌ Use `panic()` in production code (return errors)
- ❌ Skip input validation for user-provided paths
- ❌ Commit credentials or API keys
- ❌ Use release candidate Go versions (go.mod should be stable)

### Do
- ✅ Add tests for new functionality
- ✅ Use `filepath.Clean()` on all user paths
- ✅ Return structured errors with context
- ✅ Document complex functions
- ✅ Follow Go conventions (gofmt, goimports)

## Version Policy

- **v0.x.x**: Pre-release, breaking changes allowed
- **v1.0.0**: Stable API, semver rules apply
- **Patch (v1.0.x)**: Bug fixes only
- **Minor (v1.x.0)**: New features, backward compatible
- **Major (vX.0.0)**: Breaking changes

## Getting Help

- **Code questions**: Check existing patterns in codebase
- **MCP protocol**: https://modelcontextprotocol.io/
- **Go conventions**: https://go.dev/doc/effective_go
- **Release process**: docs/RELEASE.md
