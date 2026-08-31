# Datadog Code Security MCP

Datadog Code Security MCP provides all Code Security scan tools to AI coding assistants like Claude Desktop, Cursor, etc - Can also be used as a CLI tool.

> **Note:** The Datadog Code Security MCP server is currently in Preview

### Available MCP Tools

1. **`datadog_code_security_scan`** - SAST + Secrets + SCA + IAC in parallel
2. **`datadog_sast_scan`** - Static Application Security Testing only
3. **`datadog_secrets_scan`** - Secrets detection only
4. **`datadog_sca_scan`** - Software Composition Analysis (dependency vulnerabilities)
5. **`datadog_iac_scan`** - Infrastructure as code scanning
6. **`datadog_generate_sbom`** - Generate Software Bill of Materials (SBOM)

## Quick Start

### Installation

**Homebrew (Recommended):**

```bash
brew tap datadog-labs/pack
brew update
brew install datadog-labs/pack/datadog-code-security-mcp
```

**Alternative: Download from GitHub Releases**

```bash
# macOS / Linux (auto-detects platform)
curl -L "https://github.com/datadog-labs/datadog-code-security-mcp/releases/latest/download/datadog-code-security-mcp-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m).tar.gz" | tar xz
sudo install -m 755 datadog-code-security-mcp /usr/local/bin/
```

**Verify installation:**

```bash
datadog-code-security-mcp version
datadog-code-security-mcp version --detailed # Include every required scanner
```

### Install AI Client Skills

The binary ships three skills for Claude Code, Cursor, and Codex:

- **Remediation** — scans local code, loads a focused SAST, Secrets, SCA, or
  IaC playbook, applies approved fixes, and rescans to verify them.
- **Verification** — enriches a current local finding with Datadog platform
  context when a Datadog MCP server is available.
- **Toolchain** — diagnoses missing scanner binaries and relays the CLI's
  platform-specific installation instructions with confirmation guardrails.

Install them for every detected client:

```bash
datadog-code-security-mcp setup
```

Useful options:

```bash
# Preview without writing files
datadog-code-security-mcp setup --dry-run

# Restrict setup to one or more clients
datadog-code-security-mcp setup --client cursor --client codex

# Remove only skills managed by this binary
datadog-code-security-mcp setup --remove-skills

# Remove Datadog skills from Cursor only
datadog-code-security-mcp setup --client cursor --remove-skills

# Machine-readable report
datadog-code-security-mcp setup --json
```

Setup detects `claude`, `cursor`/`cursor-agent`, and `codex` on `PATH`, plus
their user configuration directories. It installs into `~/.claude/skills`,
`~/.cursor/skills`, and `~/.codex/skills`, then asks you to restart updated
clients. The accepted `--client` IDs are `claude-code`, `cursor`, and `codex`.

The skills prefer the structured local Code Security MCP tools when available
and fall back to `datadog-code-security-mcp ... --json`, so skill installation
does not require MCP registration. Setup does not modify MCP configuration.

The remediation skill never scans after every edit. It runs when explicitly
asked or when verifying a backend finding; after a task changes security-
relevant files it offers one changed-file scan and waits for confirmation.

**⚠️ Requirements:**

The MCP server requires external Datadog security binaries to perform scans.

**Note:** If a required binary is missing, the MCP server will detect this and provide platform-specific installation instructions.

## Integrations

The MCP Server requires [Datadog API key and application](https://docs.datadoghq.com/es/account_management/api-app-keys/) key as DD_API_KEY and DD_APP_KEY

### Claude Configuration

```bash
# Configure with API keys
claude mcp add datadog-code-security \
  -e DD_API_KEY=<your-api-key> \
  -e DD_APP_KEY=<your-app-key> \
  -e DD_SITE=datadoghq.com \
  -- datadog-code-security-mcp start

# Verify it's running
claude mcp list | grep datadog-code-security
```

### Manual Configuration (~/.claude/config.json)

```json
{
  "mcpServers": {
    "datadog-code-security": {
      "command": "datadog-code-security-mcp",
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

## Cursor Configuration

Cursor supports MCP servers through its settings. Add the following to your Cursor MCP configuration:

```json
{
  "mcpServers": {
    "datadog-code-security": {
      "command": "datadog-code-security-mcp",
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

## Usage

Once configured, ask your AI assistant to scan your code:

**Security Scans:**

- "Scan this directory for security vulnerabilities"
- "Check if there are any hardcoded secrets in config/"
- "Run a full security scan (SAST + Secrets + SCA)"
- "Find all security issues in this project"

**Dependency Analysis:**

- "Scan for vulnerable dependencies"
- "Check if my dependencies have any known CVEs"
- "Generate an SBOM for this project"
- "What dependencies does this project have?"

## Direct Scanning with CLI

```bash
# Comprehensive scan (SAST + Secrets + SCA in parallel)
datadog-code-security-mcp scan all ./src

# Individual scan types
datadog-code-security-mcp scan sast ./app      # SAST only
datadog-code-security-mcp scan secrets ./config # Secrets only
datadog-code-security-mcp scan sca ./           # SCA only (requires datadog-security-cli)

# SBOM generation
datadog-code-security-mcp generate-sbom .           # Generate SBOM

# JSON output for programmatic use
datadog-code-security-mcp scan all ./src --json
datadog-code-security-mcp scan sast ./app --json
datadog-code-security-mcp generate-sbom . --json
```

#### Manual Installation Instructions for Requirements (Optional)

**datadog-static-analyzer** (SAST + Secrets)

```bash
# macOS (Homebrew — tap is already added if you installed the MCP server via brew)
brew install datadog-static-analyzer
```

**datadog-sbom-generator** (SBOM)

```bash
# macOS / Linux (download from GitHub releases)
curl -L "https://github.com/DataDog/datadog-sbom-generator/releases/latest/download/datadog-sbom-generator_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m).zip" -o /tmp/sbom.zip
unzip -o /tmp/sbom.zip -d /tmp/ && mkdir -p ~/.local/bin && mv /tmp/datadog-sbom-generator ~/.local/bin/ && chmod +x ~/.local/bin/datadog-sbom-generator
```

**datadog-security-cli** (SCA)

```bash
# macOS (Homebrew)
brew install --cask datadog-security-cli
```

## Telemetry Data Collection

Datadog Code Security MCP collects **usage telemetry** (tool and scanner versions, OS/arch, run duration, success/failure, aggregate counts, coarse authentication/workspace metadata, categorized error kinds, a fixed team ownership tag, and a random install ID stored on your machine) to help improve the tool. It does not collect source code, paths, scan finding contents, secrets, repository names, usernames, or raw error messages. Each error carries a short curated, path-free description (for Error Tracking) — never the raw error text.

Scanner versions are collected once per process and are not persisted. Telemetry events sent to Datadog are retained for 30 days.

**To disable collection of any of this usage telemetry**, use any of the following:

```bash
# Per-invocation flag
datadog-code-security-mcp --no-telemetry scan sast ./src

# Environment variable (add to your shell profile to make it permanent)
export DD_CODE_SECURITY_TELEMETRY_DISABLED=1

# DO_NOT_TRACK standard (https://consoledonottrack.com/)
export DO_NOT_TRACK=1
```

Full details on what is collected, the install ID, and how to turn off data collection: [docs/TELEMETRY.md](docs/TELEMETRY.md).

Please see the Datadog [Privacy Policy](https://www.datadoghq.com/legal/privacy/) for more information.

## For Developers

**Quick References:**

- [CLAUDE.md](CLAUDE.md) - Developer guide for Claude Code
- [AGENTS.md](AGENTS.md) - Quick reference for AI coding assistants
- [docs/RELEASE.md](docs/RELEASE.md) - Release process

**Key Commands:**

```bash
make build          # Build binary
make test           # Run tests with race detector
make lint           # Run linters
go run ./cmd/datadog-code-security-mcp version
```

## License

Apache 2.0
