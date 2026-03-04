# datadog-code-security-mcp

Local code security scanning for AI coding assistants via Model Context Protocol (MCP).

## Overview

Datadog Code Security MCP provides all Code Security scan tools to AI coding assistants like Claude Desktop, Cursor, etc - Can also be used as a CLI tool.

### Available MCP Tools
1. **`datadog_code_security_scan`** - SAST + Secrets + SCA in parallel
2. **`datadog_sast_scan`** - Static Application Security Testing only
3. **`datadog_secrets_scan`** - Secrets detection only
4. **`datadog_sca_scan`** - Software Composition Analysis (dependency vulnerabilities)
5. **`datadog_generate_sbom`** - Generate Software Bill of Materials (SBOM)

## Quick Start

### Installation

**Homebrew (Recommended):**

```bash
brew update
brew install --cask datadog-labs/pack/datadog-code-security-mcp
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
```
**⚠️ Requirements:**

The MCP server requires external Datadog security binaries to perform scans.

**Note:** If a required binary is missing, the MCP server will detect this and provide platform-specific installation instructions.

## Claude Desktop Configuration

The scanner requires Datadog API credentials to fetch security rules for SAST and Secrets scanning. SBOM generation works without authentication.

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

## Direct Scanning (No AI Required)

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
