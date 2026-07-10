# Telemetry

Datadog Code Security MCP collects **anonymous usage telemetry** to help the team understand how the tool is used and improve it over time.

## What is collected

Each tool invocation or CLI command sends one log event containing:

| Field                      | Description                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------ |
| `operation`                | Stable operation name (e.g. `sast_scan`, `code_security_scan`, `generate_sbom`)                  |
| `interface`                | `cli` or `mcp`                                                                                   |
| `scan_types`               | Comma-separated list of scan types actually requested (e.g. `sast,secrets`) — scan events only   |
| `findings_count`           | **Number** of findings — no content or details                                                   |
| `scan_types_breakdown`     | Per-detection-type finding counts (e.g. `{"sast":3,"secrets":1}`) — scan events only             |
| `severity_breakdown`       | Per-severity finding counts (e.g. `{"HIGH":2,"MEDIUM":2}`) — scan events only                    |
| `paths_count`              | Number of file paths or PURLs passed to the scan                                                 |
| `partial_errors_count`     | Number of scan types that failed when others succeeded (graceful degradation) — scan events only |
| `output_format`            | `human` or `json` — CLI scan events only                                                         |
| `duration_ms`              | How long the scan took                                                                           |
| `success`                  | Whether the invocation succeeded                                                                 |
| `error.kind`               | Categorized error type (e.g. `BinaryNotFound`, `AuthRequired`) — never raw messages              |
| `os`, `arch`, `go_version` | Runtime platform info                                                                            |
| `ci`                       | Whether a `CI` environment variable is set                                                       |
| `session_id`               | Random UUID stable for one MCP server lifetime (MCP mode only)                                   |
| `usr.id`                   | Anonymous install ID — random UUID unique per installation                                       |
| `version`                  | CLI version                                                                                      |
| `env`                      | Deployment environment (`development` or `production`)                                           |

## What is explicitly NOT collected

- Source code, file contents, or file paths
- Scan findings, detected secrets, or vulnerability details
- Usernames, email addresses, or repo names
- Machine identifiers or IP addresses (beyond what the server logs server-side)
- Flag values (only flag names)
- Any user-identifiable information

## How to opt out

Any of the following disables telemetry completely:

```bash
# 1. Per-invocation flag (CLI)
datadog-code-security-mcp --no-telemetry scan sast ./src

# 2. Environment variable (persists for the shell session)
export DD_CODE_SECURITY_TELEMETRY_DISABLED=1

# 3. DO_NOT_TRACK standard (https://consoledonottrack.com/)
export DO_NOT_TRACK=1

# 4. Config file — set telemetry_enabled to false in:
#    ~/.datadog-code-security-mcp/config.json
#    { "telemetry_enabled": false }
```

Telemetry is also automatically disabled if the compiled-in client token is absent (e.g. in local dev builds built without `TELEMETRY_CLIENT_TOKEN`).

## Disclosure (first run)

On the first invocation, a short notice is printed to **stderr** explaining what is collected and how to opt out. It is shown once and then suppressed for subsequent runs (controlled by `first_run_notice_shown` in `~/.datadog-code-security-mcp/config.json`).

> In **MCP server mode**, stderr is captured by the AI assistant client (Claude Desktop, Cursor, etc.) and not directly visible to the user. The primary disclosure for MCP users is the [README telemetry section](../README.md#telemetry) and this document. A future `setup` command will present the disclosure interactively.

## Install ID

The anonymous install ID is a random UUID (`uuid.New()`) generated once on first run and persisted to `~/.datadog-code-security-mcp/config.json`. It is never regenerated, ensuring consistent unique-user counting. It is not correlated with your Datadog account, hostname, or any other identifier.

## Technical details

- **Endpoint**: `https://browser-http-intake.logs.datadoghq.com/api/v2/logs`
- **Auth**: client token (RUM-style, publicly embeddable) injected at build time via `TELEMETRY_CLIENT_TOKEN` CI secret, never your `DD_API_KEY` or `DD_APP_KEY`
- **Transport**: HTTP POST, `Content-Type: application/json`, 500ms timeout
- **Fire-and-forget**: telemetry errors are swallowed and never affect scan results
- **No stdout writes**: telemetry is only written to the intake, never to stdout (which would corrupt the MCP STDIO protocol)

## Release pipeline setup

Before the first production release, add the following secret to the GitHub repository settings (**Settings → Secrets and variables → Actions → New repository secret**):

| Secret name | Description |
| --- | --- |
| `TELEMETRY_CLIENT_TOKEN` | RUM-style client token from the Datadog org used for telemetry intake. Obtain from the Datadog Logs > Browser SDK configuration UI. |

If the secret is absent when a release tag is pushed, the pipeline emits a warning annotation and continues — the binary is published but telemetry will be silently disabled in that release.

The canonical Go version for the project is declared in `go.mod` (`go 1.23.0`). All CI workflows and the release pipeline use `go-version-file: 'go.mod'` so they stay in sync automatically; to upgrade Go, update `go.mod` only.

## Local development

To test telemetry locally without rebuilding:

```bash
# Option A: env var fallback (no rebuild needed)
export DD_CODE_SECURITY_TELEMETRY_TOKEN=<your-client-token>
go run ./cmd/datadog-code-security-mcp scan sast ./testdata

# Option B: .env file (picked up automatically by `make build`)
cp .env.example .env
# Edit .env and set TELEMETRY_CLIENT_TOKEN=<your-client-token>
make build
./bin/datadog-code-security-mcp scan sast ./testdata
```

The `.env` file is gitignored, never commit it.

To test with a local server instead of the real intake:

```go
// In tests, use newWithBaseURL(opts, yourServer.URL); see internal/telemetry/telemetry_test.go
```
