# Telemetry

Datadog Code Security MCP collects **anonymous usage telemetry** to help the team understand how the tool is used and improve it over time.

## What is collected

### Event model

Every scan emits **one telemetry event per scan type** plus, when multiple types are run together (`scan all` / `datadog_code_security_scan`), an additional **aggregate event** that covers the whole batch. This lets you count executions of any single type (e.g. `iac_scan`) directly by `operation`, without inferring counts from the aggregate.

| Invocation | Events emitted |
| --- | --- |
| Single-type (`scan sast`, `datadog_sast_scan`) | One per-scan event (`operation=sast_scan`, `standalone=true`) |
| Multi-type (`scan all`, `datadog_code_security_scan`) | One aggregate event (`operation=code_security_scan`) **plus** one per-scan event per executed type (`standalone=false`) |
| Initialization failure (binary missing, bad path) | One aggregate event only (`success=false`) — no per-scan events since nothing executed |

### Fields

**Common to all events:**

| Field | Description |
| -------------------------- | ------------------------------------------------------------------------------------------------ |
| `operation`                | Stable operation name (e.g. `sast_scan`, `code_security_scan`, `generate_sbom`)                  |
| `interface`                | `cli` or `mcp`                                                                                   |
| `duration_ms`              | Wall-clock time for this event: per-scan time for per-scan events; total elapsed time for aggregate |
| `success`                  | Whether the invocation succeeded                                                                 |
| `error.kind`               | Categorized error type (`BinaryNotFound`, `AuthRequired`, `InvalidArguments`, `PathNotFound`, `Timeout`, `Network`, `ScanError`, `GitError`, `Unknown`) |
| `error.message`            | Short curated description for Error Tracking: a per-kind default (e.g. `scan execution failed`) or a more specific string for known sub-cases (optionally suffixed with the process exit code). Hardcoded and path-free — never the raw error text |
| `os`, `arch`, `go_version` | Runtime platform info                                                                            |
| `ci`                       | Whether a `CI` environment variable is set                                                       |
| `session_id`               | Random UUID stable for one MCP server lifetime (MCP mode only)                                   |
| `usr.id`                   | Anonymous install ID — random UUID unique per installation                                       |
| `version`                  | CLI version                                                                                      |
| `env`                      | Deployment environment (`development` or `production`)                                           |
| `team`                     | Fixed telemetry ownership tag (`k9-iac`)                                                         |

**Depending on the operation:**

| Field | Description |
| -------------------------- | ------------------------------------------------------------------------------------------------ |
| `auth_method`              | Authentication source category (`none`, `env_var`, or `auth_provider`); never credentials         |
| `binary_versions`          | Installed scanner version/status by scanner (`X.Y.Z`, `not_found`, or `unknown`)                 |
| `used_binary_versions`     | Installed version/status of only the binaries this scan type or operation actually invokes (e.g. `{"static_analyzer":"1.2.3"}` for SAST; `{"sbom_generator":"…","security_cli":"…"}` for SCA; `{"sbom_generator":"…"}` for `generate_sbom`). A scoped subset of `binary_versions` — use this for per-binary version distributions to avoid double-counting the full inventory carried on every event. Present on per-scan events and on the `generate_sbom` operation event |
| `first_run`                | Whether this is the installation's first recorded invocation                                     |
| `is_git_repo`              | Whether the target is inside a Git repository                                                     |
| `is_worktree`              | Whether the target is inside a Git worktree                                                       |
| `auth_configured`          | Whether the MCP server started with authentication configured                                    |
| `libraries_count`          | Number of package coordinates submitted to a library scan                                        |
| `detailed`                 | Whether the non-sensitive `version --detailed` display mode was selected                          |
| `notice`                   | Curated message for a non-fatal informational signal from a successful operation (e.g. a zero-component SBOM generation, or a scan that had nothing to check). Present only when surfaced; appears on per-scan events and on `generate_sbom`. A hardcoded, path-free string — never raw error text |
| `config_errors`            | Category names for telemetry-config initialization failures; never raw error text or paths        |
| `id_ephemeral`             | Whether the anonymous install ID could not be persisted                                           |
| `config_rename_attempts`   | **Number** of atomic-rename attempts the config write needed (`1` on a clean write, `> 1` under cross-process write contention, seen almost exclusively on Windows). Present on config-persistence events, including the standalone `telemetry_config_rename_contended` signal emitted when a write succeeded only after retries |

**Per-scan events only** (`sast_scan`, `secrets_scan`, `sca_scan`, `iac_scan`):

| Field | Description |
| -------------------------- | ------------------------------------------------------------------------------------------------ |
| `standalone`               | `true` when the scan type was invoked on its own; `false` when part of a `scan all` batch        |
| `findings_count`           | **Number** of findings for this scan type — no content or details                               |
| `severity_breakdown`       | Per-severity finding counts for this type (e.g. `{"HIGH":2,"MEDIUM":2}`)                        |
| `paths_count`              | Number of file paths passed to the scan                                                          |
| `output_format`            | `human` or `json` — CLI events only                                                              |

**Aggregate event only** (`code_security_scan`):

| Field | Description |
| -------------------------- | ------------------------------------------------------------------------------------------------ |
| `scan_types`               | Comma-separated list of scan types requested (e.g. `sast,secrets`)                              |
| `findings_count`           | Total findings across all scan types                                                             |
| `scan_types_breakdown`     | Per-detection-type finding counts (e.g. `{"sast":3,"secrets":1}`)                               |
| `severity_breakdown`       | Per-severity finding counts across all types (e.g. `{"HIGH":2,"MEDIUM":2}`)                      |
| `scan_durations_breakdown` | Per-scan-type wall time in ms (e.g. `{"sast":1200,"secrets":340}`) — sourced from goroutine timing |
| `partial_errors_count`     | Number of scan types that failed when others succeeded (graceful degradation)                    |
| `partial_errors_breakdown` | Per-scan-type error kind for each failed type (e.g. `{"iac":"BinaryNotFound"}`) — kinds only, no raw messages |
| `notices_count`            | Number of scan types that emitted a non-fatal notice (e.g. a zero-component SBOM scan)           |
| `notices_breakdown`        | Per-detection-type curated notice message for each type that surfaced a notice (e.g. `{"sca":"No components detected..."}`) — hardcoded, path-free strings only |
| `batch_id`                 | Random UUID shared with every per-scan event in this batch — use to isolate one `scan all` execution |
| `paths_count`              | Number of file paths passed to the scan                                                          |
| `output_format`            | `human` or `json` — CLI events only                                                              |

> **Tip**: To isolate all events from a single `scan all` run, filter by `batch_id:<uuid>`. Both the aggregate event and all per-scan events (`standalone:false`) share the same `batch_id`. Single-type standalone scans do not have a `batch_id`.

## What is explicitly NOT collected

- Source code, file contents, or scan findings
- Detected secrets or vulnerability details
- Raw error messages (`error.message` is a hardcoded, curated description per
  error kind for Error Tracking — never the raw error text)
- Absolute file paths, directory structure, usernames, or repo paths
- Stack traces
- Machine identifiers or IP addresses (beyond what the server logs server-side)
- Arbitrary command arguments or user-provided flag values; only explicitly
  documented coarse modes such as `output_format` and `detailed` are collected
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

## Scanner-version collection

When telemetry is enabled, scanner versions are collected concurrently once per process. The results are held in memory only and are not persisted.

## Technical details

- **Endpoint**: `https://browser-http-intake.logs.datadoghq.com/api/v2/logs`
- **Source tag**: `ddsource=datadog-code-security-mcp`
- **Auth**: client token (RUM-style, publicly embeddable) injected at build time via `TELEMETRY_CLIENT_TOKEN` CI secret, never your `DD_API_KEY` or `DD_APP_KEY`
- **Transport**: HTTP POST, `Content-Type: application/json`, 2 s per-request timeout; process waits up to 3 s at exit for any in-flight POST to complete
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
