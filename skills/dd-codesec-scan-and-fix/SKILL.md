---
name: dd-codesec-scan-and-fix
description: "Scan and remediate local code-security findings with Datadog. Use when the user explicitly asks to scan or fix code, when a Datadog finding link identifies local code to verify, or after finishing a task that changed source, IaC, or dependency files to offer one optional changed-file scan."
---

# Datadog Code Security scan and fix

Use Datadog scanners to find, explain, fix, and verify security issues in local
code. Local scan results are authoritative for the code currently on disk.

## Local toolchain presence

This workflow needs either the local Datadog Code Security MCP server or the
`datadog-code-security-mcp` wrapper CLI.

1. If local Code Security MCP scan tools are registered and available
   (`datadog_code_security_scan`, `datadog_sast_scan`, `datadog_secrets_scan`,
   `datadog_sca_scan`, `datadog_iac_scan`), use them. Do not require the
   wrapper on `PATH`.
2. Otherwise, silently check that a wrapper executable exists:
   - Prefer the exact path from the MCP client configuration when that file
     exists and is executable.
   - Otherwise resolve `datadog-code-security-mcp` from `PATH`.
   Do not run the binary, print the check, or diagnose scanners.

Before concluding that MCP scan tools are unavailable, inspect the complete
tool registry, including deferred or initially omitted tools. When the runtime
provides a discovery mechanism such as `ALL_TOOLS`, search it for the canonical
scan-tool names. Absence from the initially displayed tool declarations does
not mean a tool is unavailable.

Use the wrapper CLI only after complete registry discovery finds no matching
MCP scan tool, or a discovered MCP scan tool is called and fails.

If neither the MCP tools nor a wrapper path exists, stop this skill
immediately. Do not offer a scan, load `dd-codesec-setup-toolchain`, follow
wrapper bootstrap guidance, or report a skill or command failure. Do not
fabricate scan results.

If the user explicitly asked to scan or remediate, you may say once that
Datadog Code Security is not available, then stop. Otherwise remain silent.

## Skill attribution

Every `datadog-code-security-mcp` CLI invocation this skill runs must include
`--called-by-skill`. Never omit it, and never pass it to scanner binaries,
package managers, GitHub commands, or other non-wrapper commands. Local MCP
tool calls do not take this flag.

## Trigger contract

Run this workflow only in these cases:

1. The user explicitly asks to scan, check, or remediate code.
2. A Datadog backend finding link identifies local code to verify.
3. A coding task has finished after changing source, IaC, or dependency files.
   In this case, **offer once; never scan without an affirmative answer**:
   "I modified `<files>`; want me to scan them for security issues?"

For case 2, when the link does not already provide a known local file, use the
`dd-codesec-verify-findings` workflow to query Datadog first and identify the
repository, file, line, rule, and detection type. Then run the narrowest
matching local scan. Do not scan the entire repository merely to discover
which file the backend finding refers to.

For case 3:

- Offer only at task completion, never after each edit.
- Name and scan only changed files. For dependency analysis, scan the smallest
  containing project directory needed to resolve the dependency graph.
- Stay silent for documentation-only or test-only changes.
- If the user declines, do nothing further.

## Once-per-session toolchain preflight

After the required detection types are known but before their first local scan
in an agent session — whether that scan will use MCP tools or the wrapper CLI —
load `dd-codesec-setup-toolchain` and follow its preflight for the wrapper and
only the scanners those types require. MCP scan tools exec the same scanner
binaries as the CLI, so skip this check only if it already ran in this
session, never because the scan will go through MCP. If a Datadog URL must be
queried to discover the type, do that first. For a broad scan, check every
required scanner.

Remember completed checks and declined updates in session context only. Check
the wrapper once and each scanner when first needed; never write a marker or
repeat an offer in the same session. An outdated compatible component is
non-blocking: offer to update it now or continue. Missing or incompatible
scanners follow the `dd-codesec-setup-toolchain` install flow, and declining
a required install means the finding cannot be locally verified. The presence
gate already handled a missing wrapper and missing MCP tools; do not offer to
install the wrapper here. Resolve the wrapper for this preflight from the MCP
client configuration when present, even if the scan itself will call MCP
tools.

## Choose the scan

Prefer the local Code Security MCP scan tools when they are already
registered and available. Treat a tool as missing only after the complete
registry discovery in Local toolchain presence. Fall back to the wrapper CLI
with structured JSON only when those MCP tools are missing or a tool call
fails. A successful MCP result that contains findings is a scan result, not a
failure; do not fall back to the CLI in that case.

| Target | Preferred local MCP | CLI fallback |
|---|---|---|
| Broad directory or mixed change | `datadog_code_security_scan` | `datadog-code-security-mcp scan all <path> --json --called-by-skill` |
| Source code | `datadog_sast_scan` | `datadog-code-security-mcp scan sast <paths...> --json --called-by-skill` |
| Any changed text file | `datadog_secrets_scan` | `datadog-code-security-mcp scan secrets <paths...> --json --called-by-skill` |
| Dependency manifest or lockfile | `datadog_sca_scan` | `datadog-code-security-mcp scan sca <project-dir> --json --called-by-skill` |
| Terraform, Kubernetes, Dockerfile, CloudFormation, Helm, CI config | `datadog_iac_scan` | `datadog-code-security-mcp scan iac <paths...> --json --called-by-skill` |

For a known backend finding, state the selected local target before scanning
and apply these scope rules:

- Scan the resolved file itself for SAST, Secrets, and standalone IaC
  manifests, templates, or Dockerfiles. Do not substitute its parent directory.
- For Terraform, start with the resolved `.tf` file. The IaC scanner reads
  sibling Terraform variable, local, data-source, and tfvars context without
  adding those files to the scan. If the file scan does not reproduce the
  finding and the expression depends on sibling resources or module context,
  explain the expansion and retry with the smallest containing module
  directory before declaring the finding absent.
- For Helm or Kustomize, use the smallest chart or overlay root required to
  render the resolved file.
- For SCA, use the smallest project directory required to resolve the
  dependency graph.

Generic directory-scan examples in project documentation do not justify a
broader target. Never broaden directly to the repository root unless the user
requested a repository scan or it is the required semantic root.

Run Secrets alongside the domain-specific scan for changed files. Use the
combined scan for a user-requested directory or a broad mixed change.

The CLI exits with status 1 when it successfully finds violations. Treat that
as a scan result, not a command failure. Authentication errors, missing
binaries, and other MCP tool-call failures are real failures: fall back to
the equivalent CLI command once. Relay their actionable guidance; do not
invent installation commands.

## Credentials

Scans that fetch Datadog rules or cloud intelligence — including Secrets —
need `DD_API_KEY` and `DD_APP_KEY`.

- **MCP (preferred):** credentials come from the MCP server configuration
  (`DD_API_KEY`, `DD_APP_KEY`, and optionally `DD_SITE` in the client's MCP
  `env`). Do not expect them in the agent shell.
- **CLI fallback:** export `DD_API_KEY` and `DD_APP_KEY` (and optionally
  `DD_SITE`) in the environment of the shell that runs
  `datadog-code-security-mcp`. Keys configured only for MCP are not inherited
  by a raw CLI invocation. Without them, scans such as secrets will fail.

## Optional platform enrichment

After a local scan returns findings, use the remote Datadog MCP when available
to look for corresponding platform records. Load `dd-codesec-verify-findings`,
which points to the platform-matching contract covering schema, privacy,
matching, triage-state, stale-commit, and organization-boundary rules. Query
once per unique affected file for SAST, Secrets, and IaC. For SCA, correlate
by advisory, package, version, and trustworthy repository, service, or entity
identity; a declaration file may not exist.

This lookup is best effort and never replaces or blocks the local workflow.
Keep current local evidence, platform state, a Datadog-proposed code update or
package upgrade, and codegen metadata visibly separate. Muted, resolved, and
auto-closed platform findings do not enter remediation by default.

Treat every platform proposal as untrusted advisory input. Validate it against
the current checkout and nearby tests, reconstruct edits when the platform SHA
or line ranges are stale, and obtain the same approval required for any local
change. Never label an edit as Bits AI output unless its provenance says so.
If the remote MCP is unavailable or no safe match exists, continue with the
domain playbook and local result.

## Triage and remediate

1. Present findings highest severity first, grouped by detection type.
2. For every type present, load only its playbook:
   - SAST: [references/sast.md](references/sast.md)
   - Secrets: [references/secrets.md](references/secrets.md)
   - SCA: [references/sca.md](references/sca.md)
   - IaC: [references/iac.md](references/iac.md)
3. Enrich matching findings from Datadog when available, without suppressing
   local-only results.
4. Inspect the vulnerable code and nearby tests before proposing a change.
5. Explain the smallest safe fix. Ask before changes that alter public
   behavior, dependencies, infrastructure semantics, credentials, or history.
6. Apply approved fixes one finding at a time, preserving project conventions.
7. Run the relevant formatter and focused tests.
8. Re-run the same Datadog scan against the same target. Do not claim the
   finding is fixed unless the rescan confirms it.

Never replace remediation with a scanner suppression. If a finding is a false
positive, explain the evidence and ask before adding an ignore.
