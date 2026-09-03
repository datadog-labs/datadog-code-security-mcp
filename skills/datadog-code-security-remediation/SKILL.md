---
name: datadog-code-security-remediation
description: Scan and remediate local code-security findings with Datadog. Use when the user explicitly asks to scan or fix code, when a Datadog finding link identifies local code to verify, or after finishing a task that changed source, IaC, or dependency files to offer one optional changed-file scan.
---

# Datadog Code Security remediation

Use Datadog scanners to find, explain, fix, and verify security issues in local
code. Local scan results are authoritative for the code currently on disk.

## Wrapper presence

This workflow needs the `datadog-code-security-mcp` wrapper. Before any other
step, silently check that a wrapper executable exists:

1. Prefer the exact path from the MCP client configuration when that file
   exists and is executable.
2. Otherwise resolve `datadog-code-security-mcp` from `PATH`.

Do not run the binary, print the check, or diagnose scanners.

If neither path exists, stop this skill immediately. Do not offer a scan,
load `datadog-code-security-toolchain`, follow wrapper bootstrap guidance,
or report a skill or command failure. Do not fabricate scan results.

If the user explicitly asked to scan or remediate, you may say once that the
Datadog Code Security CLI is not available, then stop. Otherwise remain
silent.

## Trigger contract

Run this workflow only in these cases:

1. The user explicitly asks to scan, check, or remediate code.
2. A Datadog backend finding link identifies local code to verify.
3. A coding task has finished after changing source, IaC, or dependency files.
   In this case, **offer once; never scan without an affirmative answer**:
   "I modified `<files>`; want me to scan them for security issues?"

For case 2, when the link does not already provide a known local file, use the
finding-verification workflow to query Datadog first and identify the
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
in an agent session, load `datadog-code-security-toolchain` and follow its
preflight for the wrapper and only the scanners those types require. If a
Datadog URL must be queried to discover the type, do that first. For a broad
scan, check every required scanner.

Remember completed checks and declined updates in session context only. Check
the wrapper once and each scanner when first needed; never write a marker or
repeat an offer in the same session. An outdated compatible component is
non-blocking: offer to update it now or continue. Missing or incompatible
scanners follow the Toolchain skill's install flow, and declining a required
install means the finding cannot be locally verified. The wrapper-presence
gate already handled a missing wrapper; do not offer to install it here.

## Choose the scan

Prefer the wrapper CLI with structured JSON when
`datadog-code-security-mcp` is resolvable and runnable from the agent's shell.
Use an equivalent local Code Security MCP scan tool only when it is already
registered and available, such as when the client started the wrapper from an
explicit path outside the shell's `PATH`, or when the user requests MCP.

| Target | Preferred CLI | Local MCP fallback |
|---|---|---|
| Broad directory or mixed change | `datadog-code-security-mcp scan all <path> --json` | `datadog_code_security_scan` |
| Source code | `datadog-code-security-mcp scan sast <paths...> --json` | `datadog_sast_scan` |
| Any changed text file | `datadog-code-security-mcp scan secrets <paths...> --json` | `datadog_secrets_scan` |
| Dependency manifest or lockfile | `datadog-code-security-mcp scan sca <project-dir> --json` | `datadog_sca_scan` |
| Terraform, Kubernetes, Dockerfile, CloudFormation, Helm, CI config | `datadog-code-security-mcp scan iac <paths...> --json` | `datadog_iac_scan` |

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
as a scan result, not a command failure. Authentication errors and missing
binaries are real failures. Relay their actionable guidance; do not invent
installation commands.

## Optional platform enrichment

After a local scan returns findings, use the remote Datadog MCP when available
to look for corresponding platform records. Load
`datadog-code-security-verification` and follow its schema, privacy, matching,
triage-state, stale-commit, and organisation-boundary rules. Query once per
unique affected file for SAST, Secrets, and IaC. For SCA, correlate by
advisory, package, version, and trustworthy repository, service, or entity
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
   behaviour, dependencies, infrastructure semantics, credentials, or history.
6. Apply approved fixes one finding at a time, preserving project conventions.
7. Run the relevant formatter and focused tests.
8. Re-run the same Datadog scan against the same target. Do not claim the
   finding is fixed unless the rescan confirms it.

Never replace remediation with a scanner suppression. If a finding is a false
positive, explain the evidence and ask before adding an ignore.
