---
name: datadog-code-security-remediation
description: Scan and remediate local code-security findings with Datadog. Use when the user explicitly asks to scan or fix code, when a Datadog finding link identifies local code to verify, or after finishing a task that changed source, IaC, or dependency files to offer one optional changed-file scan.
---

# Datadog Code Security remediation

Use Datadog scanners to find, explain, fix, and verify security issues in local
code. Local scan results are authoritative for the code currently on disk.

## Trigger contract

Run this workflow only in these cases:

1. The user explicitly asks to scan, check, or remediate code.
2. A Datadog backend finding link identifies local code to verify.
3. A coding task has finished after changing source, IaC, or dependency files.
   In this case, **offer once; never scan without an affirmative answer**:
   "I modified `<files>`; want me to scan them for security issues?"

For case 3:

- Offer only at task completion, never after each edit.
- Name and scan only changed files. For dependency analysis, scan the smallest
  containing project directory needed to resolve the dependency graph.
- Stay silent for documentation-only or test-only changes.
- If the user declines, do nothing further.

## Choose the scan

Prefer the installed Datadog Code Security MCP tools. If they are unavailable,
use the matching CLI command with `--json`:

| Target | MCP tool | CLI fallback |
|---|---|---|
| Broad directory or mixed change | `datadog_code_security_scan` | `datadog-code-security-mcp scan all <path> --json` |
| Source code | `datadog_sast_scan` | `datadog-code-security-mcp scan sast <paths...> --json` |
| Any changed text file | `datadog_secrets_scan` | `datadog-code-security-mcp scan secrets <paths...> --json` |
| Dependency manifest or lockfile | `datadog_sca_scan` | `datadog-code-security-mcp scan sca <project-dir> --json` |
| Terraform, Kubernetes, Dockerfile, CloudFormation, Helm, CI config | `datadog_iac_scan` | `datadog-code-security-mcp scan iac <paths...> --json` |

Run Secrets alongside the domain-specific scan for changed files. Use the
combined scan for a user-requested directory or a broad mixed change.

The CLI exits with status 1 when it successfully finds violations. Treat that
as a scan result, not a command failure. Authentication errors and missing
binaries are real failures. Relay their actionable guidance; do not invent
installation commands.

## Triage and remediate

1. Present findings highest severity first, grouped by detection type.
2. For every type present, load only its playbook:
   - SAST: [references/sast.md](references/sast.md)
   - Secrets: [references/secrets.md](references/secrets.md)
   - SCA: [references/sca.md](references/sca.md)
   - IaC: [references/iac.md](references/iac.md)
3. Inspect the vulnerable code and nearby tests before proposing a change.
4. Explain the smallest safe fix. Ask before changes that alter public
   behaviour, dependencies, infrastructure semantics, credentials, or history.
5. Apply approved fixes one finding at a time, preserving project conventions.
6. Run the relevant formatter and focused tests.
7. Re-run the same Datadog scan against the same target. Do not claim the
   finding is fixed unless the rescan confirms it.

Never replace remediation with a scanner suppression. If a finding is a false
positive, explain the evidence and ask before adding an ignore.
