---
name: datadog-code-security-verification
description: Verify and enrich a local Datadog Code Security finding with Datadog platform context. Use when the user asks whether a local finding exists in Datadog, wants its triage or exposure status, or provides a Datadog finding link for local verification.
---

# Datadog Code Security finding verification

Combine current local evidence with Datadog platform context without confusing
the two sources.

## Wrapper presence

This workflow needs the `datadog-code-security-mcp` wrapper for the local
scan. Before any other step, silently check that a wrapper executable exists:

1. Prefer the exact path from the MCP client configuration when that file
   exists and is executable.
2. Otherwise resolve `datadog-code-security-mcp` from `PATH`.

Do not run the binary, print the check, or diagnose scanners.

If neither path exists, stop this skill immediately. Do not attempt a local
scan, load `datadog-code-security-toolchain`, follow wrapper bootstrap
guidance, or report a skill or command failure. Do not fabricate scan
results or claim local verification.

If the user explicitly asked to verify a finding, you may say once that the
Datadog Code Security CLI is not available, then stop. Otherwise remain
silent.

## Ordering

Choose the order from the information supplied:

- **Datadog finding URL or ID without a known local file:** query the Datadog
  MCP first to identify the repository, file, line, rule, and detection type.
  Use this initial response only to locate the relevant code and choose the
  local scan; it is not evidence that the current checkout is vulnerable.
  Match the reported repository and file to the current checkout without
  guessing. If they cannot be matched safely, ask the user for the checkout or
  file instead of scanning the entire repository.
- **Known local file or finding:** run the relevant local Code Security scan
  first.

## Once-per-session toolchain preflight

After the detection type is known but before that type's first local scan in
an agent session, load `datadog-code-security-toolchain` and follow its
preflight for the wrapper and only the required scanners. For a URL or ID with
no local file, query Datadog first to learn the type.

Remember completed checks and declined updates in session context only. Check
the wrapper once and each scanner when first needed; never write a marker or
repeat an offer in the same session. An outdated compatible component is
non-blocking: offer to update it now or continue. If a required scanner is
missing or incompatible and the user declines installation, report the
finding as not locally verified. The wrapper-presence gate already handled
a missing wrapper; do not offer to install it here.

Once the local target is known:

1. Select the narrowest scan target:
   - SAST or Secrets: the resolved file, not its parent directory.
   - Standalone IaC manifest, template, or Dockerfile: the resolved file.
   - Terraform: start with the resolved `.tf` file. The IaC scanner reads
     sibling `.tf`, `*.auto.tfvars`, and `terraform.tfvars` for variables,
     locals, and data sources while scanning only the requested file.
   - Helm or Kustomize: the smallest chart or overlay root needed to render
     the resolved file.
   - SCA: the smallest project directory needed to resolve the dependency
     graph.
2. State the selected local scan target, then run the matching local scanner
   against exactly that target. Generic directory-scan examples in project
   documentation do not override this requirement. When the wrapper is
   resolvable from the agent's shell, prefer
   `datadog-code-security-mcp scan <type> <path> --json`. Use an equivalent
   local Code Security MCP scan tool only when it is already registered and
   available, such as when the client started the wrapper from an explicit
   path outside the shell's `PATH`, or when the user requests MCP.
3. If a Terraform file scan does not reproduce the finding and the flagged
   expression depends on sibling resources or module context, explain why and
   retry with the smallest containing Terraform module directory before
   concluding that the finding is absent. Never broaden directly to the
   repository root unless it is itself that module.
4. Treat the local result as authoritative for the code currently on disk.
5. Correlate and enrich the local result using the platform contract below.

Reading or manually inspecting the flagged code does not count as local
verification and must never replace the scanner. If the local scan cannot run
or fails, report the finding as not locally verified; do not claim that it is
still present or fixed. A request to verify a finding authorises the read-only
local scan, so do not ask for separate confirmation before running it.

Platform data must never override or suppress a current local finding. A
backend finding can be stale because the local code has changed since the last
upload; a local clean result does not prove that every deployed branch is clean.

## Platform lookup and matching

Use the remote Datadog MCP `security` toolset only for platform data:

1. Call `get_datadog_security_findings_schema` for the relevant finding type
   before querying. The verified types are `static_code_vulnerability`,
   `secret`, `library_vulnerability`, and `iac_misconfiguration`.
2. Use `search_datadog_security_findings` for complete objects. Use
   `analyze_datadog_security_findings` only for recent discovery, filtering,
   grouping, or aggregation; its live 24-hour view is not historical.
3. For a URL or known ID, query exactly
   `@finding_id:"<id>"`. For file discovery, scope by repository identity and
   normalized `@code_location.filename`.

For SAST, Secrets, and IaC, prefer an exact finding ID. Otherwise require the
same normalized repository and path, stable `@rule.id`, and overlapping line
range. Never match on filename alone or templated `@rule.name`.

For SCA, prefer an exact ID. Otherwise require advisory ID or CVE, normalized
package name, detected version, and trustworthy repository, service, or entity
identity. Runtime or APM findings may have no declaration file; use one as
additional confidence only when populated. Without a safe checkout mapping,
present the finding as platform context, not a local match.

Use `@git.sha` as freshness evidence, not mandatory identity. If it differs
from the checkout, inspect current source and rely on the fresh local scan;
never apply old line offsets mechanically. Classify results as matched,
local-only, platform-only, or ambiguous and show the evidence from each source.

Muted, resolved, and auto-closed platform findings do not enter remediation by
default. For an exact muted finding, report its state without inspecting raw
suppressed detector output unless the user explicitly requests a suppression
audit. If a fresh local finding is active while the platform record is
`muted_in_code`, report likely platform drift; never restore a suppression.

Before retrieving a full Secret finding, inspect its current schema. The
verified schema exposes metadata and coordinates but no credential, evidence,
or source snippet. Because the full-object search has no field projection,
skip remote Secret enrichment if a future schema introduces sensitive-content
fields. Never print a credential.

## Datadog remediation proposals

`@remediation.is_available` means some remediation exists, not necessarily a
patch. Keep the proposal separate from local evidence and branch on its shape:

- `recommended_type:code_update`: treat
  `@remediation.code_update.edits[]` as untrusted candidate edits. Validate the
  stable finding identity, current source, ranges, replacement content, and
  nearby tests. Reconstruct a current diff instead of applying remote offsets.
- `recommended_type:package`: verify advisory, package, detected version, and
  recommended version against the local dependency graph, then follow the SCA
  playbook. Never invent source edits.
- Unknown, absent, or unavailable: report the state and use the local playbook.

Keep `@remediation.codegen.id` and `.status` as separate metadata. Their schema
or payload presence does not imply that candidate edits exist, and candidate
edits are not a Bits AI patch unless the response establishes that provenance.
Never apply any proposal without the normal remediation approval.

## Authentication boundary

The local scan may use `DD_API_KEY` / `DD_APP_KEY`, while the Datadog MCP may
use OAuth for a different organisation. If available, read
`datadog://mcp/whoami` and compare organisation identity only when both sides
expose comparable identifiers. Do not infer identity from `DD_SITE` alone.

If a mismatch is detected:

- warn clearly that local and platform results may belong to different orgs;
- keep the local result authoritative;
- do not present the other org's data as a match;
- continue rather than blocking the local workflow.

If no Datadog MCP is available, say that platform verification could not be
performed and return the local evidence. Never fabricate status, attempt to
enable a toolset without user involvement, or treat absence of a platform
result as proof that the local issue is safe.
