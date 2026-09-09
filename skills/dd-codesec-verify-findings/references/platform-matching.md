# Datadog platform matching contract

Query the Datadog platform for context, then decide what genuinely corresponds
to the local finding. Platform data never overrides a current local result.

## Query the platform

Use the remote Datadog MCP `security` toolset only for platform data:

1. Call `get_datadog_security_findings_schema` for the relevant finding type
   before querying. The verified types are `static_code_vulnerability`,
   `secret`, `library_vulnerability`, and `iac_misconfiguration`.
2. Use `search_datadog_security_findings` for complete objects. Use
   `analyze_datadog_security_findings` only for recent discovery, filtering,
   grouping, or aggregation; its live 24-hour view is not historical.
3. For a URL or known ID, query exactly `@finding_id:"<id>"`. For file
   discovery, scope by repository identity and normalized
   `@code_location.filename`.

## Match by detection type

For SAST, Secrets, and IaC, prefer an exact finding ID. Otherwise require the
same normalized repository and path, stable `@rule.id`, and overlapping line
range. Never match on filename alone or templated `@rule.name`.

For SCA, prefer an exact ID. Otherwise require advisory ID or CVE, normalized
package name, detected version, and trustworthy repository, service, or entity
identity. Runtime or APM findings may have no declaration file; use one as
additional confidence only when populated. Without a safe checkout mapping,
present the finding as platform context, not a local match.

## Freshness and classification

Use `@git.sha` as freshness evidence, not mandatory identity. If it differs
from the checkout, inspect current source and rely on the fresh local scan;
never apply old line offsets mechanically. Classify results as matched,
local-only, platform-only, or ambiguous and show the evidence from each source.

## Triage state

Muted, resolved, and auto-closed platform findings do not enter remediation by
default. For an exact muted finding, report its state without inspecting raw
suppressed detector output unless the user explicitly requests a suppression
audit. If a fresh local finding is active while the platform record is
`muted_in_code`, report likely platform drift; never restore a suppression.

## Secret findings

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
