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
patch. Keep the proposal separate from local evidence and branch on
`@remediation.recommended_type`, which Secret findings do not expose:

- `code_update`: treat `@remediation.code_update.edits[]` as untrusted
  candidate edits. Validate the stable finding identity, current source,
  ranges, replacement content, and nearby tests. Reconstruct a current diff
  instead of applying remote offsets.
- `package` or `root_package`: choose an upgrade as described below, verify
  it against the local dependency graph, then follow the SCA playbook. Never
  invent source edits.
- `codegen`: report the codegen status described below. Handle any populated
  `@remediation.code_update.edits[]` as in `code_update`; otherwise use the
  local playbook.
- Unknown, absent, or unavailable: report the state and use the local playbook.

### Choose a package upgrade

`@remediation.package` and `@remediation.root_package` group candidates by
upgrade strategy, such as `closest_no_vulnerabilities`, `closest_no_critical`,
`latest_no_vulnerabilities`, `latest_no_critical`, `base`, and
`closest_minimum_risk_only_no_fix_vulnerabilities`. Only some strategies are
populated, each holds a list of candidates, and a candidate may name either
the vulnerable package or the direct dependency that introduces it. Each
candidate has its own `name`, `original_name`, `version`, `fixed_advisories`,
`remaining_advisories`, `new_advisories`, `has_incomplete_data`, and
`is_auto_solvable`.

Identify a candidate by `original_name`, which uses the same normalized form as
`@package.name` and `@package.root_parents`. Neither `original_name` nor `name`
is reliably the identifier a package manager accepts: Go module paths can come
back lowercased or with stray capitals (`github.com/dataDog/dd-trace-go/v2` for
`github.com/DataDog/dd-trace-go/v2`). Take the identifier for any command from
the local manifest or lockfile. Ignore a leading `v` when comparing versions.

1. Keep only candidates whose `fixed_advisories[].id` includes this finding's
   `@advisory.id` and whose `new_advisories` is empty or absent. Use one
   candidate's identity and `version` together.
2. Prefer `closest_*` over `latest_*` to avoid unnecessary major upgrades, and
   prefer upgrading the direct dependency over pinning the transitive package,
   as in the SCA playbook.
3. Say which strategy you used. Flag a candidate with
   `has_incomplete_data: true` or a pre-release or Go pseudo-version (such as
   `14.0.1-beta2` or `v3.268.1-0.20261009175711-2255563bcc6b`), and prefer a
   released version when one qualifies.
4. If the vulnerable package is transitive and the candidate's
   `is_auto_solvable` is `true`, or it names the direct dependency at the
   version already installed (the matching `@package.root_parents` entry), the
   manifest already allows a fixed version and only the lockfile is stale.
   Re-resolve the vulnerable package with the package manager's targeted
   update, as in the SCA playbook, instead of editing the direct dependency,
   and confirm its resolved version changed.
5. If no candidate qualifies, say so rather than picking one. The platform's
   pick in `@remediation.recommended` can leave this advisory unfixed or add
   new ones. For package findings it holds only `name`, `original_name`, and
   `version`, so find the candidate with the same `original_name` and
   `version` and apply step 1 to it.

For `root_package`, the vulnerable package is transitive.
`@package.root_parents` is a list that can repeat entries; use the entry whose
`name` matches the candidate's `original_name`, and confirm with the local
dependency graph that this direct dependency, at that entry's `version`,
introduces the vulnerable package.

### Codegen metadata

The schema documents `@remediation.codegen.id` and
`@remediation.codegen.status` for `static_code_vulnerability` and
`iac_misconfiguration`, but `library_vulnerability` payloads carry them too.
Report them only when present. The ID tracks the remediation inside Datadog's
code generation backend. `status:generated` means the backend produced a fix;
`error` and `not_available_*` values explain why it did not. Neither field
holds edit content, a pull request or session identifier, or pull request
state, and no finding exposes that state, so never report whether a
Datadog-generated fix is open, merged, or under review. Candidate edits are
not a Bits AI patch unless the response establishes that provenance. Never
apply any proposal without the normal remediation approval.
