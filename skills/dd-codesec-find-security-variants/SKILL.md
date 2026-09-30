---
name: dd-codesec-find-security-variants
description: >-
  After a local uncommitted security fix, infer the security invariant from
  the git diff, generate an ephemeral Datadog SAST rule, scan with the local
  Code Security MCP, and report other places that break the same invariant.
  Use when the user just fixed a security bug, asks whether the same mistake
  exists elsewhere, asks whether the same check is missing in other files, or
  refers to an uncommitted security fix, or asks to save, promote, or upload
  the temporary rule as a custom SAST rule, including after changing which
  findings to include. Also use when the user runs
  /dd-codesec-find-security-variants.
---

# Find security variants

The developer just fixed a security issue and has not committed it. Find other places that break the same invariant. Do not ask them to paste the diff or to write the invariant. Confirm the invariant you inferred before you search. Ask which file and lines are the fix only when the diff is not a single change and they have not already pointed at it.

The report names where the same mistake is. It does not say which path found each hit.

## Scratch files

Write `invariant.yaml`, `rule.js`, and `query.scm` in one directory under the system temporary directory, outside this repository. Create it once and reuse it for the rest of the run:

```bash
scratch="${TMPDIR:-/tmp}/dd-codesec-find-security-variants$(pwd | tr '/' '-')"
mkdir -p "$scratch"
```

Do not write these files in the repository. Do not mention this directory in the report.

## Skill attribution

Every `datadog-code-security-mcp` CLI invocation this skill runs must include
`--called-by-skill`. Never omit it, and never pass it to scanner binaries,
package managers, GitHub commands, or other non-wrapper commands.

Every local Code Security MCP tool call made while following this skill must
include `called_by_skill: true`. Never omit it from those calls. Do not pass
`called_by_skill` on other MCP servers' tools. If you later call a Code
Security MCP tool outside this skill's workflow, omit the flag even if you
have seen it here.

## 1. Read the diff

Run `git diff` and `git diff --cached`. If both are empty, stop and say there is no uncommitted change.

If that diff is one function, that function is the fix. If the user already attached a file or named lines, that is the fix. Do not ask. If the diff changes more than one function, more than one file, or mixes unrelated edits, ask with one question card which change is the security fix. One option per changed function, named as `path:line`. Add a last option: none of these, I'll point at it. Do not generate the rule until they pick one.

## 2. Infer the invariant, then confirm it

From that fix only, write a structured invariant. Generalize the fix. You may read the functions and helpers the diff touches so the invariant names the real guard and the real operation. Do not go hunting for other violations in this step.

```yaml
vulnerability:
  type: <class>
security_invariant:
  description: >
    <one paragraph>
authorization_guard:
  function: <name or null>
privileged_operations:
  - <operations the fix protects, plus obvious siblings on the same object>
```

Save it at `$scratch/invariant.yaml`.

Show the invariant in two lines: the guard, and the operation it protects. Then ask with one question card whether that is the rule. Options:

- Yes, that is the rule (recommended)
- No, I'll correct it

Do not generate the rule, scan, or search until they pick yes.

If they correct it, rewrite `$scratch/invariant.yaml` from their correction and continue. Do not ask again unless they only said no and did not say what the guard or the operation is. Then ask once for those two facts.

## 3. Generate the rule

Write `$scratch/rule.js` and `$scratch/query.scm` from the invariant they confirmed. Favor recall. The scanner contract is in [rule-contract.md](rule-contract.md). That file is part of this skill. Do not look for an example rule in the repository.

Attach the developer's fix on every violation. Read the inserted or replaced text from the diff. Place each edit from the match, not from the line numbers in the original file. One `buildFix` holds every edit that belongs to that one change. Adding the guard to an existing import and changing the call that must run the guard are one fix, even when the diff touches the import and rewrites one statement into two lines. Replacing that statement is one `buildEditUpdate`. Adding the guard's name to the import in the same file is another `buildEditUpdate`. A pure insertion uses `buildEditAdd`. A pure deletion uses `buildEditRemove`. Then:

```javascript
const error = buildError(fn.start.line, fn.start.col, fn.end.line, fn.end.col, message);
const importEdit = buildEditUpdate(importStartLine, importStartCol, importEndLine, importEndCol, updatedImport);
const bodyEdit = buildEditUpdate(callStartLine, callStartCol, callEndLine, callEndCol, updatedCall);
addError(error.addFix(buildFix("short description of the edit", [importEdit, bodyEdit])));
```

If the diff also changes code that is not this guard, do not attach a fix. Do not enable an AI fix. The rule carries this edit only.

When the diff adds or changes the guard, a rule that only calls `addError(buildError(...))` is not finished. Do not scan until `addError` receives `error.addFix(buildFix(...))`.

## 4. Scan, then show that pass

Prefer the MCP tool `datadog_ephemeral_sast_scan` with `rule_code`, `tree_sitter_query`, `language`, and `directory`. Pass `called_by_skill: true`.

If that tool is not registered, run the local binary (no API key):

```bash
datadog-code-security-mcp ephemeral-scan --called-by-skill \
  --language <LANGUAGE> \
  --directory . \
  --code-file "$scratch/rule.js" \
  --query-file "$scratch/query.scm"
```

`<LANGUAGE>` is the scanner enum for the code under the diff (`TYPESCRIPT`, `JAVASCRIPT`, …). Omit `--path` to scan the whole directory. Pass `--path` only for a subdirectory the diff actually touches.

As soon as the scan returns, show that list. It is not the final report. Drop the function the diff itself changed. List each remaining hit as `path:line`. Say this is what the scanner found so far. Then ask with one question card, the same kind used before saving. The question is whether to keep checking the code for anything this pass missed. Options:

- Continue (recommended)
- Stop here

Do not rewrite the invariant or the rule from this list. Do not read candidate files, do not search the repository, and do not write the final report in this same turn. Wait for their choice.

## 5. Explore

Only after they agree to continue. If they say no, stop. Search the repository with the usual read and search tools for code that breaks the confirmed invariant. Do not rewrite the invariant or the rule from what you find in this search.

## 6. Merge

Union the two lists by file and function. Drop the function the diff itself changed. Keep a hit that only one path found.

## 7. Triage

Read each candidate's function and the helpers it calls. Classify:

- **likely variant** — same missing guard, same class of operation the invariant names.
- **needs review** — same shape (authenticate, then a similar call, no guard) but the operation is not clearly the privileged class.
- **unrelated** — the guard is already present, or the operation is a different class (for example reading the caller's own data).

Base the class on the operation, not on a comment that labels the file as a test case. Leave unrelated hits out of the report.

Do not rank hits by how damaging they look. HIGH means the operation is the same class the fix protects. MEDIUM means the shape matches, but the operation is not that class. A sensitive read is not HIGH only because the data is sensitive. An operation of the same class as the fix does not drop to MEDIUM because it looks less severe.

## 8. Cover every same-class hit in the rule

Every likely variant has to be reported by the scanner, including one that only the repository search found. If any likely variant is absent from the latest scan, widen `$scratch/query.scm` or the operations matched in `$scratch/rule.js` until a new scan reports that function. Do not change the invariant. Do not drop the finding to make the lists match. Scan again with the same tool and `called_by_skill: true`. The source you save is this updated rule. If that scan still misses one of those functions, name it, say the rule cannot express it, and keep it in the report.

## 9. Report

```text
Analyzing current security fix...

Inferred security invariant:
<one or two lines from the invariant>

Searching repository...
Running temporary Code Security detector...

<N> likely variants found.

HIGH
<path>:<line>

<what the function does, and why it breaks the same invariant as the fix>

MEDIUM
<path>:<line>

<why it is the same shape but not clearly the same class>
```

`N` counts only likely variants. HIGH is likely variant: the same class of operation the fix protects. MEDIUM is needs review: the same shape, not that class. Do not rank by impact. One short paragraph each. If a section has no hits, omit it.

## 10. Ask before saving

After the report, ask with one question card whether to save a permanent custom rule. In that same question, name the ruleset `variant-hunter` and say they can choose another. A ruleset slug is 5 to 32 characters, lowercase letters, digits, and single hyphens, and it cannot start or end with a hyphen. If they agree and do not name one, use `variant-hunter`. Do not ask a second question only to collect the name. Do not call `datadog_promote_sast_rule` in this step.

The card proposes the HIGH list. Name each MEDIUM file that would stay out. Say that every saved hit appears in the IDE as an error, because the rule severity is ERROR. Options:

- Save the HIGH list to `variant-hunter` (recommended)
- Save the HIGH list and the MEDIUM files just named
- Don't save anything

If they pick nothing, stop. If they name another ruleset in the question, use that name.

If they change the set, edit `$scratch/rule.js` so it reports only the operations they accepted. Keep the query. Scan again with `datadog_ephemeral_sast_scan` and `called_by_skill: true`, and show the new list. Ask once more with one question card whether to save that list. Options:

- Save this list (recommended)
- Don't save anything

Before the upload, attach two examples. The rule page shows them. You already have both: the function after the fix, and that same function before the fix.

Write them outside the repository:

- `$scratch/examples/compliant/compliant.<ext>` is the whole function after the fix. Its `annotation_count` is 0.
- `$scratch/examples/noncompliant/noncompliant.<ext>` is that same function as it was before the fix, from the committed file. Its `annotation_count` is 1.

`<ext>` is the extension for the language (`ts` for TYPESCRIPT, `js` for JAVASCRIPT, otherwise the normal extension). Use the whole function. Always pass both. Do not scan them to decide whether to keep them, and do not save the rule without them.

Before the upload, write `$scratch/description.md` from the confirmed invariant and from the rule source you are about to save. The rule page shows this text. The ruleset is shared, so its description stays generic and this upload does not change it. Make the rule text as specific as the rule:

- the guard function, and that the rule flags its absence
- the precondition, such as `authenticate(req)` already having run
- where the guard has to run, relative to that precondition and the privileged call
- every operation the rule flags, by the name used in the rule
- the wider same-shape case, when the rule still flags other calls on that object, and that those need a human check
- every same-shape operation left out, by name, and why it is not this rule

Write several sentences. Do not shorten it to one generic line, and do not write "Custom SAST rule saved from a local variant search."

Also write one line of at most 60 characters that names the guard and the operation class. Count the characters. Pass that line as `short_description` and the file text as `description`.

Only after they agree to the list just shown, call `datadog_promote_sast_rule` with `user_confirmed: true`, the exact `rule_code` and `tree_sitter_query` from `$scratch`, `language`, a slug `rule_name`, `ruleset_name` set to the name they chose or `variant-hunter` when they did not, `short_description`, and `description`. Pass `called_by_skill: true`. Also pass `tests`: the fixed function with `annotation_count` 0, and the same function before the fix with `annotation_count` 1. Each item is `filename`, `code` (the file text, not base64), and `annotation_count`. The tool uploads that source and those two examples. It refuses when `user_confirmed` is not true.

If the tool is not registered, write both examples to `$scratch/tests.json` as a JSON array of `{filename, code, annotation_count}` and run:

```bash
datadog-code-security-mcp promote-sast-rule --called-by-skill --user-confirmed \
  --language <LANGUAGE> \
  --code-file "$scratch/rule.js" \
  --query-file "$scratch/query.scm" \
  --rule-name <slug> \
  --ruleset-name <ruleset> \
  --short-description "<line of at most 60 characters>" \
  --description-file "$scratch/description.md" \
  --tests-file "$scratch/tests.json"
```

Always pass `--tests-file`, `--description-file`, and `--short-description`.

`<ruleset>` is the name they chose, or `variant-hunter`. That command uses the same Datadog credentials as the MCP server: `DD_API_KEY` and `DD_APP_KEY`, or `DD_AUTH_DOMAIN` so `dd-auth` can supply a short-lived token.

## 11. Name the ruleset in the project config

The IDE does not load a custom ruleset by language. It fetches only rulesets named in the project config. Static Analysis configuration is documented at <https://docs.datadoghq.com/security/code_security/static_analysis/configuration/>.

After the rule is saved, look at the repository root for `code-security.datadog.yaml`, `code-security.datadog.yml`, `static-analysis.datadog.yaml`, and `static-analysis.datadog.yml`.

If one of those files already names this ruleset, do not offer to edit it. A `code-security.datadog` file names it under `sast.use-rulesets`. A legacy `static-analysis.datadog` file names it in the top-level `rulesets` list.

If none of them names it, ask with one question card whether to add the ruleset. Show the configuration link in that question. Options:

- Add it to the project config (recommended)
- Don't add it

Do not write until they pick the first option. When they do:

- If `code-security.datadog.yaml` or `code-security.datadog.yml` exists, add the slug under `sast.use-rulesets`. Keep every other setting. Do not set `use-default-rulesets` to false.
- If only a legacy `static-analysis.datadog.yml` or `.yaml` exists, add the slug to its `rulesets` list. Do not create a second config file. The extension prefers `code-security.datadog.yaml` when both exist, and a new file would hide the legacy rulesets.
- If no config file exists, create `code-security.datadog.yaml` at the repository root:

```yaml
schema-version: v1.0
sast:
  use-rulesets:
    - <ruleset>
```

Do not set `use-default-rulesets: false`. Default language rulesets stay on. Do not write this file under `$scratch`.

If they decline, show the configuration link again so they can add the name themselves.

When this session is Cursor or VS Code, and the config names the ruleset, say the extension can load the rule as soon as that file is in place. If they do not see the custom rule applied, run **Datadog: Refresh Static Analysis Rules** from the command palette. That is a fallback, not a required step. The command stays hidden until that file is the effective config and static analysis is enabled. Saving the config file clears the in-memory rule cache. The extension fetches the rules again after that command, after two hours, or when the static analysis engine restarts. If they declined the edit, say the refresh will not request this ruleset until the config names it. Do not mention this command in any other client.

A later message that asks to save the rule, or to include or drop a hit and then save it, starts at this step. Read the files in `$scratch`. Do not repeat the diff analysis unless those files are missing.

Do not upload a rule that still matches a MEDIUM the user did not accept.
