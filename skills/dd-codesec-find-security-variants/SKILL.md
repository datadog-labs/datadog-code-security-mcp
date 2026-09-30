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

## Pauses

The user sees two things for sure: the question on a question card, and the text that ends your turn. Text you write earlier in a turn that ends with a card may not be shown, and your reasoning is never shown. So each pause is one of two kinds, and its step says which:

- **Card.** Only when the options themselves carry what the user needs, and the question fits in one line. Do not refer to text above the card.
- **End of turn.** Finish the turn with the step's message as your final reply. Its last line is a direct question that says what to reply. Do not call a card in that turn, and make no tool call after that message.

Either way, wait for the answer before the next step.

Write every message in this skill as normal markdown: bold labels, bullet lists, inline code for names and `path:line`. Never wrap a message in a code block. A code block does not wrap lines, and the user has to scroll sideways. The templates below show the markdown to write, not a block to copy. The only code block in a message is the YAML in step 11.

## Scratch files

Write `invariant.yaml`, `rule.js`, and `query.scm` in one directory under the system temporary directory, outside this repository. Create it once and reuse it for the rest of the run:

```bash
scratch="${TMPDIR:-/tmp}/dd-codesec-find-security-variants$(pwd -P | tr '/' '-')"
mkdir -p "$scratch"
```

Do not write these files in the repository. Do not mention this directory in the report. The first time this run writes each file, write the whole file. Do not edit a copy left by an earlier run.

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

If that diff is one function, that function is the fix. If the user already attached a file or named lines, that is the fix. Do not ask. If the diff changes more than one function, more than one file, or mixes unrelated edits, pause with a card. The question is "Which change is the security fix?" One option per changed function, as `path:line function`, plus a last option: none of these, I'll point at it. Do not generate the rule until they pick one.

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

Save it at `$scratch/invariant.yaml`. Then pause at the end of the turn with this message:

````markdown
**Inferred security invariant**

- **Guard:** `<guard call>`, after `<precondition>`
- **Protects:** `<operation>`, `<operation>`, `<operation>`
- **Left out:** `<operation>`, `<operation>` (<why, in a few words>)

Is that the rule? Reply yes, or say what to change.
````

Name every operation by function name. Do not write "siblings" instead of the names. Omit the "Left out" bullet when nothing was excluded. Do not generate the rule, scan, or search until they reply yes.

If they correct it, rewrite `$scratch/invariant.yaml` from their correction and continue. Do not ask again unless they only said no and did not say what the guard or the operation is. Then ask once for those two facts.

## 3. Generate the rule

Write `$scratch/rule.js` and `$scratch/query.scm` from the invariant they confirmed. Favor recall. The scanner contract is in [rule-contract.md](references/rule-contract.md). That file is part of this skill. Do not look for an example rule in the repository.

Attach the developer's fix on every violation. Read the inserted or replaced text from the diff. Place each edit from the match, not from the line numbers in the original file. One `buildFix` holds every edit that belongs to that one change. Adding the guard to an existing import and changing the call that must run the guard are one fix, even when the diff touches the import and rewrites one statement into two lines. Replacing that statement is one `buildEditUpdate`. Adding the guard's name to the import in the same file is another `buildEditUpdate`. A pure insertion uses `buildEditAdd`. A pure deletion uses `buildEditRemove`. Then:

```javascript
const error = buildError(fn.start.line, fn.start.col, fn.end.line, fn.end.col, message);
const importEdit = buildEditUpdate(importStartLine, importStartCol, importEndLine, importEndCol, updatedImport);
const bodyEdit = buildEditUpdate(callStartLine, callStartCol, callEndLine, callEndCol, updatedCall);
addError(error.addFix(buildFix("short description of the edit", [importEdit, bodyEdit])));
```

If the diff also changes code that is not this guard, do not attach a fix. Do not enable an AI fix. The rule carries this edit only.

When the diff adds or changes the guard, a rule that only calls `addError(buildError(...))` is not finished. Do not scan until `addError` receives `error.addFix(buildFix(...))`.

That holds for every shape the query matches: function declarations, arrow functions assigned to a variable, and class methods. The body edit is the same statement change inside each one, found from the matched body, and the import edit is the same per file. Do not leave a shape without the fix. A widened query in step 8 attaches the fix to its new shapes too.

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

As soon as the scan returns, pause at the end of the turn with this message. It is not the final report. Drop the function the diff itself changed.

````markdown
**Scanner pass, not the final report.** <N> hits so far:

- `<path>:<line>`
- `<path>:<line>`

Search the rest of the code for anything this pass missed? Reply yes or no. Either way, I'll then sort these hits and ask whether to save the rule.
````

Do not rewrite the invariant or the rule from this list. Do not read candidate files, do not search the repository, and do not write the final report in this same turn.

## 5. Explore

Only if they reply yes. If they reply no, skip this step and step 6, and go to step 7 with the scanner hits only. No does not end the run. Search the repository with the usual read and search tools for code that breaks the confirmed invariant. Do not rewrite the invariant or the rule from what you find in this search.

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

````markdown
**Inferred security invariant:** <one or two lines from the invariant>

**<N> likely variants found.**

**HIGH**

- `<path>:<line>`: <what the function does, and why it breaks the same invariant as the fix>

**MEDIUM**

- `<path>:<line>`: <why it is the same shape but not clearly the same class>

**Save as a custom rule?** The rule `<rule slug>` would be saved in the ruleset `variant-hunter` and report the HIGH list. <each MEDIUM file> stays out. Every saved hit shows in the IDE as an error.

Reply save, save with MEDIUM, or no. To use another rule name or ruleset, add it to your reply.
````

When they skipped the repository search, add one line after the count: these are the scanner hits only, the rest of the code was not searched.

`N` counts only likely variants. HIGH is likely variant: the same class of operation the fix protects. MEDIUM is needs review: the same shape, not that class. Do not rank by impact. One short paragraph each. If a section has no hits, omit it.

## 10. Ask before saving

The report is an end-of-turn pause. Its last line is the save question. The rule severity is ERROR, which is why every saved hit shows as an error.

Choose the rule slug before you write the report: lowercase words joined by hyphens, naming the missing guard, such as `missing-require-admin`. The report shows that slug and the ruleset `variant-hunter`. A ruleset slug is 5 to 32 characters, lowercase letters, digits, and single hyphens, and it cannot start or end with a hyphen. Do not ask a second question only to collect a name. Do not call `datadog_promote_sast_rule` in this step.

If they reply no, stop. If they name another rule or ruleset, use that name. Otherwise use the slug and `variant-hunter` the report showed.

If they change the set, edit `$scratch/rule.js` so it reports only the operations they accepted. Keep the query. Scan again with `datadog_ephemeral_sast_scan` and `called_by_skill: true`. Then pause at the end of the turn with this message:

````markdown
**The rule now reports:**

- `<path>:<line>`
- `<path>:<line>`

Save this list? Reply save or no.
````

Do not upload a rule that still matches a MEDIUM the user did not accept.

Only after they agree to the list just shown, save it as [save-rule.md](references/save-rule.md) says: two examples, a rule description, and the upload. That file is part of this skill. Read it now, not earlier in the run.

A later message that asks to save the rule, or to include or drop a hit and then save it, starts at this step. Read the files in `$scratch`. Do not repeat the diff analysis unless those files are missing.

## 11. Name the ruleset in the project config

The IDE does not load a custom ruleset by language. It fetches only rulesets named in the project config. Static Analysis configuration is documented at <https://docs.datadoghq.com/security/code_security/static_analysis/configuration/>.

After the rule is saved, look at the repository root for `code-security.datadog.yaml`, `code-security.datadog.yml`, `static-analysis.datadog.yaml`, and `static-analysis.datadog.yml`.

If one of those files already names this ruleset, do not offer to edit it. A `code-security.datadog` file names it under `sast.use-rulesets`. A legacy `static-analysis.datadog` file names it in the top-level `rulesets` list.

If none of them names it, pause at the end of the turn with this message. Put the YAML you would write, or the lines you would add to the existing file, as the "Project config" section of [save-rule.md](references/save-rule.md) says:

````markdown
The IDE loads a custom ruleset only when the project config names it. I would <create | edit> `<file>` with:

```yaml
<content>
```

[Static Analysis configuration](https://docs.datadoghq.com/security/code_security/static_analysis/configuration/)

Add this to the project config? Reply yes or no.
````

Do not write until they reply yes. Then write it as the "Project config" section of [save-rule.md](references/save-rule.md) says. If they decline, show the configuration link again so they can add the name themselves.

## 12. Close

Only when the rule was saved. Once the config step is done, end the run with this short message. The report is far up the chat by now, and the next step happens in the editor. Do not repeat the report's explanations.

````markdown
**Saved:** `<rule slug>` in the ruleset `<ruleset>`. It reports these <N> places, each with your fix attached:

- `<path>:<line>`
- `<path>:<line>`

**Not in the rule:** `<each MEDIUM file left out>`

Open one of these files, or right-click the folder and run **Datadog Code Security > Analyze Folder**, then apply the quick fix on each finding.
````

Omit the "Not in the rule" line when nothing was left out. When this session is not Cursor or VS Code, replace the last line with: open these files and apply the fix the rule suggests.

When this session is Cursor or VS Code, and the config names the ruleset, add one line: if the custom rule does not show yet, run **Datadog: Refresh Static Analysis Rules** from the command palette. If they declined the config edit, say instead that the IDE will not load this ruleset until the config names it. Do not mention the refresh command in any other client.
