# SCA remediation playbook

Identify the ecosystem, affected package, installed version, fix version, and
whether the dependency is direct or transitive.

## Group by recommended package

Group findings by `(ecosystem, recommended package)` before proposing a fix,
and ask for approval once per package upgrade. The repository is not part of
the key: this flow always runs inside a single checkout. Take the ecosystem
from the package URL type. Take the name of the package to change, as used in
commands, from the local manifest or lockfile.

Derive the recommended package:

- When a platform finding is available, use `@remediation.recommended.name`,
  the field the platform groups package updates by. Do not use
  `@remediation.package.base`: it describes the installed package, not the
  recommendation. As in the platform-matching contract, find the candidate
  with the same `original_name` and `version`, and use the recommendation only
  if that candidate's `fixed_advisories` include this finding. Otherwise use
  the package this playbook would actually change.
- Otherwise use the package this playbook would actually change. That is the
  vulnerable package when it is a direct dependency, and the direct parent that
  introduces it when it is transitive. Find that parent with the ecosystem's
  `why` or `tree` command. For a lockfile-only refresh, use the transitive
  package itself.

Choose one target version that fixes every advisory in the group. If no single
version does, split off the advisories it cannot fix. Do not claim the upgrade
closes an advisory it leaves open.

The group keeps the recommended package as its name even when the proposed
change uses another candidate's package or version, such as a closer version
of the installed package. In every group where the package or version
differs, show both the platform recommendation and the proposed change, and
explain why.

Order groups by the highest severity in the group, descending, then by the
number of findings, descending, then by group name alphabetically.

Present each group as one proposed upgrade: the group name, the package to
change, its current version, and the target version. Under it, list every
advisory the upgrade closes, with its severity and the affected package when
that package differs from the group package. A count of advisories does not
replace this list.

A finding joins a group only when a fixed version can be established. The
local scan does not include a fix version, so determine it from the advisory
or a platform candidate before deciding. Findings with no fixed version, and
`MAL-*` advisories, never join a group. Report them in a separate list of
findings with no recommended upgrade, with their advisories, and handle them
with the rules below. Never drop them silently.

A local rescan cannot confirm advisories the local scan never reported, such
as transitive findings only the platform sees. After the fix, report them as
pending until the next platform scan, not as fixed.

## Universal rules

- A direct dependency is updated in its manifest with the repository's package
  manager. For a transitive dependency, first upgrade the direct parent that
  introduced it; use a supported override or constraint only when that cannot
  produce a safe graph.
- If a transitive package's existing constraints already allow a fixed version
  and only the lockfile pins the vulnerable one, leave the manifest unchanged
  and refresh that package with the ecosystem's targeted update below.
- Regenerate lockfiles and checksum files with the package manager. Never edit
  `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `uv.lock`,
  `go.sum`, `Cargo.lock`, `packages.lock.json`, `composer.lock`, or
  `Gemfile.lock` by hand.
- If no fix version exists, say so. Consider removing or replacing the
  dependency, mitigating the reachable call path, or applying a maintained
  vendor patch. Never invent a safe version.
- A `MAL-*` malicious-package advisory has no upgrade path. Remove the package
  from the manifest and installed dependency tree, regenerate the lock, and
  treat credentials available during install or runtime as exposed. Obtain
  approval before deleting dependency directories or rotating credentials.

## Ecosystem mechanics

Use the repository's existing tool and version; do not introduce a different
package manager.

- **npm:** inspect with `npm explain <package>`. Update a direct dependency with
  `npm install <package>@<safe-version>`. For a transitive dependency, upgrade
  its parent or use the root `overrides` field, then run `npm install`. When
  the parent's range already allows a fixed version, run
  `npm update <package>`.
- **Yarn:** inspect with `yarn why <package>`. Use the repository's Yarn
  generation (`yarn up` for modern Yarn, its established upgrade command for
  Classic) and `resolutions` only for a justified transitive override.
- **pnpm:** inspect with `pnpm why <package>`, update with
  `pnpm up <package>@<safe-version>`, and use `pnpm.overrides` for a necessary
  transitive pin. Let pnpm regenerate its lockfile.
- **pip / pip-tools:** locate the owning input requirement; do not treat an
  environment-only `pip install` as a repository fix. Update the requirement
  and run the project's lock command, such as
  `pip-compile --upgrade-package <package>`.
- **Poetry:** use `poetry show --tree`, update the manifest constraint when
  direct, and run `poetry update <package>`. Prefer upgrading the parent of a
  transitive package; do not edit `poetry.lock`.
- **uv:** use `uv tree --invert <package>` and the project's manifest or
  requirements input, then `uv lock --upgrade-package <package>` and
  `uv sync` only when environment mutation is approved.
- **Go modules:** use `go mod why -m <module>` and `go mod graph`; update with
  `go get <module>@<safe-version>` followed by `go mod tidy`. Prefer upgrading
  the requiring module. Use `replace` only for an intentional maintained fork
  or temporary patched source, with an explanation.
- **Maven:** use `mvn dependency:tree -Dincludes=<group>:<artifact>`. Update the
  direct dependency, shared version property, or `dependencyManagement`
  entry that owns the version, then run the repository's Maven tests.
- **Gradle:** use `dependencyInsight` to find the introducing dependency.
  Update the catalog/build constraint or parent; use dependency constraints
  or the existing resolution strategy for a necessary transitive override,
  then regenerate dependency locks with the repository's Gradle wrapper.
- **Cargo:** use `cargo tree -i <crate>`. Update `Cargo.toml` when direct or run
  `cargo update -p <crate> --precise <safe-version>` for a compatible locked
  transitive version. Use `[patch]` only for a maintained alternate source.
- **NuGet:** use `dotnet list package --include-transitive`. Update the project
  reference or central `Directory.Packages.props`; a direct version override
  for a transitive package must be intentional and compatible. Restore with
  the repository's checked-in lock policy.
- **Composer:** use `composer why <package>`, update the owning constraint, and
  run `composer update <package> --with-dependencies`. Do not misuse
  `replace` to pretend a vulnerable package is absent.
- **Bundler:** use `bundle why <gem>` or the lockfile dependency tree. Update a
  direct `Gemfile` constraint or its parent with `bundle update <gem>`, and let
  Bundler regenerate `Gemfile.lock`.

Use the repository's existing package manager and pinning conventions. Inspect
release notes before a major-version update and tell the user about likely
breaking changes.

After the update, regenerate and inspect the dependency graph to confirm the
resolved vulnerable version is gone. Run the focused build and tests, then
re-run the SCA scan against the same project root. Do not report success merely
because manifest text changed.
