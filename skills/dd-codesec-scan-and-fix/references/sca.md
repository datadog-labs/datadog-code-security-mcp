# SCA remediation playbook

Identify the ecosystem, affected package, installed version, fix version, and
whether the dependency is direct or transitive.

## Universal rules

- A direct dependency is updated in its manifest with the repository's package
  manager. For a transitive dependency, first upgrade the direct parent that
  introduced it; use a supported override or constraint only when that cannot
  produce a safe graph.
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
  its parent or use the root `overrides` field, then run `npm install`.
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
