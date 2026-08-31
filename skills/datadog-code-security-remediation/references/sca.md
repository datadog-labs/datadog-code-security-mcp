# SCA remediation playbook

Identify the ecosystem, affected package, installed version, fix version, and
whether the dependency is direct or transitive.

- **Direct dependency:** update the manifest using its package manager.
- **Transitive dependency:** prefer upgrading the direct parent. If necessary,
  use the ecosystem's supported override or constraint mechanism rather than
  adding an unrelated direct dependency.
- **Lockfiles:** regenerate with the package manager. Never hand-edit a
  lockfile or checksum file.
- **No fix version:** say so. Consider removing the dependency, replacing it,
  mitigating the vulnerable call path, or applying a maintained patch.
- **Malicious package:** remove it rather than upgrading it. Consider any
  credentials available to its install or runtime environment exposed.

Use the repository's existing package manager and pinning conventions. Inspect
release notes before a major-version update and tell the user about likely
breaking changes.

After the update, regenerate the dependency graph, run the focused build and
tests, and re-run the SCA scan. Do not report success merely because the
manifest text changed.
