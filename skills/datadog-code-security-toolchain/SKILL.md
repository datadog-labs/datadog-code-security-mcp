---
name: datadog-code-security-toolchain
description: Diagnose and safely repair the local Datadog Code Security scanner toolchain. Use when a Datadog scan reports a missing binary, when the user asks whether scanners are installed or current, or when installing or upgrading the Code Security CLI.
---

# Datadog Code Security toolchain

Keep scanner installation knowledge in the compiled CLI. Do not invent
download URLs, archive names, architectures, or installation commands.

## Diagnose

1. Identify the exact wrapper executable in use. Prefer an explicit path from
   the MCP client configuration; otherwise resolve
   `datadog-code-security-mcp` from `PATH`. Do not inspect a different
   Homebrew or development copy.
2. Run that exact executable with `version --detailed`.
3. Report the wrapper version and the status, path, and version of every
   scanner exactly as returned.
4. For a missing scanner, relay the CLI's platform-specific installation
   instructions without rewriting them.
5. If the user asked whether the wrapper, scanners, or whole toolchain are
   current, check currency against each component's real release channel
   (see below). Installed version alone is not enough.

If the wrapper itself is absent, the bootstrap commands are:

```bash
brew tap datadog-labs/pack
brew install datadog-labs/pack/datadog-code-security-mcp
```

## Currency

`version --detailed` reports the installed version only. Decide "latest"
from the same channel the CLI install instructions name. Never invent a
second source.

- `datadog-code-security-mcp` wrapper:
  - If its reported version is `dev`, treat it as a development build and
    skip wrapper currency checking. Do not compare it with public releases
    or recommend replacing it with Homebrew.
  - Determine the provenance of the exact executable diagnosed above. The
    presence of another Homebrew installation does not make the active
    executable Homebrew-managed.
  - For a Homebrew-managed executable, use the installed formula's channel:

    ```bash
    brew outdated --formula datadog-labs/pack/datadog-code-security-mcp
    brew info --formula datadog-labs/pack/datadog-code-security-mcp
    ```

  - For a release build installed manually, compare its normalized semantic
    version, ignoring a leading `v`, with the latest stable GitHub release of
    `datadog-labs/datadog-code-security-mcp`.
  - For a prerelease build, compare it with the corresponding GitHub
    prerelease channel, not only with the latest stable release.
  - If provenance or release data cannot be established, report wrapper
    currency as unknown. Never infer "current" from the installed version
    alone.
- `datadog-static-analyzer`, `datadog-sbom-generator`, `datadog-iac-scanner`:
  the latest GitHub release of the public repo named in those instructions.
- `datadog-security-cli`: **never GitHub**. It is a private package, not a
  public GitHub release. A public tag being older than the installed
  version is meaningless and must not be used to skip an upgrade.

  macOS (Homebrew cask):

  ```bash
  brew outdated --cask datadog-security-cli
  brew info --cask datadog-security-cli
  brew upgrade --cask datadog-security-cli
  ```

  Linux: use apt or yum against the Datadog `datadog-security-cli` package
  named in the CLI install instructions.

If the package manager reports a newer version, the scanner is outdated.
If it reports current, the scanner is current.

## Wrapper upgrade

Keep the wrapper on its existing installation channel unless the user
explicitly asks to switch:

- Homebrew:

  ```bash
  brew upgrade datadog-labs/pack/datadog-code-security-mcp
  ```

- Manual GitHub release: use the matching platform asset and published
  checksum from the official release. Do not silently replace it with a
  Homebrew installation.
- Development build: do not offer a release upgrade. The user controls it
  through their source checkout.

After an upgrade:

1. Run the upgraded executable by exact path with `version --detailed`.
2. Offer to run that same executable with `setup` so installed managed skills
   are refreshed from the new wrapper. Obtain confirmation before writing.
3. Tell the user to restart the MCP client. Replacing the binary does not
   update an already-running server process or a skill already loaded by the
   client.

## Installation guardrails

- Show the exact commands and explain what they change.
- Obtain explicit confirmation immediately before running any installer.
- Prefer the CLI's no-sudo `~/.local/bin` route when it offers one.
- Never pipe a remote download directly into a shell.
- Never substitute the README's system-wide `sudo install` route when the CLI
  reports a supported no-sudo route.
- Do not claim success until `version --detailed` reports the binary installed.

When future `install`, `upgrade`, and `status` subcommands become available,
prefer them over executing the printed scanner instructions.
