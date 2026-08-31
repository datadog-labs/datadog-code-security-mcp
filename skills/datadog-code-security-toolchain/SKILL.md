---
name: datadog-code-security-toolchain
description: Diagnose and safely repair the local Datadog Code Security scanner toolchain. Use when a Datadog scan reports a missing binary, when the user asks whether scanners are installed or current, or when installing or upgrading the Code Security CLI.
---

# Datadog Code Security toolchain

Keep installation knowledge in the compiled CLI. Do not invent download URLs,
archive names, architectures, or scanner installation commands.

## Diagnose

1. Run `datadog-code-security-mcp version --detailed`.
2. Report the status, path, and version of every scanner exactly as returned.
3. For a missing scanner, relay the CLI's platform-specific installation
   instructions without rewriting them.
4. If the user asked whether scanners are current, check currency against
   each scanner's real release channel (see below). Installed version alone
   is not enough.

If the wrapper itself is absent, the bootstrap commands are:

```bash
brew tap datadog-labs/pack
brew install datadog-labs/pack/datadog-code-security-mcp
```

For an installed Homebrew wrapper, use:

```bash
brew upgrade datadog-labs/pack/datadog-code-security-mcp
```

## Currency

`version --detailed` reports the installed version only. Decide "latest"
from the same channel the CLI install instructions name. Never invent a
second source.

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
