# SAST remediation playbook

Fix the vulnerability at its source while preserving intended behaviour.

- **Injection:** replace string construction with structured APIs:
  parameterised SQL, argument arrays instead of a shell, and framework-native
  query builders. Escaping user input is not a substitute.
- **XSS:** use context-aware output encoding and safe DOM APIs such as
  `textContent`. Prefer framework-native escaping. Sanitise only when trusted
  HTML rendering is an explicit requirement.
- **Path traversal:** canonicalise first, then enforce allowlisted roots with a
  containment check. Blacklisting `..` is insufficient.
- **SSRF:** allowlist destinations, reject private/link-local/metadata
  addresses, and validate every redirect target.
- **Deserialisation:** prefer data-only formats and restrict permitted types.
- **Cryptography:** use maintained libraries and modern named algorithms.
  Never invent crypto. Use a purpose-built password hash for passwords.

Before editing, trace untrusted data from source to sink and read nearby tests.
Make the smallest change that breaks that flow. Add or extend a regression test
when the project has a test suite.

Suppression comments are not remediation. Re-run the SAST scan and focused
tests before reporting success.
