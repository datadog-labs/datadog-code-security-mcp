# SAST remediation playbook

Fix the vulnerability at its source while preserving intended behavior.

## Fix by vulnerability class

- **SQL injection:** use the database or ORM's parameter API, not escaping.
  Replace `db.Query("SELECT ... WHERE id="+id)` with the driver's placeholder
  form, such as `db.Query("SELECT ... WHERE id = ?", id)`. With an ORM, bind
  values through its expression/query API; never build a raw clause with
  interpolation.
- **XSS:** replace `node.innerHTML = value` with
  `node.textContent = value`. Keep framework-native escaping enabled. If the
  product intentionally accepts HTML, sanitise it with a maintained,
  context-appropriate library before rendering; URL, attribute, JavaScript,
  CSS, and HTML contexts require different handling.
- **Path traversal:** canonicalise both paths and prove containment. In Python,
  replace `open(base / user_path)` with resolution followed by
  `candidate.relative_to(base.resolve())` before opening. In Go, use
  `filepath.Abs`/`EvalSymlinks` as appropriate and `filepath.Rel`; reject
  `..` or absolute results. A textual blacklist for `..` is bypassable.
- **Command injection:** avoid the shell. Replace
  `exec.Command("sh", "-c", "tool "+input)` with
  `exec.Command("tool", input)` and validate arguments against the operation's
  allowed values. Do not solve shell injection by adding quotes or escaping.
- **SSRF:** replace `http.Get(userURL)` with a fetch helper that parses the URL
  and requires its scheme, hostname, port, and resolved addresses to satisfy an
  allowlist before connecting. Reject loopback, private, link-local, and cloud
  metadata addresses. Disable automatic redirects or repeat the complete
  validation for every redirect.
- **Insecure deserialisation:** choose a data-only format and schema. Replace
  Python `yaml.load(data, Loader=yaml.Loader)` with `yaml.safe_load(data)`;
  avoid Java native object deserialisation for untrusted bytes. If typed
  deserialisation is unavoidable, allowlist concrete types and disable dynamic
  type resolution.
- **Weak crypto or hashing:** use maintained primitives with safe defaults.
  Replace token generation from Go `math/rand` with `crypto/rand`. Use
  Argon2id, scrypt, bcrypt, or the project's approved password-hashing API for
  passwords—not a fast general hash. Never hand-roll cryptography.

Before editing, trace untrusted data from source to sink and read nearby tests.
Make the smallest change that breaks that flow. Add or extend a regression test
when the project has a test suite. Preserve valid inputs and intended error
behavior; if the secure design changes semantics, explain it and ask first.

LOW findings are still findings. Present them after higher severities and
evaluate their actual data flow and reachability rather than dismissing them
solely because of severity.

Suppression comments are not remediation. Re-run the SAST scan and focused
tests before reporting success.
