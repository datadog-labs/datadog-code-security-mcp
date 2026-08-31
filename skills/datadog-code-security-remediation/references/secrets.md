# Secrets remediation playbook

**Deleting the literal is not the fix.** Treat a committed credential as
compromised and rotate or revoke it at the provider before changing code.

1. Identify the secret type, provider, owner, and affected environment without
   reproducing the value.
2. Ask the user to rotate or revoke it. If no available tool can do that,
   provide the provider location and stop before claiming remediation.
3. Replace the literal with the project's existing secret source: environment
   variable, CI secret, or secret manager reference.
4. Verify the application uses the replacement.
5. If the secret reached a shared remote, assume exposure. Discuss history
   rewriting and team coordination, but never force-push or rewrite history
   without explicit approval. Rotation remains mandatory even if history is
   cleaned.

Never echo a secret into chat, logs, diffs, commit messages, or scan summaries.
Refer to its type and file location only.

Test fixtures and documentation examples may be intentional false positives.
Verify that they are non-functional before proposing an ignore, and never
rotate a credential that was never real.

Re-run the Secrets scan after replacement. A clean rescan confirms that the
literal is gone; it does not by itself prove provider-side rotation occurred.
