# Secrets remediation playbook

**Deleting the literal is not the fix.** Treat a committed credential as
compromised and rotate or revoke it at the provider before changing code.

1. Identify the secret type, provider, owner, and affected environment without
   reproducing the value.
2. Rotate or revoke it at the provider before editing code. If no approved tool
   can do that, tell the user which provider console or owner must act and stop
   before claiming remediation.
3. Replace the literal with the project's existing secret source: environment
   variable, CI secret, or secret manager reference.
4. Verify the application uses the replacement.
5. If the secret reached a shared remote, assume exposure. Discuss history
   rewriting and team coordination, but never force-push or rewrite history
   without explicit approval. Rotation remains mandatory even if history is
   cleaned.

## Provider handoff

Name the destination and required owner without inventing commands or exposing
the credential:

- **AWS:** IAM access-key management for the owning user or role; disable or
  delete the exposed key and issue replacement access through the approved
  credential flow.
- **GitHub:** the user's token settings, GitHub App installation credentials,
  or Actions environment/repository secrets, according to token type.
- **Datadog:** Organization Settings API or application key management. Confirm
  the Datadog site and owning user/service account before revocation.
- **GCP:** IAM service-account key management or the owning secret in Secret
  Manager; prefer keyless workload identity where the project supports it.
- **Slack:** the owning app's OAuth/token management; reinstall or rotate the
  affected app credential as required.
- **Stripe:** Developers API keys for the correct test or live mode. Preserve
  restricted-key scope rather than replacing it with a broader key.
- **Database connection string:** the database or managed-service credential
  owner must rotate the password/user and update every authorised consumer.
- **Private key or certificate:** revoke/replace through the owning PKI, CA, or
  cloud certificate service; replacing a PEM file alone is not revocation.

Do not batch-remediate unrelated secrets. Confirm owner, environment, rotation
path, and blast radius for each one before proceeding.

Never echo a secret into chat, logs, diffs, commit messages, or scan summaries.
Refer to its type and file location only.

Test fixtures and documentation examples may be intentional false positives.
Verify that they are non-functional before proposing an ignore, and never
rotate a credential that was never real.

If history cleanup is requested, explain that `git filter-repo` or BFG rewrites
commit IDs and normally requires coordinated force-pushes, fresh clones, and
cleanup of forks, caches, artifacts, and open branches. Obtain explicit
approval immediately before any rewrite or force-push. A pushed secret remains
compromised even after all reachable history is cleaned.

Re-run the Secrets scan after replacement. A clean rescan confirms that the
literal is gone; it does not by itself prove provider-side rotation occurred.
