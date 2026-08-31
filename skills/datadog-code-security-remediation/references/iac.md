# IaC remediation playbook

Trace the insecure value to its real source before editing. The scanner may
point to a resource whose value comes from a Terraform module default,
`tfvars`, Helm values, a Kustomize overlay, or another generated layer. Fix the
source rather than hardcoding a contradictory override at the use site.

Account for the target environment. A development fixture may intentionally be
permissive; ask before changing semantics when intent is unclear.

Common safe directions include least-privilege IAM and network rules,
encryption in transit and at rest, audit logging, non-root containers, pinned
image tags, bounded resources, and avoiding privileged or host-mounted
workloads. Apply the platform's native secure option rather than deleting the
resource or silencing the rule.

**Never apply infrastructure changes.** Run formatters and static validation.
You may propose or run a read-only `terraform plan` with the user's approval,
but do not run `terraform apply`, deploy a manifest, or mutate cloud resources.

Explain that fixing code does not fix already-deployed infrastructure; the live
resource remains vulnerable until the normal deployment process applies the
change. Re-run the IaC scan before reporting the source finding as fixed.
