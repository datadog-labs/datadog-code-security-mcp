# IaC remediation playbook

Trace the insecure value to its real source before editing. The scanner may
point to a resource whose value comes from a Terraform module default,
`tfvars`, Helm values, a Kustomize overlay, or another generated layer. Fix the
source rather than hardcoding a contradictory override at the use site.

For example, if `module "storage" { public = var.public }` is flagged and
`variable "public" { default = true }` supplies the value, fix the environment
input or default that expresses the wrong policy. Do not add a conflicting
literal to the resource generated inside the module. Trace module inputs,
locals, data sources, workspaces, and `*.tfvars` before choosing the edit.

Account for the target environment. A development fixture may intentionally be
permissive; ask before changing semantics when intent is unclear.

## Format-specific guidance

- **Terraform/HCL:** use provider-native encryption, logging, public-access
  blocks, least-privilege IAM statements, and narrowly scoped network rules.
  Preserve module interfaces when possible. Run `terraform fmt` and
  `terraform validate`; offer a read-only `terraform plan` to show blast radius
  only after confirming the correct initialized workspace and variables.
- **Kubernetes:** replace `privileged: true`, root execution, host namespaces,
  and broad capabilities with a restrictive pod/container
  `securityContext`; avoid `hostPath`, pin images, and set requests/limits.
  First confirm whether the value is owned by this manifest, a ConfigMap or
  Secret reference, or a Helm/Kustomize generation layer and edit that source.
  Do not blindly harden a test fixture or controller that documents a required
  privilege—ask and constrain the exception.
- **Dockerfiles:** use a pinned trusted base image, a non-root `USER`, minimal
  packages, explicit ownership such as `COPY --chown`, and multi-stage builds
  that keep build credentials and tools out of the final image. Do not place
  secrets in `ARG`, `ENV`, or layers.
- **CloudFormation:** change the parameter, mapping, or nested-stack input that
  owns the insecure value. Use native properties for encryption, public access
  blocking, logging, IAM scope, and network boundaries; validate the template
  without creating or updating a stack.
- **Helm:** trace rendered output back through template expressions to the
  chart default and the environment's `values*.yaml`. If
  `privileged: {{ .Values.security.privileged }}` renders insecurely, fix the
  owning values layer rather than hardcoding `false` in the template. Render
  and lint the chart with the same values before rescanning.
- **Kustomize:** trace a generated manifest to its base, component, patch, or
  overlay. Fix the smallest owning layer and render that overlay; do not edit
  generated YAML that the next build will overwrite.

Common safe directions include least-privilege IAM and network rules,
encryption in transit and at rest, audit logging, non-root containers, pinned
image tags, bounded resources, and avoiding privileged or host-mounted
workloads. Apply the platform's native secure option rather than deleting the
resource or silencing the rule.

**Never apply infrastructure changes.** Run formatters, renderers, and static
validation. You may propose or run a read-only `terraform plan` with the
user's approval, but do not run `terraform apply`, deploy a manifest, execute
CloudFormation changes, or mutate Kubernetes or cloud resources.

Explain that fixing code does not fix already-deployed infrastructure; the live
resource remains vulnerable until the normal deployment process applies the
change. Call out any urgent out-of-band mitigation separately, but do not
perform it. Re-run the IaC scan against the same file, module, chart, or overlay
before reporting the source finding as fixed.
