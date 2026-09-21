# Policy contract and limitations

Policies use modern `import rego.v1` and a shared `main.deny` decision. Input is Terraform **plan JSON**, not HCL, state JSON or Conftest's HCL parser output. Production command: `conftest test terraform/tfplan.json --policy policies/terraform`.

`common.rego` prefers managed `resource_changes[].change.after` when a change record exists. It evaluates creates, updates, replacements and no-ops; delete-only and forget-only records are excluded from the final-state view. It does not assess a deleted object's `before` values as newly deployed infrastructure. Nested `planned_values.root_module` supplies unchanged resources and supports the preserved Phase 1 fixtures. Missing plan structure is rejected.

`unknowns.rego` inspects `change.after_unknown`. Unknown policy-relevant ingress, storage protection/encryption, IAM policy and tag fields block the plan; computed IDs/ARNs alone do not. A computed legacy S3 bucket ACL is only tolerated when every planned public-access block is explicitly true, independently proving that the unknown ACL cannot grant public access. Known public ACLs are still rejected. Unknown public-access blocks never satisfy that proof. This is value-based enforcement, not a Checkov-style resource exemption.

Sensitive known values are evaluated normally. `before_sensitive`/`after_sensitive` do not exempt resources or hide values from OPA; they are not used as an evidence-redaction guarantee. The evidence generator separately excludes all values and raw policy messages.

The input format follows the [Terraform JSON specification](https://developer.hashicorp.com/terraform/internals/json-format). Authenticated integration has not run locally. The added change-record tests are explicitly synthetic boundary tests, not a claimed AWS plan capture.

| Concern | Behavior |
|---|---|
| Network | Inline SG rules, legacy standalone ingress rules and modern VPC ingress rules; TCP numeric/string protocols, ranges covering 22, all protocols, IPv4 and IPv6 world CIDRs |
| S3 public access | Every bucket needs all four public access blocks; public ACLs are rejected |
| S3 encryption | Every bucket needs a separate encryption configuration using AES256, aws:kms or aws:kms:dsse |
| Tags | Explicit supported taggable resource types; use tags_all with tags fallback; nonblank baseline tags; ManagedBy must equal Terraform |
| IAM | Managed and inline role/user/group policies; Allow wildcard actions, including service wildcards, and Allow+NotAction are rejected; Deny wildcards are valid; invalid/unknown policy JSON is blocked |

S3 controls are matched using known bucket names in final values. Unknown/generated names or unknown controls block S3 rather than assuming compliance. This can conservatively block otherwise safe plans until values are known; Phase 1 uses an explicit configurable bucket name. No configuration-reference inference is implemented.

These are scoped organization checks, not a complete AWS authorization model. S3 resource-policy semantics, IAM trust policies/attachments and inherited grants are not exhaustively analyzed. Public ACL detection plus mandatory public blocks does not replace a full effective-access review. Unknown-value enforcement covers the documented resource types and security fields; it is not a complete AWS authorization model. Checkov provides an independent configuration scan. Future mutation experiments should measure these limitations, not assume completeness.

Checkov runs its full Terraform ruleset with six inline resource-scoped sandbox exceptions. There are no global skipped IDs, check allowlists or soft failures. [Security exceptions](security-exceptions.md) records each rule ID, resource, reason, security impact, acceptance rationale and review trigger. The seventh initial finding (lifecycle) is resolved by aborting incomplete multipart uploads after seven days; completed objects and versions are retained. Rego policies have no exceptions.

Tests assert positive, negative and boundary behavior for each concern. Insecure fixtures are expected to fail with their specific diagnostic prefix; parser failures or unrelated denials do not count as successful detection.
