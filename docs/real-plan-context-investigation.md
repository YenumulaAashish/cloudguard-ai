# Real-plan security failure — evidence and local reproduction

## Confirmed execution milestones (owner-provided)

Run [45484703135](https://github.com/YenumulaAashish/cloudguard-ai/actions/runs/45484703135),
job 138766888056, main commit `003a26a775ec651b415fe039267bc590bd8eb831`:
OIDC PASS; Terraform plan PASS with exit 2; 18 creates / 0 updates / 0 deletes.
Conftest: 12 passed / 1 failed / 0 warnings / 0 exceptions. Checkov: 30 passed /
0 failed / 6 approved exceptions. Phase 4 integration and sanitized artifact
uploads PASS. Risk: 50/MEDIUM. Nine CGA_DATA_011 UNKNOWN findings (eight entries
on aws_s3_bucket, one on ownership-controls) and 16 unresolved graph relationships.

These are owner-confirmed run facts, not results of new AWS execution by this
task. Authentication and planning succeeded; the security gate correctly kept
the job failed. Neither exit 2 nor successful report publication means compliance.
CG-SM-PLAN-002 is **CONSUMED**, with no retry authorized by its historical expiry.
Its original false activity flags describe the approval-record task, not this
later authenticated run. No new approval, GitHub variable change or run is issued.

## Verified local causes and limits of attribution

All six Rego files were reviewed: common final-state selection, IAM, network,
S3 protection/encryption/ACL, tags and security unknowns. Original messages were
intentionally stripped from public evidence, leaving only counts. The exact
failed deny template in the hosted run is **not confirmed**. Do not call a 12/1
count match proof of a particular rule or declare the real plan compliant.

The installed, locked AWS provider **6.65.0** schema was inspected locally with
`terraform providers schema -json`, using the cached binary/provider and disabled
metadata/checkpoint calls. No AWS API or credentials were used. It identifies:

| Attribute | Schema evidence |
|---|---|
| Bucket acl, policy | optional + computed |
| Bucket ARN, domain names, region, hosted zone | computed |
| Encryption rule bucket_key_enabled, blocked_encryption_types | optional + computed |
| Encryption rule apply_server_side_encryption_by_default.kms_master_key_id | optional + computed |
| Encryption sse_algorithm | required |
| Ownership-controls id/region | computed |

The synthetic `computed-s3.json` uses explicit AES256, known PAB/versioning/
lifecycle/ownership controls, computed IDs/legacy bucket readback, and an unknown
bucket-policy body (its ARN-derived JSON is not yet available). With the original
code it reproduced **12 Conftest successes / 1 UNKNOWN failure**, plus **nine
CGA_DATA_011 findings**. The local Rego denial arose from computed nested encryption
metadata inside `after_unknown.rule`. This is a verified implementation defect
and a strong candidate for the hosted failure, but not its confirmed identity.

Other possible failures remain real blockers: unknown/invalid algorithms, unknown
PAB association/flags, unknown required tags, public SSH/ACL, missing encryption,
or invalid/wildcard IAM. The negative fixtures and existing policies still reject
these cases. The real failing message or equivalent safe rule/reason evidence is
needed to disambiguate. Raw plans and private logs must not be uploaded for that.

## Narrow corrections

Rego only discounts three provider-computed metadata paths under an explicitly
known, single-rule AES256 configuration. Whole unknown rules, algorithm unknowns,
unrecognized paths and KMS unknowns still block. Companion association and positive
encryption checks remain mandatory. This does not establish arbitrary unknown
encryption as safe or remove a deny category; no skip or exemption is added.

The data analyzer previously used any unknown legacy bucket field to invalidate
all eight categories. It now evaluates each known dedicated companion independently.
Missing controls with unresolved legacy context remain UNKNOWN; explicit nonempty
inline legacy configuration remains unsupported. Unknown companion identities,
policy JSON and security fields stay UNKNOWN. Ownership is understood narrowly:
known BucketOwnerEnforced plus all four known PAB flags can mark ACL configuration
REVIEWED, not certify runtime access. Unknown/unsupported ownership stays reviewable.

After the fix, this synthetic plan has 13 Conftest successes and no denial. PAB,
AES256 encryption, enabled versioning and multipart cleanup are ESTABLISHED from
known values; ACL is REVIEWED from ownership/PAB evidence; policy, transport and
logging remain UNKNOWN. This is **not** a prediction of the actual run's next
result, risk score or finding count.

Graph references are resolved only from exact known values. New creates commonly
have unknown VPC/subnet/route IDs, even when the configuration contains dependency
expressions. A dependency is not evidence of a resolved target or reachability.
No guessed name/configuration-reference edges are added. The synthetic fixture
has 12 unresolved relationships; the actual reported 16 remain unresolved facts
requiring the actual private input for exact explanation. No graph UNKNOWN is
converted to PROVEN merely to reduce the count.

## Fixtures and future diagnostics

`tests/fixtures/realistic-plan/` contains four nested-module create-plan fixtures:
known AES256 with computed metadata, unknown algorithm, disabled public block and
unknown companion reference. They are synthetic provider-shaped examples, not
recordings of the private run. The example has 17 resources; it is deliberately
not padded to reproduce the hosted 18-resource count. All four join the original
six Conftest fixtures in offline CI. Dedicated negative OPA/Python cases verify
unknowns and explicit violations still block or require review.

`policy_summary` now adds bounded `failure_reasons` to the existing uploaded
`reports/phase2/plan-policy.json`. Each entry contains only an allowlisted existing
Rego category ID (`UNKNOWN`, `S3_PUBLIC`, etc.), fixed reason code and count.
For example: UNKNOWN / UNRESOLVED_SECURITY_FIELD. It exports no address, dynamic
field string, raw message, filename, metadata, policy JSON or Terraform value.
Unknown templates become UNMAPPED / UNRECOGNIZED_POLICY_MESSAGE, never PASS.
The category IDs identify existing deny message families, not new controls or
severity/risk assignments. Counts/exit semantics remain authoritative and failures
are not truncated. Existing artifact paths/retention/permissions are unchanged.

## Proposed repeatable read-only authorization — NOT APPROVED

A future owner-approved development window could replace one-attempt paperwork
with a bounded standing planning authorization: at most **5 manual attempts in
7 calendar days**, at most **2/day**, existing role/bucket/region and workload scope
only. These are proposed limits, not active permission. Owner must approve exact
scope, dates, permitted review accommodation and attempt budget before enabling.

Every attempt still requires protected-main code, required up-to-date passing
offline checks, protected-environment human review, unchanged exact OIDC trust and
read-only role, and an audit entry with run/SHA/source/gate outcomes and remaining
budget. No auto retry, PR/fork credentials, deployment, state mutation or IAM
expansion is allowed. Normal failed security findings stay failed; a later manually
requested diagnostic plan does not override them. Source changes must go through
the required PR process; workflow/trust/permission/gate weakening or scope changes
require a new explicit security decision, not standing-window reuse.

Use a separately reviewed attempt ledger/concurrency control and expiry enforcement
before claiming machine-enforced budgets. Current booleans/JSON records do not
implement those guarantees. Identity/protection/permission failure, suspected
exposure, scope breach or owner revocation stops the window immediately. On expiry
or budget exhaustion disable both enable/review variables and restore any temporary
review accommodation. No such mechanism or external setting change is implemented
or activated here. CG-SM-PLAN-002 cannot be reused for this proposal.

## Remaining manual steps

Confirm planning variables are disabled and prior review accommodations restored.
Review this branch and separately authorize a push/PR; require its hosted checks.
Obtain explicit new authorization (a new one-shot approval or reviewed standing
model), bind the reviewed main SHA and verify live protections/permissions before
any future attempt. Inspect the new allowlisted failure reasons if that attempt
fails. Do not infer the old run's exact rule from the new synthetic result.
No AWS contact, authenticated retry, apply/destroy, push, merge, variable enablement,
permission expansion or Phase 6 implementation is performed by this task.

## Completed local validation

The final offline runner passed against the current source fingerprint. Terraform
1.9.8 workload and bootstrap format/init/validate, TFLint 0.59.1, all **715 Python
tests**, OPA 1.0.1 **40/40**, Conftest 0.60.0 **10 fixture outcomes**, destructive-CI
guard, hosted-CI contract and evidence generation passed. Checkov 3.2.471 remains
**30 passed / 0 failed / 6 skipped / 0 parsing errors**; exception verification
observed exactly six expected exceptions, none missing or unexpected.

Frontend build and **50 tests**, **3 browser tests**, **1 mock HTTP test** and
**8 exporter tests** passed, along with source/build privacy checks and the local
secret scan. Repeated synthetic integration output was byte-identical across
five private and four sanitized files. Private outputs stay ignored and are not
included in the commit. Cached providers were used; no AWS calls were made.

A new authenticated plan and real-plan policy reevaluation are **NOT RUN**.
The offline summary deliberately reports plan-specific evidence as NOT RUN;
fixture success does not fill in missing authenticated evidence or approve a retry.
