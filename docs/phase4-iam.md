# Phase 4.1: deterministic IAM structural analysis

**Deterministic tools decide. AI explains. PR reporting informs.**

The standalone analyzer reads supplied local `terraform show -json` documents;
it never runs Terraform, resolves HCL, queries AWS, downloads managed policies or
calls AI. Phase 3 remains unchanged. Network, storage, graph and posture phases
4.2–4.5 are not implemented.

## Input and project context

The workload has no IAM resources. The separate bootstrap defines an IAM role
with conditioned GitHub federation trust and an inline read policy. Existing Rego
checks four permissions-policy resource types for wildcard actions/NotAction and
unknowns; existing source Checkov remains independent. No real plan was generated
for this phase. Synthetic fixtures are not evidence of AWS state.

Accepted format_version values: 1.0, 1.1 and 1.2, with
planned_values.root_module resources and nested child_modules. resource_changes
change.after takes precedence over snapshots, including unknown creates absent
from the snapshot. after_unknown on a relevant policy produces UNKNOWN; unrelated
unknown attributes do not erase known policy evidence. Delete-only changes are
omitted. Missing/null policies become UNKNOWN. Malformed JSON and malformed
supported structures are hard errors, never passes. Object and JSON-string policy
forms and single-object/list Statement forms are accepted. No interpolation runs.

Supported policy bodies: aws_iam_policy, aws_iam_role_policy,
aws_iam_user_policy, aws_iam_group_policy. aws_iam_role.assume_role_policy is
analyzed separately as trust. Embedded role inline_policy/managed_policy_arns
are not resolved; nonempty or unknown blocks produce UNKNOWN. Other aws_iam_*
resources, including policy-document data sources, produce UNKNOWN. Non-IAM
resources are outside scope. No claim of full Terraform/provider validation is
made; run the existing validators separately.

## Stable controls and severities

| ID | Structural condition | Severity |
|---|---|---|
| CGA_IAM_001 | Allow Action=* and Resource=* | CRITICAL |
| CGA_IAM_002 | Global wildcard action with scoped resource | HIGH |
| CGA_IAM_003 | Service or partial action wildcard | HIGH |
| CGA_IAM_004 | Wildcard resource with Allow permissions | MEDIUM |
| CGA_IAM_005 | IAM privilege-management capability | HIGH |
| CGA_IAM_006 | PassRole with wildcard resource | HIGH |
| CGA_IAM_007 | Scoped PassRole | MEDIUM |
| CGA_IAM_008 | Unrestricted trust principal | HIGH |
| CGA_IAM_009 | Federation without nonempty Condition | MEDIUM |
| CGA_IAM_010 | Unsupported/unresolved context | UNKNOWN |

Action matching is case-insensitive. Privilege management includes
CreatePolicyVersion, SetDefaultPolicyVersion, AttachUserPolicy, AttachRolePolicy,
AttachGroupPolicy, PutUserPolicy, PutRolePolicy, PutGroupPolicy, AddUserToGroup,
CreateAccessKey and UpdateAssumeRolePolicy. Action patterns are matched against
these names and PassRole. This identifies capability, never a confirmed escalation
path. Wildcard Resource alone is not administrator access; legitimate AWS actions
can require it. Resource '*' or '?' patterns count as broad; no ARN existence or
effective resource-scope resolution is attempted.

A full-admin-shaped statement emits only 001, suppressing redundant subordinate
controls. Otherwise one finding per applicable control per statement is emitted.
Exact duplicate statement objects within a policy are suppressed, retaining the
first zero-based index. Sid does not replace indexes; differing objects (including
Sid) are retained. Resources sort lexically, then policy kind, original statement
index and control ID. No timestamps, randomness or new fingerprints are added.

Deny statements never grant access and produce no risk finding. Separate Deny
statements are not combined with Allow to calculate effective permissions.
NotAction, NotResource and NotPrincipal on Allow produce UNKNOWN rather than
being reinterpreted. Conditions are retained as a conditioned boolean; severity
remains structural and effective impact requires review. Condition operators and
external SCPs, boundaries, sessions and policies are not evaluated.

Trust analysis accepts the three explicit STS assume-role actions and examines
AWS/Service/Federated/CanonicalUser principals. '*' is flagged; scoped AWS and
normal service principals are not labeled public. Federation lacking a nonempty
Condition is flagged for review; a Condition does not prove secure OIDC binding.
Unsupported trust actions/principal kinds produce UNKNOWN. Account-root trust,
organization relationships and trust-condition semantics are not resolved.

Attachments always receive UNKNOWN because effective attachment resolution is
outside this contract. Supplied aws_iam_policy content is analyzed independently;
no ARN joins or external managed-policy retrieval are performed. Zero findings
means no supported structural control matched, not effective access approval.

## CLI, schema and bounds

```sh
python scripts/analyze-iam.py --help
python scripts/analyze-iam.py --plan tests/fixtures/iam/admin.json --output reports/private/phase4/iam-report.json
```

Exit 0 means analysis/report generation completed, even with security findings
or UNKNOWNs. Exit 2 means input/schema/dependency/output failure. Reports are
private JSON only, never executable Markdown. Messages are fixed; policy bodies,
actions, conditions and source snippets are not copied. Resource addresses remain
untrusted private identity data. No invented file paths, lines, ARNs or accounts.
Diagnostics omit input values and paths. Output must resolve under reports/private;
exclusive creation prevents overwrite. Failed ordinary writes remove owned files.
As with other single-file CLIs, a hard kill may leave a partial file; validate it
before consumption. Windows inherited ACLs must protect the workspace.

The strict security/iam-report.schema.json closes every object, bounds fields and
uses enums. Runtime validation also binds control IDs to severity/message/status
and verifies summary counts. jsonschema/referencing are existing dependencies;
remote schema retrieval is disabled. No dependencies are added.

Limits: 8 MiB plan input, 2048 snapshot resources and 2048 changes (at most 4096 combined identities), 4096 module nodes,
32 child-module levels, 256 KiB per policy, 256 statements, 128 actions/resources
or principals per list, eight principal kinds, 2048 characters per identity/list
string and 20000 findings. Exceeding limits fails clearly. The CLI checks file
size before JSON loading; direct Python callers must supply bounded JSON values.

## Phase 3 compatibility and verification

`cloudguard.iam.normalized(report)` emits the existing normalized schema using
its Conftest-compatible transport: failed for structural findings, warning for
UNKNOWN, severity unchanged, exception false, source file/lines null. Private
metadata explicitly identifies cloudguard-iam, policy kind, index and conditioning.
This does not claim Conftest executed. Existing risk defaults apply to custom IDs;
no risk-model change is made. The production Phase 3 runner is not modified and
cannot treat this adapter output as matching authoritative real-plan evidence.

Tests cover controls, safe cases, false-positive defenses, unknown creates,
conditions, negated constructs, attachments, malformed JSON, bounds, duplicate
suppression, ordering, schemas, inert malicious strings, no network/execution,
private output collisions and normalized/risk compatibility. Synthetic scoped and
admin fixtures are committed; runtime reports remain ignored. See evidence.md for
actual regression results. Hosted execution, AWS state and effective escalation
remain unverified. Phase 4.2 requires a separately authorized scope.
