# Phase 6 — single-operator offline MVP architecture

This replaces the proposed separate deployment-review workflow. The MVP has one
authenticated operator: their Deploy action explicitly authorizes the exact saved,
validated plan. There are no separate reviewer accounts, approval queue, multi-user
approval protocol or approval-management dashboard. The existing Phase 5 planning
authorization, independent-review default, exceptions, IAM and OIDC restrictions
remain unchanged and are not reused to authorize Phase 6.

CURRENT IMPLEMENTATION: MOCK_ONLY. No AWS execution adapter, SDK, credentials,
real provisioning, live inventory scan or live drift refresh is implemented here.
No native Terraform deployment command is constructed or executed. Terraform
configuration validation and security tools run offline; their plan input is a
clearly marked deterministic synthetic fixture, not an authenticated Terraform plan.

## FR-4 / O4: drift detection first

The owner's instruction identifies drift as mandatory under FR-4 and O4 of KL
University CLOUD-08. This mapping is recorded from the owner; the original
specification document is not in this repository and has not been independently
quoted or verified. The implementation compares declared configuration against a
separate observed mock infrastructure snapshot, not the form or planned intent.

The detector distinguishes IN_SYNC, CHANGED, MISSING, UNMANAGED and UNKNOWN.
Incomplete/unavailable/stale observations, wrong state lineage/serial, unresolved
fields, unowned expected resources and unsupported observed attributes remain
UNKNOWN. Known computed identity fields are excluded from managed-attribute
comparison; this is not runtime reachability or effective-access proof.

Changes create persistent deduplicated alerts. UNKNOWN does not clear an alert or
mean no drift. Alerts resolve only after a complete comparison finds the declared
and observed configurations in sync. Alerts are local dashboard records; no email,
Slack, AWS alarm or external notification is sent.

Reconciliation uses the saved declared configuration as its target and generates
a fresh plan with all gates/cost/state checks. The operator explicitly deploys
that exact plan. No automatic reconciliation, silent acceptance of drift or
deletion of unmanaged resources is allowed. Missing observations block mutation.
Native AWS refresh adapters and scheduled live drift detection require future,
separately authorized work; current fixtures must never be labeled actual AWS.

## Architecture and authority

```text
Authenticated operator -> closed EC2/S3/VPC configuration -> deterministic HCL
 -> offline Terraform validation + Checkov source scan + OPA/Conftest fixture checks
 -> cost fixture/budget checks + private immutable plan artifacts
 -> READY or BLOCKED preview -> operator Deploy action on that exact plan
 -> transactional mock worker -> observed mock inventory + deployment history
 -> drift comparison -> alerts -> new gated reconciliation preview
```

The new loopback service is separate from AI advisory. It has no AI endpoint and
never submits configurations, state, identities or policy contents to OpenAI.
Model output cannot reach configuration, gates, cost limits, job state or workers.

## Operator authorization without a reviewer workflow

A server-side operator secret establishes a 15-minute HttpOnly/SameSite session.
The secret never enters source, logs, browser storage or child-tool environments.
State-changing POSTs require the session, exact allowed origin/host, a custom
client header and session-bound CSRF token. Login is rate-limited; errors are fixed
and do not echo input. This is loopback development authentication, not production
OIDC login or a claim that plain local HTTP protects a remote deployment service.

Every preview binds configuration, template/source revision, exact artifact bytes,
gate evidence, mock price catalog/limit, state lineage/serial, observation revision,
expiry and an opaque single-use plan ID. The browser receives counts, gate results,
mock estimates and opaque IDs, never raw plans/state/policies or private fingerprints.
The operator's Deploy action is the authorization; there is no second approval step.

The server revalidates all bindings under a workspace transaction before consuming
the job. A stale, changed, expired, failed, UNKNOWN or missing input is denied.
Idempotent delivery of the same completed request returns the same result; a new
request cannot replay the consumed plan. Changing configuration requires a fresh
preview. No silent replanning occurs during Deploy.

States: READY / BLOCKED -> EXECUTING -> MOCK_SUCCEEDED or RECOVERY_REQUIRED.
A persistent short execution lease prevents overlapping mutations. Interrupted jobs
need explicit operator recovery after lease expiry; they are not silently unlocked.

## Configuration, gates, costs and deletion

Closed typed input covers Mumbai-only VPC/private subnet, EC2 size/hours/encrypted
root disk and S3 storage/request/transfer assumptions. Only approved mock AMI and
instance-type choices are accepted. No arbitrary HCL, IAM roles, credentials,
provider endpoints, user data, profiles, public admin access or external modules.
Terraform/provider versions remain 1.9.8 / 6.65.0. Generation uses reviewed static
structure with validated scalar input, and deterministic native HCL so Checkov
3.2.471 discovers source resources. JSON-only directory input is not treated as a
successful empty source scan. S3 companion references are explicit source links.

Mandatory gates: offline Terraform schema validation, Checkov, OPA, Conftest and
cost/budget checks. The generated source gets NO resource-scoped exemptions and
must have nonempty successful coverage, zero failures, zero skips and zero parsing
errors. Phase 1's six accepted exceptions remain confined to their original scope.
Actual generated-source findings block Deploy; they are not waived to make a demo.

Prices are explicitly illustrative MOCK_ONLY fixtures, not current AWS prices or
billing promises. Decimal arithmetic, configurable operator ceiling, requested
budget, usage bounds, price expiry and missing/invalid-price rejection are enforced.
Real regional pricing, billing alerts and complete production cost coverage are
NOT IMPLEMENTED. Unknown cost never becomes zero or enables Deploy.

Removing an EC2/S3 component uses a fresh preview; dependent network deletion is
rejected unless its compute dependency is removed. A whole-workspace deletion
preview is also available. Any deletes/replacements require typing the exact
server-generated resource-count confirmation before Deploy. Nonempty mock buckets
require data-retention review and cannot be emptied/force-deleted by this API.
Unmanaged/unowned resources cannot be reconciled or deleted.

## State, audit and fault recovery

Mock SQLite state and artifacts live only under ignored reports/private/phase6-mock.
Native artifacts/logs are not served by Vite or returned by the API. SQLite FULL
synchronous transactions, state serials, sealed immutable jobs, artifact hashes
and chained audit events detect ordinary corruption/substitution. History records
server-derived operator identity, action, sequence, time, job and state serial.

This local store is not encrypted, externally anchored or administrator-tamper-proof.
An administrator can rewrite/restore the complete database/history. It is not a
production state backend or multi-host/cloud-sync locking design. Real state needs
separately provisioned encryption, locking, backups and immutable audit retention.
Do not add unsupported S3 lockfile arguments to Terraform 1.9.8. Future backend
selection must use a separately tested version and reviewed state permissions.

Partial mock failures retain the observed partial result and mark RECOVERY_REQUIRED,
never success or automatic rollback. Recovery creates a fresh gated plan against
current observed state and needs a new explicit Deploy action. Failed jobs and
their audit history remain visible; old plan consumption is not undone.

## Future AWS boundary

No expansion of cloudguard-ai-plan, live IAM change, planning-variable enablement
or Phase 5 authorization activation occurs. A future AWS worker needs separate
least-privilege provisioning/deletion/state permissions, exact workspace ownership,
isolation, reviewed price/AMI sources and real saved-plan/state bindings. Existing
read-only permissions cannot provision resources. Future AWS activation requires
separate owner authorization; that operational restriction is not an MVP reviewer
workflow or approval dashboard.
