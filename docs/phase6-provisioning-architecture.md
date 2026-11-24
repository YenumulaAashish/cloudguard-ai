# Phase 6 design — secure dashboard-controlled provisioning

DESIGN ONLY. No privileged endpoint, role, state backend, resource or deployment
execution is implemented by Phase 5. The current read-only plan role is unchanged.

## Architecture and authority

```text
Authenticated user → schema-validated resource form → deployment API
  → isolated job + reviewed Terraform templates → deterministic gates
  → immutable private saved plan + public review summary + cost envelope
  → explicit user approval bound to plan → isolated deployment worker
  → audited execution status → inventory/history → dashboard
```

Keep the advisory server separate from this privileged control plane. Model output
has no route to form configuration, generated Terraform, approval tokens, worker
commands, roles, inventory authority or gate decisions. Reuse the dashboard's public
contracts and analyzers. Raw plans/state stay in private encrypted storage, never
in the browser, PR artifacts, OpenAI payloads or ordinary logs.

## Components and configuration contracts

| Component | Required behavior and default constraints |
|---|---|
| Authentication/API | OIDC login with secure server session; user/workspace authorization; CSRF defense; no browser AWS keys; audit actor and tenant on every operation |
| Configuration forms | Closed versioned JSON schemas and server revalidation; reject arbitrary HCL, provider/backend blocks, URLs, shell/user data and environment metadata |
| VPC/subnets | Region ap-south-1 initially; validated RFC1918 CIDRs, no overlap, bounded subnet count, AZ allowlist, private routing by default |
| Security groups | Default deny; typed rules with explicit direction/protocol/ranges and approved sources; reject public admin ports and unbounded ingress; changes must pass existing policies |
| EC2 | Initially at most one allowlisted small instance type, approved AMI catalog, private subnet, no public IP, IMDSv2, encrypted root disk; no arbitrary instance profiles or user data |
| EBS | Bounded encrypted gp3 volumes, size/performance limits, permitted AZ, explicit attachment dependencies, deletion/snapshot retention policy |
| S3 | Private access, TLS enforcement, versioning, encryption, ownership, required tags; no force-delete or automatic object deletion; logging/replication choices require reviewed cost/design decisions |
| Template generator | Typed variables into reviewed static modules; JSON encoding, no shell interpolation, no arbitrary Terraform expressions/provider endpoints/provisioners/remote modules |
| Worker isolation | Ephemeral non-root jobs, controlled binaries and provider mirror/lockfiles, bounded network egress, no user commands or host credentials, per-workspace concurrency lock |
| Job storage | Transactional database for immutable config revisions, actor, gate results, approval and job state; private object storage for plan/state artifacts; idempotency keys |
| Inventory/history | Resources identified by approved workspace/state and ownership tags; track actual execution and refresh outcome; never treat a UI request or AI advice as deployed state |

Numbers above are proposed initial limits, not approved cloud spending. Require a
reviewed quota configuration and budget owner before enabling any deployment. Add
NAT, public endpoints, large instances and paid services only through later review.
Do not weaken the existing six Checkov exception contract for new resources; new
architecture must satisfy gates or obtain a separate explicit security decision.

## State and IAM boundaries

Bootstrap the private versioned state store and encryption policy through a
separately approved administrator process. Use one state key and lock per authorized
workspace, S3 public-access blocking, encryption, precise prefix permissions, state
version recovery and deletion protections. Current Terraform 1.9.8 remains unchanged
in Phase 5. Before Phase 6 select/pin a separately tested Terraform version supporting
S3 native lockfiles; do not place unsupported backend arguments in the current root.
Native locking and the distinct lock-object permissions are documented in the
[HashiCorp S3 backend contract](https://developer.hashicorp.com/terraform/language/backend/s3).
DynamoDB locking is deprecated; do not introduce a new dependency on it by default.

Use separate principals and trust conditions for planning, deployment and cleanup.
Do not expand `cloudguard-ai-plan`. A new Phase 6 planning role may need narrowly
scoped state-lock access under the approved backend design; metadata read permission
alone is not enough. Deployment roles have only the required service actions,
region, ownership/request tags and named state prefix. Cleanup is a distinct,
explicitly approved workflow/role with stronger destructive-action review. Workers
receive short-lived credentials only after job authorization. The API itself does
not hold deployment credentials. Never grant administrator or wildcard PassRole.
If EC2 instance profiles are eventually required, allow only preapproved role ARNs
and EC2 service use, following [AWS PassRole guidance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/permission-to-pass-iam-roles.html).
Creation of IAM roles by end-user forms is outside the initial resource scope.

## Exact-plan approval protocol

Maintain an immutable configuration revision and saved binary plan in private
storage. After a successful plan, bind approval to the actor, authorized workspace,
exact source commit/template revision, configuration digest, Terraform/provider
versions and lockfile digest, binary plan digest, baseline state lineage/serial,
gate-evidence digest, cost envelope, expiry and one-time nonce. These private digests
belong to the future control-plane audit record, not the current public report or AI.
The browser receives an opaque approval ID and sanitized human-readable diff/cost
summary. Its approval action is CSRF-protected, authenticated, short-lived and
server-verified; it cannot supply substitute digests or override a gate result.

Before execution, acquire a per-workspace lock and atomically consume the approval.
Verify artifact integrity, actor authorization, expiry, unchanged config/source,
required gates, current state serial/lineage and cost bounds. Reject stale, replayed,
replaced or unbound artifacts. Any change requires a new plan and fresh approval;
never silently replan between approval and execution. Apply only the exact saved
plan in the isolated worker. A report SHA or UI button alone cannot prove this chain.
This protocol is design work and grants no present deployment authorization.

Suggested job states: DRAFT → VALIDATED → PLANNING → REVIEW_REQUIRED → APPROVED →
EXECUTING → SUCCEEDED or FAILED. Also support REJECTED, EXPIRED and CANCELLED with
explicit allowed transitions. Timeout/partial execution is not success or automatic
rollback. Persist events before state transitions and make retries idempotent.

## Gates, costs, history and cleanup

Run format/validate/lint, source Checkov and exact exceptions, real-plan Conftest,
all analyzers and ownership/quota/cost checks before an approval can be created.
Document analyzer review flags separately from blocking policy verdicts; do not
quietly convert informational posture into a new gate or clear UNKNOWN values.
Deployment policy must explicitly define which unresolved facts block execution.
AI remains advisory and never resolves an unknown into permission to deploy.

Cost estimation uses a reviewed regional price source with recorded price timestamp,
currency, time horizon and bounded assumptions for compute, EBS, S3, requests and
transfer. Missing prices/usage are UNKNOWN and block budget approval; they are not
zero. Require per-resource, per-workspace and global configurable quotas plus a
maximum reviewed estimate. Real bills can differ because usage is uncertain;
budget alerts and expiry cleanup are separately approved operational controls.

Record actor, config revision, approved change summary, job transitions, gate IDs,
private artifact references, cost assumptions, session identity and provider result
with redacted errors. Audit events should be append-only with restricted deletion
and retention settings. Correlate with cloud audit logs after separately approving
their configuration/costs. Tenant-scoped history and inventory APIs must reject
cross-workspace IDs. UI status is obtained from persisted worker events, not polling
raw Terraform output or assuming success after a timeout.

Cleanup requires an inventory/ownership-verified preview, data-retention review,
its own exact-plan approval and narrowly scoped cleanup role. Never delete arbitrary
tagged/untracked resources, empty buckets, discard EBS data/snapshots or force-unlock
state automatically. Partial failures require reconciliation and a new reviewed
cleanup plan. Expiry may notify and propose cleanup; it does not authorize it.

## Threat model and acceptance criteria

| Threat | Required acceptance test |
|---|---|
| Unauthorized or cross-tenant provisioning | Unauthenticated, CSRF, forged actor/workspace and object-ID access denied before any credential issuance |
| Template/command injection or malicious module/provider | Unknown fields, expressions, paths, source URLs and shell payloads rejected; generated files use only reviewed modules/binaries |
| Stolen/replayed approval or plan substitution | Changed binary/config/state/gates/cost/actor, expiry and duplicate execution all fail closed |
| Concurrent/stale state writes | Two jobs cannot execute for one workspace; stale serial/lineage rejected; recovery does not silently force unlock |
| Credentials, state or private evidence leakage | Canary data absent from browser/OpenAI/public artifacts/errors/logs; private stores have tested access isolation |
| Cost abuse | Unsupported pricing, exceeded limits, oversized requests and rapid repeats blocked; no automatic broad retry |
| Excessive IAM or cleanup blast radius | Policy simulation/review verifies narrow resources/conditions; deny cross-region, cross-workspace, arbitrary PassRole and unowned deletion |
| AI-induced gate/approval bypass | Model payloads and prose cannot change configuration, authority fields, job state, approvals or worker commands |
| Partial execution and misleading inventory | Failure/timeout never marked success; reconciliation is explicit, bounded and audited |

## Implementation sequence and dependencies

1. Close Phase 5 with explicit security exception decision, hosted PR checks and
   separately authorized authenticated plan evidence. Keep enable switches false.
2. Approve the deployment threat model, budget, resource limits and state/IAM design.
   Select identity provider, database, queue/private artifact store and reviewed
   Terraform version. Provision these only under separate cloud authorization.
3. Implement authentication, tenancy, closed form schemas and pure template generation
   with offline adversarial tests. Add no execution credentials yet.
4. Implement isolated plan jobs, remote-state locking, deterministic gates and cost
   reports. Test against synthetic plans first; then approved sandbox read-only runs.
5. Implement private immutable artifacts, exact-plan one-time approvals, job state
   machine and audit trail. Prove replay/substitution/concurrency defenses offline.
6. After separate deployment authorization, implement the distinct deployment worker
   and narrowly scoped roles. Exercise only approved low-cost sandbox cases with
   failure/recovery tests and an explicit data-retention decision.
7. Add inventory/history and reviewed cleanup. Require the same approval binding
   and threat-model acceptance tests before enabling dashboard deployment controls.

No Phase 6 component is claimed implemented or production-verified by this document.
