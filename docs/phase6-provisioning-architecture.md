# Phase 6: single-operator AWS integration architecture

The platform now has two execution adapters: the existing deterministic mock engine
and a native AWS backend in `backend/cloudguard_live`. The live backend is CODED,
not CONFIGURED or AWS VERIFIED. Repository activation templates are NOT_APPROVED.
No AWS account API, authenticated planning, deployment or remote state change was
performed during implementation. Offline SDK/process doubles are not live proof.

There is one authenticated operator. Their Deploy action authorizes one exact
saved, validated plan. There are no reviewer accounts or approval-management UI.
Owner review of infrastructure/host configuration before first live activation is
a platform installation boundary, not a separate per-deployment reviewer workflow.
Phase 5 OIDC, IAM, planning approvals/ledger and deterministic policies are intact.

## Native execution path

```text
Explicit operator connectivity verification -> private owner-bound configuration
 -> temporary credentials, exact STS account/role, support-resource checks
 -> deterministic HCL -> native Terraform remote-backend plan (exit 0 or 2)
 -> private binary plan and show JSON -> Checkov + OPA + Conftest + reviewed cost
 -> immutable, expiring READY preview -> authenticated operator Deploy action
 -> atomic one-use job + remote state lineage/serial/content check
 -> saved binary plan execution with Terraform backend locking
 -> native state observation, live inventory, private history and audit chain
 -> refresh-only drift -> local alerts -> fresh gated reconciliation/deletion
```

The AWS worker is outside CI command surfaces. No workflow imports or runs it;
the reviewed CI contract pins its code as well as the unchanged CI workflows.
Offline tests inject every AWS/process boundary. The credential-free policy-tool
environment remains stripped of operator, AWS and AI secrets. The native worker's
allowlisted child environment contains temporary AWS credentials only. Raw plans,
state, source, identities, IAM/policy documents and subprocess errors stay private.
Only closed-schema reason codes, opaque inventory IDs and gate summaries reach UI.
This service never calls an AI model or forwards configuration to advisory.

## FR-4 / O4: actual drift before reconciliation

The live adapter plans with `-refresh-only` against the declared configuration;
it does not apply refresh or write refreshed state. Native `resource_drift` gives
changed/missing resources, while unresolved values, refresh errors or concurrent
state change give UNKNOWN. It never interprets a failed observation as IN_SYNC.
Alerts stay open until a successful in-sync comparison. This is explicit on-demand
detection, not a scheduled monitoring service or a resource reachability test.
Live EC2/VPC tag discovery labels resources outside native state as unowned; tags
never authorize deletion. S3 inventory targets state-owned buckets rather than
listing an entire account. Inventory failure returns UNKNOWN. Unmanaged discovery
is displayed separately; refresh-only drift covers Terraform-managed resources.

Reconciliation produces a new normal native plan. Normal configuration plans with
known drift are blocked until explicit reconciliation. Unknown drift blocks even
reconciliation. Deletion uses a new gated plan against disabled configuration,
never a direct destroy command. Source security checks on final deletion examine
the retained declared source; native validation and OPA/Conftest examine the actual
deleting target/plan. The retained source is hashed and cannot reintroduce resources
into the native target. Versioned objects, delete markers and multipart uploads
block deletion; the worker never empties a bucket. A typed live deletion phrase and
a separate installation-level deletion permission are required.

## Authorization, concurrency and recovery

The original Host/Origin checks, loopback-only bind, HttpOnly SameSite session,
CSRF token, login throttling and 15-minute session remain. No requests start on
page load. A successful connection is not deployment authorization. UI warnings
age out after five minutes; the backend independently rechecks grants/credentials.

Private installation grants bind exact source and configuration digests, reviewed
host-isolation digest and at most seven days. Read access, remote-lock writes,
deployment and deletion are distinct permissions. Grant changes/expiry/revocation,
source or price changes and stale state invalidate plans. Repository templates and
missing grants fail closed. Short-lived session credentials are mandatory; the
AWS SDK uses an explicit session, no default profile/metadata chain, and no retries.
Credential changes invalidate the verified connection. Native provider and backend
both pin the allowed account. Credentials must outlive the operation; uncertain
expiry/timeouts require recovery and never count as success.

An exclusive service lock prevents two service processes; private SQLite immediate
transactions serialize workspace consumption. Each saved plan expires in ten
minutes. A unique request ID makes delivery idempotent without re-executing a
completed or failed attempt. Remote Terraform locks protect against other clients;
no force-unlock or lock disable exists. Every execution attempt advances the workspace generation and invalidates other saved plans. Native execution failures become RECOVERY_REQUIRED, never an automatic retry/rollback. Inventory remains UNKNOWN while execution or recovery is uncertain. Recovery requires a fresh owner/operator grant after incident inspection, then a newly gated plan; no additional reviewer account is introduced. A crashed EXECUTING worker
remains blocked until an owner checks its process/backend lock/state manually.
Recovery generates another plan and requires another operator Deploy action.

The hash chain detects accidental edits, not a malicious host administrator who
can rewrite all files. The host and private directory are a trusted installation
boundary. Windows ACLs, encryption and backup integrity require owner verification;
POSIX mode bits do not establish Windows isolation. See [owner setup](phase6-live-setup.md).

## State and reproducibility

Terraform 1.9.8 and AWS provider 6.65.0 remain pinned, with the committed provider
lock copied into each private working directory. Native init uses the verified
local provider mirror only. S3 state requires a Mumbai versioned, private TLS-only
KMS bucket plus a dedicated DynamoDB LockID table. This preserves the existing
Terraform toolchain. DynamoDB locking is deprecated by current HashiCorp guidance,
so a separately tested Terraform upgrade and migration to S3 native lockfiles is
required before removing that table; this implementation does not pretend 1.9.8
supports newer lockfile options. No state migrations run automatically.

[HashiCorp S3 backend and locking reference](https://developer.hashicorp.com/terraform/language/backend/s3).
