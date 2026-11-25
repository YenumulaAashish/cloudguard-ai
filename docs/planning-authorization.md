# Bounded read-only planning authorization

CODED AND OFFLINE TESTED; NOT ACTIVATED OR HOSTED-VERIFIED. No new owner approval
has been issued. CG-SM-PLAN-002 remains consumed by run 45484703135. The template
security/planning-authorization.template.json is intentionally NOT_APPROVED and
cannot initialize a ledger. A seven-day/five-attempt proposal is not permission.

## Authority and feasibility

The authenticated workflow now requires a dedicated Linux runner carrying the
cloudguard-readonly-plan label and a private durable local volume outside the
checkout. The existing hosted offline workflow is unchanged. A disappearing
artifact/cache or Git branch is not used as a quota authority; no repository write
permission or AWS IAM permission is added. The GitHub token gains only actions:read
for environment-approval history. Existing contents:read and id-token:write remain.

The dedicated runner/group must be restricted externally to this repository's
reviewed main planning workflow. Never register it for fork/PR jobs or general
untrusted code. Prefer a disposable isolated job environment with a durable mounted
ledger, no ambient AWS credentials and cleanup of credential/process remnants.
A runner label alone is NOT access control. If the operator cannot provide this
isolation and persistent storage, keep planning disabled; ordinary GitHub-hosted
ephemeral disks cannot implement this design. Do not silently fall back to them.
GitHub documents the trust risks of [self-hosted runners](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions).

Feasibility blocker: organization runner groups can restrict selected workflows;
a personal public repository may not have that control. Verify eligibility rather
than treating a label or repository-only runner registration as equivalent. If
this repository lacks a workflow-restricted group or independently enforced runner
admission boundary, **do not register/activate this runner or grant**. Do not transfer
the repository or change the confirmed OIDC trust to work around this constraint.
A separate remote transactional authority for GitHub-hosted jobs is an alternative
architecture, not implemented or approved here. The local backend's tested quota
logic is not a claim that safe hosted deployment is presently available. See
[GitHub runner-group access restrictions](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access).

This is trusted-runner admission enforcement, not an AWS STS quota or a malicious
administrator sandbox. Reviewed code, runner clock, filesystem and operator are
trusted. Existing IAM trust remains exact StringEquals for the confirmed subject
and sts.amazonaws.com audience; no IAM policy, role or Terraform bootstrap changes.
A compromised privileged runner or owner can bypass code-level controls. Restoring
BOTH DB and anchor can roll history back; this is not cryptographic anti-rollback
against the storage administrator. Recovery therefore requires owner reconciliation
of run history and fresh approval; never reset a ledger to gain quota.

## Actual implemented guarantees

- Explicit owner-approved grant: exact source SHA and fingerprint, repository and
  immutable IDs, main ref/workflow, read-only role name, sandbox bucket and Mumbai.
  Changing source or bucket requires an explicit new reviewed scope binding.
- Window no longer than seven days, at most five reservations and at most two per
  UTC calendar day. Lower limits are supported; booleans are not numeric limits.
- Reservations close forty minutes before UTC midnight or grant expiry. This
  conservative admission margin accommodates the 25-minute job timeout and
  15-minute STS session, preventing a reservation from spilling across daily limits.
- Manual workflow_dispatch only; run_attempt must be 1. GitHub reruns are denied.
- Independent human review is required by default. The fresh owner grant must
  explicitly set allow_self_review true to permit the dispatcher to approve. A
  consumed historical accommodation is not inherited; a string flag is invalid.
- Before STS: all current deterministic gates pass, evidence age is at most 30
  minutes, main is protected and still at the dispatched SHA, and the GitHub review
  history contains human approval for aws-plan. Missing API access/data denies.
- The reservation commits before requesting credentials. Authentication failure,
  cancellation and policy failure still spend an attempt. No refund or auto retry.
- Workflow cancel-in-progress is false. An exclusive filesystem lock and SQLite
  BEGIN IMMEDIATE serialize local mutations; a persistent active reservation
  prevents overlapping attempts even across independent invocations.
- A random run-bound nonce and persisted run ID prevent replay. Start consumes the
  reservation exactly once and rechecks scope, evidence, review, protection and
  expiry after STS. Terraform subprocesses have a deadline bounded by grant expiry.
- Missing/corrupt DB, missing/mismatched sidecar, stale lock, unfinished reservation,
  backward clock or partial commit fails closed. No workflow initializes storage.
- Explicit revocation blocks future reservation/start. Existing 900-second STS
  sessions are not revoked by a local ledger; operator credential/process cleanup
  and AWS session expiry remain separate controls. Deadline checks do not attest
  provider-child termination on a compromised runner.

SQLite commits are durable on a correctly configured local filesystem. The
separately fsynced digest sidecar detects a DB-only rollback. A crash between DB
commit and sidecar replacement deliberately blocks subsequent use instead of
repairing or replaying it. A stale lock requires operator investigation; do not
add automatic lock deletion. See [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html).
Only one host may use a volume; no NFS/SMB or replicated multi-writer ledger.
A future remote authority needs authenticated CAS/transactions and independent
anti-rollback storage, not an HTTP wrapper around an ephemeral database.

## Operator procedure — requires separate approval, not performed here

1. Merge reviewed code through required PR checks. Verify current main SHA and
   source digest from that exact main offline run; verify branch protection,
   required status checks, exact live trust, unchanged read-only role, sandbox
   bucket, region, environment reviewer and runner-group restrictions. Do not put
   role/account/bucket identities in public reports or AI requests.
2. Obtain a new explicit owner grant for exact scope, UTC start/end, <=7 days,
   <=5 total and <=2/day, including allow_self_review true only for a separately approved temporary
   environment self-review exception. The checked-in template defaults false.
   Independent-review accommodations are not inferred from old approvals.
3. Populate a private copy of the inactive template with APPROVED and precise
   approval timestamp. Keep it and the database outside the repository and public
   artifacts in an operator-created private local directory. Do not version real
   account identifiers or the populated grant.
4. On the trusted host OUTSIDE GitHub Actions, provision exactly once:
   python scripts/manage-planning-ledger.py initialize --ledger ABSOLUTE_PRIVATE_PATH
   --approval-record PRIVATE_APPROVED_RECORD --confirm-separate-owner-approval
   (One command, shown wrapped.) Existing authorities cannot be overwritten.
5. Only after separate owner approval, configure CLOUDGUARD_LEDGER_PATH and verify
   required environment/branch/runner protections, then enable the existing two
   planning switches. Manually dispatch main and human-review the environment.
6. Record run outcomes privately; inspect safe policy reasons and review UNKNOWN
   findings. At expiry/exhaustion/revocation disable both switches and restore
   review accommodations. Revoke locally with the operator command's revoke action.
7. On crash, lost receipt or stale active attempt, stop. Preserve the DB/sidecar and
   reconcile consumed attempts with GitHub before operator closure/reapproval. No
   automatic recovery or arbitrary decrement/reset endpoint is provided.

Authentication requests may still be made outside this reviewed workflow by a
principal satisfying the existing trust. Preventing that at STS would require a
separately approved trust/identity architecture; this task does not change it.

## API and action contracts reviewed

The human-review check uses the documented [workflow review-history API](https://docs.github.com/en/rest/actions/workflow-runs#get-the-review-history-for-a-workflow-run),
with actions:read and a human User approval for aws-plan. Rejected review history
fails closed even if another entry approved it. Authentication disables the
[action's STS retry mechanism](https://github.com/aws-actions/configure-aws-credentials/blob/v6.3.0/action.yml).
No live approval-history lookup or AWS authentication was performed by this task;
positive/negative tests inject representative API responses.
