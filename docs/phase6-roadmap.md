# Phase 6 implementation roadmap

The MVP is single-operator. Configuration -> preview -> mandatory automated gates
and budget -> the operator's Deploy action on the exact validated plan. Separate
reviewer accounts, multi-user deployment approvals and approval-management UI are
removed from the MVP. Phase 5's planning authorization and IAM remain intact.

Implemented offline:

1. FR-4/O4 drift classification first: changed/missing/unmanaged/UNKNOWN snapshots,
   freshness and state identity checks, deduplicated local alerts and explicit
   reconciliation through a new gated plan.
2. Closed Mumbai EC2/S3/VPC forms, deterministic native Terraform generation and
   synthetic change preview. No arbitrary Terraform or IAM input.
3. Actual offline Terraform validation, Checkov source scanning and OPA/Conftest
   fixture evaluation; failed/UNKNOWN/missing gates keep Deploy disabled.
4. Decimal mock estimates, configurable budget ceiling, unknown/stale price blocks.
5. One authenticated operator, CSRF/session controls, exact-plan and state/artifact
   integrity checks, expiry, replay prevention and transactional execution lock.
6. Simulated inventory/history, explicit deletion confirmation, nonempty-bucket
   protection, partial-failure recovery and chained private audit records.

Remaining before any real AWS mode (not authorized by this task):

1. Resolve generated-template security findings with an approved architecture and
   cost model; add no global skips or inherited Phase 1 exceptions.
2. Add offline provider/state/refresh contract fixtures for real computed attributes,
   unsupported drift context and native saved-plan replacement semantics.
3. Select reviewed current AMI and regional price sources; implement complete costs
   and budget alerts. Illustrative fixture prices cannot authorize real spending.
4. Design/provision protected state, isolated workers and separate narrow roles.
   Do not reuse or broaden the existing read-only role or bypass Phase 5 controls.
5. Implement a future native AWS planning/refresh adapter only after separate scope
   approval. Validate live inventory/FR-4 drift under read-only authorization first.
6. Separately authorize any real deployment/deletion exercise. Preserve the same
   exact-plan operator action, mandatory gates, explicit deletion confirmation,
   idempotency, locking, recovery and audit controls; no reviewer dashboard required.

No live AWS adapter, provisioning, IAM changes, native deployment, paid AI calls,
push or merge is performed in this offline implementation task.
