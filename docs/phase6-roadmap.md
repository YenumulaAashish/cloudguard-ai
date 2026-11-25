# Phase 6 implementation roadmap — DESIGN ONLY

The existing phase6-provisioning-architecture.md remains the design authority.
No provisioning API, apply worker, IAM permission, resource or deployment UI is
implemented here. Phase 5's read-only role and admission ledger must not become a
deployment authority.

1. Review architecture and threat model with owner: separate deployment API and
   worker from advisory; authenticated users, tenant authorization, CSRF, audit and
   budgets. Approve permitted regions/services/quotas and costs before implementation.
2. Specify closed EC2/S3/VPC request schemas and reviewed static templates. VPC CIDRs,
   subnet/route counts and sources must be bounded. EC2 needs approved AMI/type,
   private subnet, IMDSv2 and encrypted storage. S3 needs private access, encryption,
   TLS, ownership/versioning and reviewed retention. No arbitrary HCL, policies,
   user data, provider endpoints, shell commands or AI-generated executable input.
3. Design separately approved IAM principals and private state/locking storage.
   Preserve the plan-only role; least-privilege deployment/cleanup roles require
   independent review. Select a tested pinned Terraform/backend combination.
4. Build an offline planner/control-plane prototype with immutable configuration
   revisions, idempotent jobs, source/plan/state/gate digests and cost envelopes.
   All failures/unknown required context block privileged execution.
5. Implement the exact-plan approval protocol from the architecture: short expiry,
   one-time approval, per-workspace concurrency lock, state-change detection and
   immutable saved plan. No silent replanning or model authority.
6. Only after a separate owner decision, implement isolated privileged workers,
   scoped short-lived credentials, bounded network access and audited status.
   Inventory must derive from verified execution/state, not UI intent or AI prose.
7. Validate positive/negative tenant, replay, stale-plan, cost, state-lock, policy,
   cancellation and recovery cases offline first. A later explicitly approved
   disposable sandbox exercise precedes any supported provisioning release.

Review gates: architecture approval -> schema/template tests -> state/IAM review ->
plan-bound approval tests -> isolated-worker review -> authorized sandbox validation.
None of these gates is an authorization to begin provisioning during this task.
