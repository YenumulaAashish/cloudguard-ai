# Phase 6 delivery and verification roadmap

Single operator: configuration -> native preview -> mandatory security and budget
gates -> Deploy authorizes that exact saved plan. No separate reviewer workflow.
Phase 1-5 policies, six legacy Checkov exceptions, OIDC and planning permissions
remain unchanged.

Implemented offline and tested:

- Secure generated Mumbai EC2/VPC/S3 source, including flow logs, least-privilege
  instance-profile binding, KMS, access logging, EventBridge and true cross-region
  replication to a pre-provisioned Hyderabad destination.
- Mock regression adapter and an inactive native AWS adapter: explicit STS/support
  verification, authenticated plan, actual saved-plan deployment code, inventory,
  refresh-only drift, reconciliation, controlled deletion and fault recovery.
- Private remote-state/locking configuration, transactional job consumption,
  replay/expiry/state/artifact/source checks and a closed safe dashboard contract.
- Reviewed live price-export input with fail-closed stale/missing provenance and
  conservative monthly estimates. Mock catalogs cannot authorize live spending.

Before live operation (requires separate owner authorization):

1. Review [architecture](phase6-provisioning-architecture.md),
   [security controls and costs](phase6-generated-security.md) and
   [exact owner configuration requirements](phase6-live-setup.md).
2. Provision a separate trusted service host, state/lock resources, support buckets,
   keys and narrow roles. Review IAM with the account owner. Do not broaden or reuse
   the Phase 5 planning role or put the worker on a repository-controlled runner.
3. Review current Mumbai/Hyderabad price exports and approved AMI, then bind private
   inactive configuration and a short-lived read-only installation grant.
4. Separately authorize explicit connectivity verification and confirm all real
   support checks. Then authorize lock-writing native planning and validate actual
   plan gates. No live test result is claimed by offline SDK doubles.
5. After reviewing those results, separately authorize deployment/deletion capability.
   Execute a small exact-plan exercise, inventory, deliberate safe drift, gated
   reconciliation and version-safe cleanup. Preserve the complete private evidence.

Remaining limitations: on-demand rather than scheduled drift; no billing hard cap;
owner-reviewed rather than automatic AWS pricing retrieval; host ACL/isolation and
rollback-resistant backups require owner administration; DynamoDB locking needs a
future native-lockfile migration; real IAM service condition applicability and
end-to-end AWS behavior are NOT RUN. No live activation, push or merge was done.
