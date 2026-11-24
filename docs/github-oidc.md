> **Current execution update**

CG-SM-PLAN-002 is **CONSUMED** by run 45484703135. Owner-confirmed OIDC authentication
and Terraform planning passed; the security verdict failed. Historical approval and
NOT RUN statements below describe earlier checkpoints, not current authorization.
See [the investigation](real-plan-context-investigation.md). No retry or standing authorization is active.

# GitHub OIDC and the read-only plan role

CODED: yes. CONFIGURED: user-reported, not independently inspected. VERIFIED: NOT RUN.
The first authentication attempt failed with AccessDenied in run 45469018350;
post-correction authentication verification is NOT RUN. See the incident below and current approval handoff.
The user reports an existing provider, cloudguard-ai-plan role, repository variables,
protected aws-plan environment and main ruleset. This task did not create, inspect
or modify AWS resources or GitHub settings. The enable switch remains user-controlled.

The exact trust audience is sts.amazonaws.com and subject is:

```text
repo:YenumulaAashish@212769106/cloudguard-ai@1379194368:environment:aws-plan
```

Environment deployment refs and review protections are part of this boundary.
The updated workflow accepts only manual dispatch on protected main, exact repository,
AWS_PLAN_ENABLED=true, AWS_PLAN_REVIEW_APPROVED=true and a nonempty role variable.
The retained same-repository condition is an additional legacy defense; PR and push
triggers are removed. Offline PR checks remain credential-free, with contents: read.
OIDC write permission is only on the guarded plan job; no PR write permissions exist.

`CG-SM-PLAN-001` is **CONSUMED** by failed run 45469018350; its historical
2026-12-01T18:30:00Z cutoff does not authorize another attempt. `CG-SM-PLAN-002`
is **APPROVED_RESTRICTED_SCOPE** on 2026-11-25, expiring 2026-12-01T18:30:00Z. See
[the incident and exact-subject contract](oidc-subject-mismatch.md). The owner
reports the deployed trust was manually corrected; this task did not contact AWS
or verify successful STS exchange. Do not retry until all
reviewed commit, required check, environment and permission bindings are recorded.
No enable variable or GitHub setting is changed here. Deployment, state mutation,
apply/destroy, broader IAM and privileged Phase 6 operations remain prohibited.

## Permission rationale

The role has an inline custom policy, not AdministratorAccess or AWS ReadOnlyAccess. No action wildcard, service write, object download, role chaining, or deployment operation is granted.

| Action group | Why needed | Scope |
|---|---|---|
| sts:GetCallerIdentity | Provider account identity discovery | Resource `*` because this operation has no resource-level scope |
| ec2:DescribeVpcs, DescribeVpcAttribute | Refresh VPC and DNS settings | Resource `*`; requested region ap-south-1 |
| ec2:DescribeSubnets, DescribeInternetGateways, DescribeRouteTables | Refresh configured network resources and associations | Same regional restriction |
| ec2:DescribeSecurityGroups, DescribeSecurityGroupRules, DescribeTags | Refresh security rules and tags | Same regional restriction |
| s3:ListBucket, GetBucketLocation | Bucket existence/location metadata; no object-body reads | Exact sandbox bucket ARN |
| s3:GetBucketAcl, GetBucketPolicy, GetBucketPolicyStatus, GetBucketPublicAccessBlock | Refresh access controls and TLS policy | Exact sandbox bucket ARN |
| s3:GetEncryptionConfiguration, GetBucketVersioning, GetBucketOwnershipControls, GetBucketTagging, GetLifecycleConfiguration | Refresh implemented storage controls | Exact sandbox bucket ARN |
| s3:GetBucketLogging, GetBucketNotification, GetReplicationConfiguration, GetBucketCORS, GetBucketWebsite, GetBucketRequestPayment, GetAccelerateConfiguration, GetBucketObjectLockConfiguration | The AWS provider's bucket refresh can inspect these optional settings even when absent from source | Exact sandbox bucket ARN |

EC2 metadata APIs generally do not support per-resource IAM scoping; region is restricted. S3 metadata can include object names via ListBucket, but there is no GetObject permission. IAM Get/List permissions are intentionally omitted because the workload root has no IAM resources; the bootstrap is a separate administrator operation. This is a minimal starting policy for this root, not a claim of live AWS verification.

## State boundary

The workload root currently uses local state and nothing has been deployed. On a fresh hosted runner, a plan therefore describes intended creation; it is not a drift scan or a comparison with a deployed environment. Before deployment/drift experiments, select a protected remote backend, state locking and precise state-access permissions in a separate review. Do not add backend write permissions to this role by assumption.

References: [GitHub AWS OIDC](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws), [official AWS credential action](https://github.com/aws-actions/configure-aws-credentials), [Terraform JSON format](https://developer.hashicorp.com/terraform/internals/json-format).

Current approval update: **CG-SM-PLAN-002 is APPROVED_RESTRICTED_SCOPE** by the owner
on 2026-11-25 through **2026-12-01T18:30:00Z**. Only environment self-review is
approved. Amendment PR/check/main bindings remain pending; execution is NOT RUN.
See [the current approval handoff](plan-002-approval.md).
