# GitHub OIDC and the read-only plan role

CODED: yes. CONFIGURED: user-reported, not independently inspected. VERIFIED: NOT RUN.
The user reports an existing provider, cloudguard-ai-plan role, repository variables,
protected aws-plan environment and main ruleset. This task did not create, inspect
or modify AWS resources or GitHub settings. The enable switch remains user-controlled.

The exact trust audience is sts.amazonaws.com and subject is:

```text
repo:YenumulaAashish/cloudguard-ai:environment:aws-plan
```

Environment deployment refs and review protections are part of this boundary.
The updated workflow accepts only manual dispatch on protected main, exact repository,
AWS_PLAN_ENABLED=true, AWS_PLAN_REVIEW_APPROVED=true and a nonempty role variable.
The retained same-repository condition is an additional legacy defense; PR and push
triggers are removed. Offline PR checks remain credential-free, with contents: read.
OIDC write permission is only on the guarded plan job; no PR write permissions exist.

The owner approved `CG-SM-PLAN-001` on 2026-11-25 for one read-only sandbox
planning run, permitting self-review and temporarily accepting no independent
PR/CODEOWNERS approval. Expiry: **2026-12-01T18:30:00Z**, or earlier on run
completion/failure/cancellation or revocation. This approval grants no deployment,
Terraform apply/destroy, IAM expansion or privileged Phase 6 authority.
See [the recorded scope, execution prerequisites and restoration duties](phase5-integration.md).
No GitHub setting or enable variable is changed by this record. Before a later
manual run, bind the final reviewed PR/main SHAs and passing hosted checks, verify
effective protections/trust/permissions, and confirm approval remains unused and
unexpired. Preserve all other controls. No bootstrap provisioning is authorized.

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
