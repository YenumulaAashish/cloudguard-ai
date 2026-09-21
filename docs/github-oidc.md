# GitHub OIDC and the read-only plan role

## Status

CODED: bootstrap Terraform, exact trust policy and gated workflow. CONFIGURED: NOT RUN. VERIFIED: NOT RUN. Nothing in this implementation created an IAM role, OIDC provider or workload resource. No hosted authenticated plan is claimed.

Repository identity is `YenumulaAashish/cloudguard-ai`; the region is `ap-south-1`. Permanent AWS credentials are neither required nor stored. GitHub requests a short-lived OIDC token and exchanges it with AWS STS for a 15-minute role session.

## Trust and fork boundary

The role trusts only an existing GitHub OIDC provider with audience `sts.amazonaws.com` and exact subject:

```text
repo:YenumulaAashish/cloudguard-ai:environment:aws-plan
```

There is no repository wildcard. Because an environment subject replaces the branch/PR subject, **GitHub environment protection is part of the security boundary**, not optional decoration. Create `aws-plan` with required trusted reviewers, prevent self-review, and disallow administrator bypass where supported. Restrict eligible deployment refs to main and only those same-repository PR refs/branches you intend to review. Do not enable the workflow if these protections are unavailable for the repository's GitHub plan.

The plan job also requires all of:

- The exact repository above.
- `AWS_PLAN_ENABLED` equal to `true` and a nonempty `AWS_PLAN_ROLE_ARN`.
- For a PR: `github.event.pull_request.head.repo.full_name == github.repository`.
- For push/manual runs: `github.ref == 'refs/heads/main'`.
- Approval through the protected `aws-plan` environment.

Fork PRs get offline checks only. Never approve an AWS-environment run for fork-controlled code. A maintainer must review the changes, place accepted code on a maintainer-controlled same-repository branch, and run authenticated validation there if needed before merge. Normal PR workflows, including this one, are editable by proposed changes; the condition alone is not a replacement for protected-environment review and branch protections. Require CODEOWNERS review for workflow, scripts, security policy, bootstrap and Terraform changes using the included `.github/CODEOWNERS` file.

No privileged PR trigger is used. `id-token: write` exists only on the guarded plan job; offline CI has `contents: read` only. Checkout does not persist repository credentials. Installation and offline preflight gates precede AWS credential configuration.

## Manual setup, in order

1. Confirm the intended repository and commit/review the local changes. This checkout currently has no commits and no `origin`; neither was silently created. If still absent, configure it yourself:

   ```sh
   git remote add origin https://github.com/YenumulaAashish/cloudguard-ai.git
   ```

   Do not run that command if an origin already exists; inspect `git remote -v`. Decide the initial commit/main branch and push separately. This implementation does not push.

2. Sign in to the intended AWS account with an administrator's short-lived SSO session. Discover existing OIDC providers without creating one:

   ```sh
   aws sts get-caller-identity
   aws iam list-open-id-connect-providers
   aws iam get-open-id-connect-provider --open-id-connect-provider-arn YOUR_PROVIDER_ARN
   ```

   Confirm its URL is `token.actions.githubusercontent.com` and `ClientIDList` contains `sts.amazonaws.com`. Provider ARN account and your intended role account must match. If no provider exists, have the account owner separately approve and create the account-wide provider using the [AWS/GitHub OIDC instructions](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws). The bootstrap intentionally does not create a provider or guess whether one exists.

3. Select one globally unique sandbox bucket name; it must match the bootstrap input, Terraform input and GitHub variable. Copy `bootstrap/aws-plan-role/terraform.tfvars.example` to `terraform.tfvars` within that directory and replace the dummy provider ARN/account and bucket name. No credential belongs in that file.

4. Review the bootstrap before any cloud changes:

   ```sh
   terraform -chdir=bootstrap/aws-plan-role init
   terraform -chdir=bootstrap/aws-plan-role validate
   terraform -chdir=bootstrap/aws-plan-role plan
   ```

   The last command is an authenticated administrator plan, not part of offline CI. Separately authorize provisioning the reviewed role and inline policy. **No bootstrap provisioning was executed here.** An account administrator must do that later. Protect its local state and do not commit it. After provisioning, obtain `terraform -chdir=bootstrap/aws-plan-role output -raw aws_plan_role_arn`.

5. Configure the protected `aws-plan` environment and main-branch/code-owner review rules above. Set repository variables (not secrets):

   | Variable | Value |
   |---|---|
   | AWS_PLAN_ROLE_ARN | Reviewed role's output ARN |
   | AWS_SANDBOX_BUCKET_NAME | Exact bucket name from step 3 |
   | AWS_PLAN_ENABLED | `true` only after all protection/setup steps |

   Region is explicitly `ap-south-1` in the workflow. Do not store AWS access keys or session credentials as repository secrets.

6. Run offline CI, then manually dispatch **Authenticated Terraform plan** on main. Review and approve the environment request only for trusted code. Verify STS authentication, real plan export, Conftest gate, and sanitized artifacts. A denial must remain a failed run. A missing read permission must be reviewed and added narrowly; do not substitute an administrator or broad read-only policy.

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
