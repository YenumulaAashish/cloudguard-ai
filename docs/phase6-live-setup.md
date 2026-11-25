# Phase 6 live installation requirements — owner review only

Status: adapters CODED; private installation NOT CONFIGURED; AWS verification,
planning, deployment, remote-state locking and deletion NOT RUN. Do not execute
this checklist against AWS until the owner separately authorizes that stage.
This task does not activate live operation, change IAM or GitHub, or reuse Phase 5
authorization. Source templates remain NOT_APPROVED.

## 1. Isolated runtime and ledger decision

Use a dedicated owner-controlled workstation or private service host with one
unprivileged OS account, loopback frontend/API, encrypted disk and an owner-only
private directory OUTSIDE this checkout and cloud-synchronized folders. Do not expose port 8790 publicly or add
this service to a GitHub Actions/self-hosted repository runner. No repository or
fork job may mount that directory, obtain its credentials or run on the host.
Review the executable/provider mirror installation and exact source digest before
installation. Do not share an OS account with untrusted projects. Set Windows ACLs
explicitly; chmod-mode arguments alone do not enforce Windows privacy.

Write an owner-reviewed host-isolation record (host/account/directory ACLs, backups,
credential injection, process isolation, no CI access, disk protection), hash it,
and bind that digest in settings and the grant. This is an owner attestation, not
a code-generated proof of host isolation. A compromised host administrator can
bypass a local service; the application does not claim otherwise. Keep encrypted,
access-controlled backups of the private SQLite history and audit chain. Restoring
an old database is an administrative recovery event, never an authorization reset.

The new service uses persistent SQLite one-use jobs, unique request IDs, immediate
transactions, an exclusive service process lock and native remote Terraform state
locking. It does not introduce an attempt-count authorization model or claim a
rollback-resistant centralized ledger. The existing Phase 5 GitHub planning
ledger/runner-isolation blocker is not externally resolved; those controls remain
intact. Hosting Phase 6 outside repository CI is the proposed secure alternative
for this platform, subject to owner validation. No machine-enforced Phase 5 limit
or environment approval is bypassed.

## 2. Owner-provisioned state and support resources

All names/ARNs belong in private settings, never in the dashboard or repository.

| Resource | Exact required configuration |
|---|---|
| State bucket | Same owner account, ap-south-1, versioning Enabled, all four Public Access Block flags, BucketOwnerEnforced, SSE-KMS with exact state CMK, explicit TLS deny on bucket/objects. Dedicated state key `phase6/<workspace>/terraform.tfstate`; Terraform CLI default workspace only. No shared Phase 1/5 state. |
| State lock table | ap-south-1, ACTIVE, string partition key `LockID`, no sort key; on-demand capacity, encryption, owner-reviewed recovery/backup policy. No TTL-based unlock or automatic force unlock. |
| State CMK | Exact Mumbai customer-managed enabled key with rotation and narrow key policy; worker use only for its state object. |
| Audit bucket | Same account, ap-south-1, private BucketOwnerEnforced, all PAB flags, SSE-S3, TLS deny, no requester-pays/Object Lock default retention/self-logging; owner-defined retention. Service delivery policy below. |
| Source CMK | Exact enabled rotating Mumbai key; limited workload S3 and replication use. |
| Replica bucket/CMK | Same account, ap-south-2 (Hyderabad), private versioned BucketOwnerEnforced, PAB, TLS deny, enabled rotating customer CMK. Separate from state and audit buckets. |
| EC2 profile/role | Existing named `cloudguard-phase6-*` profile with exactly one EC2-service-trusted role, zero inline/attached identity policies and a permissions boundary that unconditionally denies `Action: *` on `Resource: *`. No SSM role or instance secrets. |
| Replication role | Existing named `cloudguard-phase6-*` role trusted only by S3 for `sts:AssumeRole`. Inline permission scope below; no attached managed policies. |
| AMI | Explicit available x86_64 Linux image ID and owner, reviewed for Mumbai and t3.micro/small. The browser's fixed template choice is mapped to this image. |

The generated source bucket name is `cg-live-<workspace>-<project>-<first8 SHA256
of canonical JSON project string>`. Compute it locally with `generate` after filling
private settings; use that EXACT name in support policies. The application does
not create general-purpose object read/write APIs. No internet gateway/NAT/public
IP/SSH is generated. Verify log and replica delivery separately after authorization.

Audit delivery policy must allow `logging.s3.amazonaws.com` `s3:PutObject` only to
`<audit>/access/<project>/*`, with `aws:SourceAccount` and exact source-bucket ARN
conditions. VPC flow-log delivery must allow `delivery.logs.amazonaws.com`
`s3:GetBucketAcl` on the audit bucket and `s3:PutObject` on
`<audit>/vpc/AWSLogs/<account>/*`, with SourceAccount, regional/account SourceArn
restrictions and the AWS-required ACL condition. Retain the TLS deny. Verify the
service conditions against current AWS documentation before provision; the code
checks the safe bucket envelope but is not an IAM Access Analyzer substitute.

Replication inline policy uses exactly these action/resource pairs (multiple
statements may group actions with the same resource):

- `s3:GetReplicationConfiguration`, `s3:ListBucket`: exact source bucket ARN.
- `s3:GetObjectVersionForReplication`, `s3:GetObjectVersionAcl`,
  `s3:GetObjectVersionTagging`: exact source bucket ARN + `/*`.
- `s3:ReplicateObject`, `s3:ReplicateTags`: exact replica bucket ARN + `/*`.
- `kms:Decrypt`: exact source CMK; `kms:Encrypt`: exact replica CMK. Restrict with
  regional `kms:ViaService` and applicable S3 encryption-context conditions.

No replication delete permission is included because delete-marker replication is
disabled. Review KMS Bucket Key encryption-context semantics before authorizing;
source/replica bucket contexts must not be confused with object contexts.

## 3. Separate Phase 6 operator IAM role

Use a separately reviewed `cloudguard-phase6-<name>` role assumed through the
owner's existing short-lived SSO/federation mechanism. Keep Phase 5 IAM/OIDC
unchanged. Do not paste permanent keys, attach AdministratorAccess or create new
OIDC trust automatically. Bind trust to the owner's actual federation subject.
The following is the required action/resource review matrix, not an already
validated deployable IAM policy. Service-level condition applicability and the
first real plan remain NOT RUN. Narrow deny/allow statements must be reviewed
with IAM policy validation before activation.

| Surface | Required permissions and restriction |
|---|---|
| Identity | `sts:GetCallerIdentity`; exact expected account and assumed Phase 6 role verified before a live connection is marked verified. |
| State | `s3:ListBucket` on exact state bucket with prefix restricted to the exact state key; `s3:GetObject`, `s3:PutObject` on exact key only. No state-object delete. `kms:Decrypt`, `kms:Encrypt`, `kms:GenerateDataKey` on exact state CMK, ViaService S3 Mumbai and state encryption context. |
| Lock table | `dynamodb:DescribeTable`, `GetItem`, `PutItem`, `DeleteItem` on exact table only. Where applicable restrict LeadingKeys to `<state-bucket>/<state-key>` and its `-md5` checksum record; validate Terraform backend key behavior. Never a wildcard table or force-unlock action. Plan lock writes require separate grant flag. |
| EC2 read | `ec2:DescribeVpcs`, `DescribeVpcAttribute`, `DescribeSubnets`, `DescribeSecurityGroups`, `DescribeRouteTables`, `DescribeNetworkAcls`, `DescribeInstances`, `DescribeInstanceAttribute`, `DescribeInstanceCreditSpecifications`, `DescribeVolumes`, `DescribeImages`, `DescribeAvailabilityZones`, `DescribeFlowLogs`, `DescribeTags`, `DescribeNetworkInterfaces`; AWS describe APIs generally require `Resource: *`, region-condition ap-south-1. |
| VPC mutation | `CreateVpc`, `ModifyVpcAttribute`, `DeleteVpc`, `CreateSubnet`, `ModifySubnetAttribute`, `DeleteSubnet`, `CreateRouteTable`, `DeleteRouteTable`, `AssociateRouteTable`, `DisassociateRouteTable`, `CreateSecurityGroup`, `DeleteSecurityGroup`, `RevokeSecurityGroupIngress`, `RevokeSecurityGroupEgress`, `CreateFlowLogs`, `DeleteFlowLogs`, `CreateTags`, `DeleteTags`. Only Mumbai resources in this owner account, project/ManagedBy request-tag and existing-resource-tag restrictions as each API supports. Default-security-group revoke/tag operations need a scoped VPC/default-group review because AWS creates that group initially without tags. No route-to-internet or broad ingress authorization permission is needed by these fixed templates. |
| Flow-log delivery | `logs:CreateLogDelivery`, `logs:DeleteLogDelivery` in ap-south-1. AWS documents `Resource: *` for these two delivery APIs; they have no resource-level ARN restriction. This narrow service-action wildcard requires explicit owner IAM review before activation. Do not add broad CloudWatch Logs permissions or audit-bucket policy mutation to the worker. |
| EC2 mutation | `RunInstances`, `TerminateInstances`, `ModifyInstanceAttribute`, `ModifyInstanceCreditSpecification`, `MonitorInstances`, `UnmonitorInstances`, `CreateTags`, `DeleteTags`; exact approved AMI, t3.micro/small, Mumbai account/subnet/SG/instance/volume/network-interface resource classes, project tags. RunInstances authorizes multiple resource types: do not assume a condition valid for new instances also works on referenced image/subnet/SG/ENI resources. No SSM/SSH, arbitrary AMI or network attachment APIs. |
| Workload S3 | Exact generated bucket ARN and its configuration, never all sandbox buckets: `CreateBucket`, `DeleteBucket`, `ListBucket`, `ListBucketVersions`, `ListBucketMultipartUploads`, `GetBucketLocation`, `GetBucketPolicy`, `PutBucketPolicy`, `DeleteBucketPolicy`, `GetBucketPublicAccessBlock`, `PutBucketPublicAccessBlock`, `GetEncryptionConfiguration`, `PutEncryptionConfiguration`, `GetBucketVersioning`, `PutBucketVersioning`, `GetBucketOwnershipControls`, `PutBucketOwnershipControls`, `GetLifecycleConfiguration`, `PutLifecycleConfiguration`, `GetBucketLogging`, `PutBucketLogging`, `GetBucketNotification`, `PutBucketNotification`, `GetReplicationConfiguration`, `PutReplicationConfiguration`, `GetBucketTagging`, `PutBucketTagging`, `GetBucketAcl`, `GetBucketCORS`, `GetBucketWebsite`, `GetAccelerateConfiguration`, `GetBucketRequestPayment`, `GetBucketObjectLockConfiguration`. Provider 6.65.0 refreshes deprecated computed bucket metadata too. No workload GetObject/PutObject/DeleteObject/DeleteObjectVersion or force-empty privilege. CreateBucket constrained by LocationConstraint Mumbai where supported. |
| Support read | `s3:GetBucketLocation`, `GetBucketVersioning`, `GetBucketPublicAccessBlock`, `GetEncryptionConfiguration`, `GetBucketOwnershipControls`, `GetBucketPolicyStatus`, `GetBucketPolicy`, `GetBucketLogging`, `GetBucketAcl` on exact state/audit/replica buckets; `kms:DescribeKey`, `GetKeyRotationStatus` on exact three keys; `iam:GetInstanceProfile`, `GetRole`, `ListRolePolicies`, `ListAttachedRolePolicies`, `GetRolePolicy`, `GetPolicy`, `GetPolicyVersion` on exact profile/roles/boundary. No support mutation. |
| Role passing | `iam:PassRole` on exact INSTANCE ROLE ARN with `iam:PassedToService=ec2.amazonaws.com`; exact REPLICATION ROLE ARN with `iam:PassedToService=s3.amazonaws.com`. Never profile ARN, wildcard role or CreateRole/AttachRolePolicy/PutRolePolicy. |
| Pricing | No AWS Pricing API permission is required: this version uses an owner-reviewed official AWS price export. Do not add billing/admin permissions. |

The pinned [provider bucket implementation](https://github.com/hashicorp/terraform-provider-aws/blob/v6.65.0/internal/service/s3/bucket.go) also supports newer bucket resource tagging. Review whether `s3:TagResource`, `s3:UntagResource` and `s3:ListTagsForResource` are required by the account/API path, confined to the exact generated bucket; never grant them account-wide.

Ownership-controls deletion uses `s3:PutBucketOwnershipControls`, not a nonexistent DeleteBucketOwnershipControls IAM action ([AWS API reference](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketOwnershipControls.html)).

VPC S3 delivery requires the two log-delivery actions listed above ([AWS prerequisites](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3-create-flow-log.html)). The owner must preconfigure the audit service policy; the worker must not receive audit `PutBucketPolicy`. If the service still requires first-time destination setup, stop for owner setup instead of expanding worker permissions. [S3 log delivery setup permissions](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/AWS-logs-infrastructure-S3.html).

Any missing permission must fail closed. An AccessDenied is diagnostic evidence,
not permission to broaden this matrix or bypass a gate. No real IAM policy has
been installed, account-tested or certified by this offline change.

## 4. Private files and environment

Copy the two `security/phase6-live-*.template.json` files OUTSIDE the repository.
Fill every settings placeholder, including exact AMI owner and support bindings.
Private files are closed-key validated; no arbitrary HCL, endpoints or shell
commands are accepted. Configuration/source/isolation hashes must match the grant.
Grant fields are strict booleans, numeric UTC epoch seconds, APPROVED with explicit
owner identity and a validity interval at most seven days. Repository template is
NOT_APPROVED and cannot authorize anything. Never commit a filled grant or price
export. A changed grant/source/configuration invalidates prior plans immediately.

Provide a private JSON price export:
`kind=AWS_REVIEWED_EXPORT`, `currency=USD`, `regions=[ap-south-1,ap-south-2]`, numeric
`as_of`/`expires_at` no more than seven days apart, and `rates` with every meter in
`backend/cloudguard_live/pricing.py:METERS`. Each rate has decimal-string
`usd_per_unit`, official `https://aws.amazon.com/` source URL, unit, regional SKU and
`reviewed=true`. Normalize requests to per-request USD, storage to GB-month and
compute to hours. Unit strings must exactly match `pricing.py:UNITS`; a per-thousand quote cannot be labeled as a per-request price. Include state/DynamoDB/backup operations in `state_month`.
Record applicable rotated-key charges in `kms_key_month`. Zero requires an actual
reviewed zero price; absent values are never zero. Hash the canonical export into
settings.price_digest. The application verifies freshness/completeness/hash and
owner review, not independent price authenticity. No automatic pricing lookup is
claimed. Do not use the mock price file in live mode.

Use the pinned Terraform 1.9.8 binary, AWS provider 6.65.0 and committed lock file;
seed the provider mirror using the existing reviewed installation. All security
tools retain their existing pinned versions. Install SDK versions from
`backend/requirements-live.txt` in the reviewed environment. Do not install an
unreviewed Terraform wrapper on PATH; executable installation is part of host trust.

Server environment (never browser variables):

- `CLOUDGUARD_OPERATOR_TOKEN`: random private 32-128 character operator secret.
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`: temporary
  credentials for the separate Phase 6 role; all three required.
- `CLOUDGUARD_AWS_EXPIRES_AT`: numeric UTC expiry, more than 120 seconds ahead and
  no more than 12 hours ahead. Renew for a complete operation; no auto retry.
- No AWS endpoint overrides, web identity token path, role ARN override or profile
  fallback. The worker constructs a minimal native/SDK environment.

Do not enable GitHub planning variables. No GitHub permission or OIDC change is
needed by this owner-hosted backend. Any future remote browser access needs a
separately reviewed TLS/authentication/Origin design; do not bind this loopback
service to all interfaces or use an unauthenticated reverse proxy.

## 5. Exact staged verification after separate authorization

1. Review/commit code and establish owner-approved host isolation, IAM and support
   configuration. Preserve Phase 5 controls. Resolve full source/config/price
   digests locally with `settings.source()` and `config.digest()`.
2. Owner authorizes READ ONLY first: allow_read true, other flags false, explicit
   bounded dates and exact bindings. This task supplies no approved grant.
3. After permission, start `python backend/serve_platform.py --mode live
   --private-dir <owner-private-dir> --configuration <private-settings.json>
   --authorization <private-grant.json> --prices <private-prices.json>` as one command.
   Start the loopback frontend, sign in and click Verify AWS connectivity.
   Merely starting the service or loading the dashboard makes no AWS requests.
4. Review STS/support verification. Record real results separately from mock tests.
   Authorize allow_state_locking only when remote init/lock operations are approved;
   then create an authenticated native plan and inspect all mandatory gate results.
   Exit code 2 means proposed changes, not plan failure. Raw artifacts remain private.
5. Only after a separate deployment authorization, set allow_deploy in a freshly
   owner-approved bound grant. This change requires a fresh preview. The operator's
   Deploy click authorizes exactly that validated binary plan; no reviewer account.
6. Verify inventory, native drift and controlled reconciliation. For deletion,
   separately authorize allow_delete, ensure all bucket versions/uploads are empty
   by the owner-approved data-retention process, preview and type the exact phrase.
   This worker has no object-purge API or automatic rollback. A failed attempt invalidates earlier plans and requires owner/operator incident inspection and a freshly bound grant before recovery preview. Unmanaged project inventory or unavailable observation blocks that new plan.
7. Revoke grant/remove temporary credentials after testing. Inspect state backups,
   audit/history and backend locks. After a crash, confirm no process is active and
   inspect native lock/state before owner removal of the local service.lock; do not
   delete locks blindly or reset a consumed job. An EXECUTING job requires manual
   incident review; no automated abandoned-job takeover is implemented.

No step above was run against AWS. Final end-to-end deployment, IAM condition
validation, service-delivery checks and real budget quote remain blockers until
separate owner authorization and configuration.
