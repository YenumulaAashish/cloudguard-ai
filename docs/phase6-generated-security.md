# Generated workload controls and cost review

The all-enabled source contains 18 resources. With Terraform 1.9.8, provider
6.65.0 and Checkov 3.2.471 it validates offline and yields 39 passed / 0 failed /
0 skipped / 0 parsing errors. This is separate from the original Phase 1 source's
accepted 30 / 0 / 6 baseline. No skips or Rego exemptions were added. Mock plans
still use explicitly fake support identities; live support requires private owner
bindings and runtime verification. Source passing cannot prove AWS delivery works.

| Finding | Implemented workload configuration | Applicability and cost |
|---|---|---|
| CKV2_AWS_11 | ALL-traffic VPC flow logs directly to a private Mumbai S3 audit bucket, 600-second aggregation | Applicable; traffic-volume delivery and retained-log storage charges. No NAT, CloudWatch log group or new log-writer IAM role. Delivery is best effort. |
| CKV2_AWS_41 | Existing EC2 profile with exactly one EC2-trusted role, no identity policies and an unconditional deny-all boundary | Applicable to this EC2 template; no extra IAM price and no application permissions. It does not enable SSM or secret retrieval. The worker cannot create or attach IAM policies. |
| CKV2_AWS_62 | S3 EventBridge event notifications enabled | Applicable; no consumer, event rule or paid target is provisioned. Downstream processing costs require a separate design. |
| CKV_AWS_144 | Versioned source, genuine cross-region replication to an existing Hyderabad versioned KMS destination, existing scoped replication role | Disaster-recovery value, but optional for a tiny teaching sandbox. Implemented securely rather than treating same-region replication as cross-region. Adds replica storage, requests, KMS and inter-region transfer. No RTC, cross-account replication or delete-marker replication. |
| CKV_AWS_145 | Customer-managed Mumbai KMS encryption, S3 Bucket Key and SSE-C blocked | Applicable; owner controls both regional keys, rotation enabled. Keys and KMS operations are chargeable. |
| CKV_AWS_18 | Access logging to a separate same-account Mumbai audit bucket and project-specific prefix | Applicable; delivered log storage/requests are chargeable. No recursive self-logging. |

## Support resources are explicit installation requirements

The worker does not provision its own IAM roles, log bucket, replica destination,
state bucket or keys. The owner must separately review/provision them; generated
source cannot be deployed with mock ARNs. Live verification checks identity,
locations, bucket protections/encryption, KMS rotation, lock-table shape, approved
AMI, deny-all instance-role boundary and exact replication permission scope.

AWS documents that S3 access-log destinations must use SSE-S3 and should not log
to themselves. The audit sink therefore deliberately uses SSE-S3, a restrictive
service delivery policy, TLS enforcement and no recursive server logging. It is
not silently represented as a KMS-encrypted/self-logged workload bucket. No
Checkov exception is introduced here. If the owner later brings this audit sink
into Terraform/Checkov scope, its encryption/logging/replication applicability
needs a separate resource-scoped owner decision; do not copy legacy exceptions.
See [AWS access logging constraints](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html).

## Estimated spend, not a bill guarantee

Three fresh customer-managed KMS keys (state, source, replica) have a base storage
cost of approximately **USD 3/month total**, before key-rotation versions, requests,
taxes or existing key costs. Keys are prorated; account-specific discounts/free
tier are not assumed. [AWS KMS pricing](https://aws.amazon.com/kms/pricing/).

The remaining estimate is explicitly a formula until current regional rates are
owner reviewed: 730 x Mumbai t3.micro/small hourly rate + root gp3 GB-month +
detailed monitoring + source and replica GB-month + request/KMS/replication and
transfer meters + flow-log delivery + audit storage + state/lock-table costs.
The model reserves 10 GB each for log delivery and audit retention and charges
730 compute hours even if a user enters fewer hours: no automatic stop scheduler
is implemented. Support charges remain after workload deletion. No public IPv4,
NAT gateway, load balancer, CloudTrail trail or paid EventBridge target is added.
The backend requires a complete fresh owner-reviewed AWS regional price export;
missing, ambiguous, stale or mock prices yield UNKNOWN and block deployment.
The public docs do not supply an account-specific Mumbai/Hyderabad quote, so no
invented final monthly total is represented as verified.

S3 GB, requests, log volume and transfer are forecast inputs, not enforceable AWS
quotas. The budget gate enforces that forecast against the lower of owner and
operator limits; it cannot cap a bill, stop external writes or halt an already
running EC2 instance. Owner Budgets/alerts and retention/usage monitoring are
required operational safeguards. Breaching an alert does not authorize automatic
resource mutation. See [S3 pricing](https://aws.amazon.com/s3/pricing/) and
[EC2 on-demand pricing](https://aws.amazon.com/ec2/pricing/on-demand/).

No additional security exception approval is requested by this implementation.
If CRR costs are rejected, do not disable it quietly: request an explicit narrowly
scoped owner exception and policy applicability review in a separate change.
