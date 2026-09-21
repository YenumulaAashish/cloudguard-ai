# Phase 1 sandbox security decisions

On 2026-09-21 the project owner delegated resolution of the seven Checkov findings to the implementer, subject to the original small, low-cost, no-deployment scope. The selected resolution adds a safe lifecycle rule and accepts **six resource-scoped sandbox exceptions**. This is not a production security approval or authorization to deploy.

## Implemented control

CKV2_AWS_61 is resolved with an S3 lifecycle rule that aborts incomplete multipart uploads seven days after initiation. This limits orphaned upload storage. It does not expire completed objects, delete object versions or transition storage classes. A client that leaves a multipart upload unfinished for seven days must restart it. No bucket or other AWS resource was deployed.

## Accepted exceptions

Each exception is an inline Checkov annotation on the resource below, not a global skip. The normal scan keeps all other checks active and exits nonzero for unaccepted findings. The associated Rego policies have no exemptions.

| Rule ID | Resource | Reason and acceptance rationale | Security impact / review trigger |
|---|---|---|---|
| CKV2_AWS_11 | module.network.aws_vpc.this | Phase 1 has no workloads and excludes paid monitoring. Adding logging destinations and roles solely to satisfy this check would expand the sandbox. | No VPC flow-log audit trail. Review logging and retention before any workload deployment or drift experiment. |
| CKV_AWS_145 | module.storage.aws_s3_bucket.this | Explicit SSE-S3 AES256 is adequate for the sandbox's encryption-at-rest baseline; dedicated KMS key governance is not a Phase 1 requirement. | No customer-managed key revocation, key policy or KMS usage audit. Review KMS before storing sensitive data or introducing a key-management requirement. |
| CKV_AWS_18 | module.storage.aws_s3_bucket.this | No application or sensitive data is intended, and no logging destination exists. Avoid creating an additional bucket just for an empty sandbox. | No S3 server-access-log audit trail. Review access auditing before application use or real data storage. |
| CKV_AWS_144 | module.storage.aws_s3_bucket.this | Single-region educational sandbox has no cross-region disaster-recovery objective. Replication would add storage, transfer and IAM scope. | No cross-region replica; versioning does not provide regional disaster recovery. Reassess when durability/recovery requirements are defined. |
| CKV2_AWS_62 | module.storage.aws_s3_bucket.this | No event consumer or event-driven workflow exists. Unused notifications would add architecture without serving a requirement. | No event-driven object processing or alerts. Remove the exception when introducing a consumer or alerting requirement. |
| CKV2_AWS_5 | module.security.aws_security_group.this | The reusable security group is deliberately unattached because Phase 1 excludes compute. Creating compute to attach it would violate the intended scope. | Unattached group currently protects no workload. Attach and review rules if compute is later explicitly authorized, then remove this exception. |

## Boundaries and maintenance

Exceptions apply only to these module resources in the Phase 1 sandbox. Inline annotations travel with copied code, so remove/review them before reusing these modules for production. The Phase 2 request explicitly preserves these same six decisions. Review them again before Phase 3 or any deployment approval; acceptance does not automatically extend to real workloads. Never use these exceptions to report unqualified coverage, accuracy or mutation scores.

Public access blocking, explicit storage encryption, TLS enforcement, versioning, disabled SSH by default, mandatory tags and IAM wildcard checks remain active. No global check filter or soft-fail mode is used. Checkov output must report exceptions as skipped, not passed. CI must fail for any other security violation.


## Phase 2 machine enforcement

`security/checkov-exceptions.json` holds the six rule/resource pairs with brief rationales and review triggers. The full explanation remains here. `scripts/verify-checkov-exceptions.py` checks the JSON against the reviewed invariant, walks source annotations through local module references, and compares them with a complete actual Checkov source-scan JSON report. Exactly the six pairs must appear once each as SKIPPED, not PASSED or FAILED. New annotations in the bootstrap or root-level Terraform source are rejected too. Any other failure, missing/duplicate/moved skip, global filtering or soft-failure configuration fails the gate.

The standard source runner invokes this guard after every scan and exports sanitized evidence. The guard conservatively rejects unsupported dynamic/remote module sources, Terraform JSON and heredoc syntax instead of guessing annotation ownership. Extending source syntax requires explicit parser support and tests. The static CI guard detects ordinary prohibited commands and failure-masking settings; it cannot prove arbitrary executable code harmless. Required code-owner/environment reviews remain necessary.
