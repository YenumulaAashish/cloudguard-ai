# Phase 4.3: deterministic S3 data protection

**Deterministic tools decide. AI explains. PR reporting informs.**

This component analyzes configuration posture in supplied local Terraform plan
JSON. It does not query S3/KMS, execute Terraform, call AI or prove deployed state.
Its scope is S3 only; graph/posture phases 4.4 and 4.5 are not implemented.

## Repository context and architecture

The sandbox defines aws_s3_bucket, public_access_block, encryption configuration
(AES256), versioning (Enabled), ownership controls (BucketOwnerEnforced), a TLS
Deny bucket policy and an enabled global seven-day multipart-upload abort rule.
It uses separate resources, not deprecated inline fields. There is no ACL or
logging resource. Accepted bucket Checkov exceptions cover KMS (CKV_AWS_145),
logging (CKV_AWS_18), replication (CKV_AWS_144) and notifications (CKV2_AWS_62).
The six-pair exception contract is unchanged. Custom findings do not inherit these
exceptions; a missing logging configuration can yield a LOW finding for review.
Existing S3 checks include public-access blocking, encryption, versioning, TLS,
ownership and multipart cleanup. No source Checkov interpretation is changed.

The analyzer reuses plan_input.project unchanged: supported plan format versions
1.0/1.1/1.2, nested planned_values.root_module, authoritative change.after values,
after_unknown, delete-only exclusion and replacement after-state analysis once.
IAM and network modules, schemas, controls and risk behavior are unchanged.

Supported separate resources: aws_s3_bucket, aws_s3_bucket_public_access_block,
aws_s3_bucket_acl, aws_s3_bucket_policy,
aws_s3_bucket_server_side_encryption_configuration, aws_s3_bucket_versioning,
aws_s3_bucket_logging and aws_s3_bucket_lifecycle_configuration. Other aws_s3_*
resources (including ownership/Object Lock) produce UNKNOWN context. Non-S3
resources are ignored. Object Lock is not required and compliance is not inferred.

## Local S3 correlation and uncertainty

Companions match exact known bucket/id values on local aws_s3_bucket resources.
No ARN, region, account, name or deployment identity is invented. Known aliases
are accepted; ambiguous bucket identities or duplicate companions of a given kind
for one bucket fail. Unmatched or unknown references yield UNKNOWN on that
companion and conservatively taint that companion kind across local buckets;
there is no speculative join. No generic cross-domain graph is constructed.
Known bucket ARNs are used only in memory for policy scope checks, never derived
from names or copied into output. Unknown ARN prevents ARN-based scope proof;
explicit Resource=* can still establish structural scope.

Each bucket has eight bounded check records: pab, acl, policy, transport,
encryption, versioning, logging, lifecycle. States mean:

- ESTABLISHED: the explicitly supported protection pattern is present.
- REVIEWED: supported ACL/policy structure was examined without a matched public
  control; this is not effective-access approval.
- MISSING: no supported companion exists and no unresolved same-kind mapping or
  unknown bucket identity prevents establishing its absence.
- WEAK: a known configuration matches the documented structural weakness.
- UNKNOWN: necessary values, mappings or supported semantics are unavailable.

Missing ACL/policy records do not create public-access findings. Missing policy
can still produce a transport-pattern finding. Missing PAB, encryption,
versioning, logging and lifecycle have their own controls. Relevant after_unknown
and null fields produce UNKNOWN, not safe or confirmed insecure assumptions.
Inline legacy ACL/policy/versioning/logging/lifecycle/encryption configuration is
unsupported: nonempty or unknown legacy fields conservatively make bucket checks
UNKNOWN. No companion/inline merge is attempted. Empty deprecated defaults do not
hide the supported separate resources.

## Stable controls and severity

| ID | Structural condition | Severity |
|---|---|---|
| CGA_DATA_001 | PAB has explicitly false protection(s) | HIGH |
| CGA_DATA_002 | Complete PAB configuration missing | MEDIUM |
| CGA_DATA_003 | public-read ACL | MEDIUM |
| CGA_DATA_004 | public-read-write ACL | CRITICAL |
| CGA_DATA_005 | Supported public-principal S3 Allow | HIGH |
| CGA_DATA_006 | Explicit encryption configuration not established | MEDIUM |
| CGA_DATA_007 | Enabled versioning not established | MEDIUM |
| CGA_DATA_008 | Logging absent/empty target | LOW |
| CGA_DATA_009 | Recognized transport Deny pattern absent | MEDIUM |
| CGA_DATA_010 | Global enabled multipart abort within seven days absent | LOW |
| CGA_DATA_011 | Unsupported/unresolved context | UNKNOWN |

PAB is established only with all four explicit booleans true. Explicit false
produces one 001 finding; missing fields produce UNKNOWN. Unknown masks take
precedence over partial known values. Missing PAB never means definitely public.

ACL supports public-read and public-read-write detection; private,
bucket-owner-read, bucket-owner-full-control and log-delivery-write are reviewed.
Custom grant/access_control_policy blocks and other/unknown ACLs require review.
The analyzer does not resolve ownership/PAB effects on effective ACL access.

Policy JSON object/string and single/list Statement forms are supported. Duplicate
JSON keys and malformed JSON fail; missing Statement is UNKNOWN. Public principals
are literal '*' or AWS principal lists containing '*'. Scoped AWS/string principals
do not match the public control; other principal kinds require review. Supported
Allow actions are *, s3:*, GetObject, PutObject, DeleteObject, GetObjectVersion and
ListBucket (case-insensitive action names). Object actions require Resource=* or
the directly supplied bucket ARN plus /*; ListBucket requires Resource=* or the
bucket ARN. Other action/resource patterns become UNKNOWN rather than guessed.

Allow Conditions produce UNKNOWN for effective public scope; they are never
stripped. A separately proven unconditioned public Allow can coexist with UNKNOWN
context. Deny is never public Allow. NotPrincipal/NotAction/NotResource produce
UNKNOWN. This is not full IAM resolution; independent Deny, SCP, session, PAB and
ownership effects are not combined into effective access.

Transport is established only by a Deny with public principal, Action=* or s3:*,
Resource=* or both the supplied bucket ARN and its /* objects, and exactly
Condition.Bool.aws:SecureTransport=false (boolean false or string 'false').
Additional restrictions or partial resource/action/principal coverage do not prove
the global pattern. Absence means the recognized enforcement pattern is not
established; it never means data is being transmitted over HTTP.

Encryption supports one rule/default block with AES256 or aws:kms and records
only that fixed mode. Missing/unsupported algorithms are UNKNOWN; malformed block
shapes fail. SSE-S3 is encryption. SSE-KMS says nothing about key policy, rotation,
access, cross-account behavior or availability; no key lookup occurs. Missing
explicit config never asserts existing objects are plaintext or ignores AWS's
separate default-encryption behavior.

Versioning Enabled is established; Suspended/Disabled are WEAK; unknown status is
UNKNOWN. Versioning is not backup/recovery assurance. Logging needs a known
nonempty target; unknown target is UNKNOWN, missing resource is MISSING, empty
target is WEAK. Other audit mechanisms/destination security are not inferred.

Lifecycle establishes only an Enabled global rule with abort incomplete multipart
uploads after 1..7 days, consistent with the existing seven-day Checkov control.
Disabled/scoped rules, >7 days, expiration/transitions/noncurrent rules alone do
not establish this pattern. Unknown relevant fields remain UNKNOWN. This says
nothing about object retention, recovery, deletion safety or regulatory compliance.

## Output, bounds and CLI

One finding per bucket/category/control suppresses duplicate statements and
repeated configuration signals. Distinct controls such as public ACL and disabled
PAB remain separate. Findings sort by resource/category/control and checks by
resource/category; policy statement/resource ordering does not change output.
No timestamps, random IDs or new fingerprints are added. Inputs are not mutated.

Reports are private JSON with fixed messages/enums, source Terraform identity,
closed check records and counts. Policy bodies, bucket names, ARN values, logging
targets, KMS identifiers, condition prose and untrusted metadata are not copied.
Terraform addresses can themselves contain sensitive keys; protect private storage.
No executable Markdown, sanitized upload or workflow integration is added.

Limits: 8 MiB plan; shared depth 32, 4096 module nodes, 2048 snapshot resources
plus 2048 changes; 256 buckets; at most one matched companion per kind/bucket;
256 KiB policy and 256 statements; 128 actions/resources/principals per list,
eight principal kinds, 32 Condition operators with 128 terms/list values each;
2048-character identity/action/resource/condition strings; 256 lifecycle rules;
8192 findings and 2048 check records. Oversized/malformed input fails. The CLI
checks file size before loading. Overall plan/policy byte limits additionally
bound unsupported metadata. JSON serialization rejects nonfinite values.

```sh
python scripts/analyze-data-protection.py --help
python scripts/analyze-data-protection.py --plan tests/fixtures/data/s3-secure.json --output reports/private/phase4/data-protection-report.json
```

Output must resolve under reports/private. Exclusive creation prevents overwrite;
ordinary failed writes remove owned files. Hard termination can leave a partial
file; validate before consuming. Windows inherited ACLs govern private access.
Exit 0 means completed analysis, including findings/UNKNOWN. Exit 2 means
input/schema/dependency/output failure, with fixed value-free diagnostics.

security/data-protection-report.schema.json closes objects, bounds fields and
uses fixed IDs/enums. Runtime validation binds IDs to severity/message/status and
checks finding counts. Existing jsonschema/referencing are required; remote schema
retrieval is denied. No dependencies were added.

The normalized adapter reuses Phase 4's Conftest-compatible transport with explicit
cloudguard-data/s3/category provenance. Structural findings become failed and
UNKNOWN becomes warning, exception=false, source file/lines=null. This does not
claim Conftest ran. Existing normalized schemas/risk defaults are unchanged;
production Phase 3 runner/gate binding is untouched. See evidence.md for executed
tests, reproducibility and prior-phase regressions. Real AWS/hosted behavior and
future graph/posture integration require separate validation and scope.
