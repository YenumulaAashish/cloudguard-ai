# Security fixtures

JSON files are **synthetic deterministic inputs**, not real Terraform plans. JSON does not support comments, so every insecure fixture contains an explicit `_comment` field stating ONLY for security testing. No fixture creates AWS resources.

Secure baseline includes trusted SSH, all required tags, encrypted private S3 and narrowly scoped IAM. Each insecure fixture changes one concern: public SSH, public S3, missing encryption, missing tags or wildcard IAM.

`opa test ./policies -v` runs self-contained unit tests. `bash scripts/policy-test.sh` also runs Conftest against the secure fixture and verifies every insecure fixture returns policy failure with the expected message family. An executable error or policy compilation error is never accepted as detection.

Normal Checkov scanning targets only terraform/. Fixtures are policy inputs; they are not Terraform configurations for Checkov. Combined Checkov/OPA coverage experiments belong to Phase 2 and require a separate Terraform mutation corpus.


## Phase 2 tests

All original fixtures and Rego tests remain. Additional Rego cases exercise resource changes, replacement/deletion/no-op semantics, unknown security fields and known sensitive values. They follow the Terraform plan schema but are synthetic unit tests. Only an authenticated `terraform plan` followed by `terraform show -json` can provide the AWS integration result; that has not been run here.

`python -m unittest discover -s tests/unit -v` checks exception tampering, global suppression, failure masking, plan exit codes 0/1/2, export failures, stale evidence and secret stripping. Plan-process tests mock Terraform; they never deploy or contact AWS. A passing unit test is not OIDC or AWS permission verification.
