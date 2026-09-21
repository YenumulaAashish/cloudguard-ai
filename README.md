# CloudGuard AI

**A Self-Testing AI-Assisted Policy-as-Code Framework for Secure Terraform Infrastructure**

Final-year engineering capstone. Phase 1 supplies modular Terraform and deterministic security policies; Phase 2 adds an enforced exception contract, read-only OIDC planning and sanitized evidence. AWS region: **ap-south-1**. Intended repository: [YenumulaAashish/cloudguard-ai](https://github.com/YenumulaAashish/cloudguard-ai).

**No AWS resources have been deployed.** OIDC/bootstrap code is implemented, but AWS-side configuration and authenticated GitHub planning have not been verified. AI, mutation testing, regression experiments and drift detection remain future work. No experimental accuracy or coverage results are claimed.

## Infrastructure and security

Three Terraform modules define a VPC, public/private subnets, an internet gateway and routes, security groups, and private encrypted/versioned S3 storage with TLS enforcement. Private routing has no internet default route. Public IP assignment and SSH are disabled by default. Explicit security-group rule lists preserve default deny while making planned ingress inspectable. Optional trusted IPv4 SSH ranges are configurable. `enable_ec2` must remain false.

There is no compute, NAT gateway, database, load balancer or paid monitoring. A seven-day lifecycle rule aborts incomplete multipart uploads without expiring completed objects. Deployment could incur storage/request/transfer costs; it remains a separate approval decision.

Terraform defines infrastructure. TFLint checks configuration quality. Checkov scans Terraform source. OPA/Conftest evaluates organization policies against plan JSON. AI is **not** the final security authority; future suggestions must pass these deterministic gates and human approval.

## Run offline checks

Install the toolchain in [setup](docs/setup.md), then:

```sh
TFLINT_AWS=1 make test
# Equivalent portable entry point (including native Windows):
python scripts/run-offline.py
```

Set `TFLINT_AWS=1` in the environment to include AWS lint in the portable command. The default local lint uses core rules and explicitly reports the AWS plugin as NOT RUN. CI requires both.

Offline means **no AWS credentials or AWS API calls**; provider/tool installation still needs network access. The runner executes Terraform formatting, backend-free init and validation for both roots, lint, Python negative-control tests, the destructive-CI guard, source Checkov, the exception contract, OPA tests and Conftest fixtures. Failures produce a nonzero exit status. Evidence is retained even if a gate fails.

Existing targets remain: `init`, `fmt`, `validate`, `lint`, `security`, `policy-test`, `plan`, `clean`. New targets: `check-exceptions`, `ci-safety`, `aws-plan`, `plan-json`, `plan-policy`, `evidence`.

```sh
make security          # Fresh source scan plus exact exception verification
make check-exceptions  # Check source against the last private scan JSON
make policy-test
make evidence          # Generate summaries; missing/stale results are NOT RUN
```

Exactly six [resource-scoped Checkov exceptions](docs/security-exceptions.md) are allowed. The guard verifies both source annotations and actual scan records. Additional, missing, moved or duplicated exceptions, global suppression, parser errors and unaccepted failures block CI. A skipped check is never reported as passed. Rego has no corresponding exceptions.

## Authenticated planning (explicit, opt-in)

After separately configuring AWS/GitHub as described in [github-oidc.md](docs/github-oidc.md):

```sh
make aws-plan
# `make plan` and `make plan-json` are explicit aliases for this authenticated path.
# To evaluate an existing real plan without AWS access:
make plan-policy
```

The plan runner handles Terraform exit 0 and 2 as successful planning, rejects exit 1, exports JSON, and runs Conftest. It does not deploy. CI skips authenticated planning for forks and until the required variables/environment exist. The plan role has selected metadata-read permissions, not deployment permissions.

Raw plans and logs stay in ignored private local paths. CI uploads only named sanitized evidence files for three days. See [evidence](docs/evidence.md), [policy contract](docs/policies.md), [architecture/research traceability](docs/architecture.md), and [validation](docs/validation.md).
