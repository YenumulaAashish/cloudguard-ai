# CloudGuard AI

**A Self-Testing AI-Assisted Policy-as-Code Framework for Secure Terraform Infrastructure**

Final-year engineering capstone. Phase 1 supplies modular Terraform and deterministic security policies; Phase 2 adds an enforced exception contract, read-only OIDC planning and sanitized evidence. AWS region: **ap-south-1**. Intended repository: [YenumulaAashish/cloudguard-ai](https://github.com/YenumulaAashish/cloudguard-ai).

**No AWS resources have been deployed.** OIDC/bootstrap code is implemented, but AWS-side configuration and authenticated GitHub planning have not been verified. Live AI, mutation testing, regression experiments and drift detection remain future work. Offline advisory analysis and the complete Phase 3 reporting chain are implemented. No experimental accuracy or coverage results are claimed.

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

## Phase 3.1: finding normalization

A deterministic standard-library Python adapter converts existing full Checkov
and Conftest JSON reports into schema 1.0 findings. It preserves failed/skipped
status and the six-pair exception annotation; missing severity remains UNKNOWN.
Existing security gates remain authoritative. No AI or additional Terraform
detection is introduced.

```sh
python scripts/normalize-findings.py --checkov reports/private/checkov-raw.json
```

Output defaults to the ignored private file
`reports/private/phase3/normalized-findings.json`; existing files are never
overwritten. It is not uploaded by CI. See [schema, commands, limitations and
Phase 3.2 handoff](docs/phase3-normalization.md). Existing Python test discovery
includes the new normalizer tests.

## Phase 3.2: deterministic risk scoring

A separate standard-library engine prioritizes Phase 3.1 findings on an explicit
0-100 scale, with versioned weights, status/exception treatment and explainable
factors. Overall risk is the highest individual priority. UNKNOWN severity stays
visible. **Risk scoring does not override policy enforcement.**

```sh
python scripts/score-risk.py --input reports/private/phase3/normalized-findings.json
```

Output defaults to `reports/private/phase3/risk-report.json`; existing files are
never overwritten or uploaded by CI. See [model, schema, commands and limitations](docs/phase3-risk.md).
Phase 3.3 builds advisory explanations on these immutable results.

## Phase 3.3: advisory security explanation and remediation

**Deterministic tools decide. AI explains.** An optional standard-library analyzer
verifies matching normalized/risk reports and adds validated private advice.
Offline mode uses honest deterministic templates; a provider interface supports
future adapters. No live AI provider is configured, and requested AI mode fails
clearly. **AI-generated remediation is advisory and does not override policy
enforcement or risk scoring.**

```sh
python scripts/analyze-security.py --findings reports/private/phase3/normalized-findings-phase32.json --risk reports/private/phase3/risk-report.json --mode offline
```

Output defaults to `reports/private/phase3/remediation-report.json`, with optional
`--markdown PATH`. Existing files are never overwritten or uploaded by CI.
See [trust boundary, provider contract, schema and limitations](docs/phase3-analysis.md).
No automated Terraform remediation is implemented.

## Phase 3.4: sanitized PR security reporting

**Deterministic tools decide. AI explains. PR reporting informs.** The reporter
validates matching private Phase 3 reports and emits bounded aggregate JSON and
Markdown. Gate statuses come from current matching evidence or remain UNKNOWN;
LOW risk never implies policy PASS. Offline CI produces sanitized artifacts with
unchanged read-only permissions. Automatic PR comments are not implemented.

```sh
python scripts/render-pr-summary.py --findings reports/private/phase3/normalized-findings-phase33-final.json --risk reports/private/phase3/risk-report-phase33-final.json --remediation reports/private/phase3/remediation-final.json --current-evidence --output reports/sanitized/pr-summary.json --markdown reports/sanitized/pr-summary.md
```

See [privacy, gate authority, CLI and publication boundary](docs/phase3-pr-reporting.md).
Generated reports remain uncommitted. A PR report is informational and does not
replace CI security gate conclusions.

| Phase | Status |
|---|---|
| 3.1 Finding normalization | COMPLETE |
| 3.2 Deterministic risk prioritization | COMPLETE |
| 3.3 Advisory security analysis | COMPLETE |
| 3.4 Sanitized PR security reporting | COMPLETE |
| 3.5 Integration/evidence | COMPLETE |

**PHASE 3 — COMPLETE** for the locally validated offline scope. Phase 4 is in progress.

## Phase 3.5: integrated execution and evidence

Checkov/Conftest JSON -> normalized findings -> deterministic risk -> offline
advice -> sanitized PR reporting -> validated completion receipt.

```sh
python scripts/run-phase3.py --checkov reports/private/checkov-raw.json --current-evidence --mode offline
```

The runner reuses the existing engines, requires the JSON Schema libraries from
the Checkov toolchain, validates every stage, checks cross-phase consistency and
reproduces all bytes before publishing. Private outputs stay under
`reports/private/phase35/`; three bounded public files stay under
`reports/sanitized/phase35/`. Existing directories are never overwritten; use new
output directories for reruns. CI uploads only after successful completion.

The final local baseline is 218 Python tests, Checkov 30/0/6 with zero parsing
errors, six exact exceptions, 35 OPA tests and six Conftest fixtures passing.
All Phase 3 outputs reproduce byte-for-byte. Real-plan policy remains UNKNOWN;
hosted execution, OIDC, AWS planning and live AI are not verified.
See [integration and closure](docs/phase3-integration.md) and
[validation evidence](docs/evidence.md) for failure behavior and limitations.

## Phase 4: advanced cloud security

Phases 1, 2 and 3 are COMPLETE. Phase 4 is IN PROGRESS.

| Sub-phase | Status |
|---|---|
| 4.1 Deterministic IAM analyzer | COMPLETE |
| 4.2 Network exposure | NOT STARTED |
| 4.3 S3/data protection | NOT STARTED |
| 4.4 Security graph | NOT STARTED |
| 4.5 Posture integration | NOT STARTED |

The offline IAM analyzer reads supplied Terraform plan JSON, identifies bounded
structural permissions/trust risks and preserves unsupported or unknown context
for review. It makes no AWS, AI or network calls. It does not resolve effective
permissions or modify the existing policy gates and risk model.

```sh
python scripts/analyze-iam.py --plan tests/fixtures/iam/admin.json --output reports/private/phase4/iam-report.json
```

See [IAM input, controls, CLI, compatibility and limitations](docs/phase4-iam.md).
