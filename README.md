> Phase 6: [single-operator architecture](docs/phase6-provisioning-architecture.md), [mock testing](docs/phase6-offline-mvp.md), [inactive live AWS setup](docs/phase6-live-setup.md). Secure native AWS adapters are coded; live configuration, connectivity and deployment remain separately authorized and unverified. Phase 1-5 controls are preserved.

> Phase 5 final hardening: [release/verification](docs/phase5-release.md), [bounded planning authorization (inactive)](docs/planning-authorization.md), and [Phase 6 roadmap](docs/phase6-roadmap.md). Historical authentication and planning passed; the real-plan security verdict failed and remains recorded. No fresh authenticated verification is claimed.

> **Current execution update**

CG-SM-PLAN-002 is **CONSUMED** by run 45484703135. Owner-confirmed OIDC authentication
and Terraform planning passed; the security verdict failed. Historical approval and
NOT RUN statements below describe earlier checkpoints, not current authorization.
See [the investigation](docs/real-plan-context-investigation.md). No retry or standing authorization is active.

# CloudGuard AI

**A Self-Testing AI-Assisted Policy-as-Code Framework for Secure Terraform Infrastructure**

Final-year engineering capstone. Phase 1 supplies modular Terraform and deterministic security policies; Phase 2 adds an enforced exception contract, read-only OIDC planning and sanitized evidence. AWS region: **ap-south-1**. Intended repository: [YenumulaAashish/cloudguard-ai](https://github.com/YenumulaAashish/cloudguard-ai).

**No AWS resources have been deployed.** OIDC/bootstrap code is implemented, but AWS-side configuration and authenticated GitHub planning have not been verified. Live AI validation, mutation testing, regression experiments and drift detection remain future work. Offline advisory analysis and the complete Phase 3 reporting chain are implemented. No experimental accuracy or coverage results are claimed.

## Frontend Dashboard

The React/TypeScript dashboard runs **without AWS**, using reviewed sanitized
Phase 3 reports and Phase 4 synthetic posture summaries. It offers eight views:
Overview, Findings, Cloud Posture, Risk Analysis, Security Graph, AI Advisory,
CI / Scan Status and AWS Integration. Risk and gate results come from the existing
engines; AI remains informational. Private findings, advisory prose and graph
topology are withheld. Missing real-plan evidence stays UNKNOWN.

```sh
cd frontend
npm install
npm run dev
# Production static build and tests:
npm run build
npm test
```

Use Node 22.20.0 / npm 10.9.3; `npm ci` uses the committed dependency lockfile.
Serve only `frontend/dist/`. The optional local AI service is documented below;
AWS login and deployment are unavailable.
See [frontend architecture, data sources, privacy boundaries and testing](docs/frontend-dashboard.md).
Historical AWS authentication and planning succeeded; the historical security verdict failed. Final verification of this hardened release remains pending.

## Live OpenAI advisory

The dashboard now offers an explicit **Explain with AI** action backed by a local
Python service and the OpenAI Responses API. Only reviewed static control context and allowlisted finding fields leave the server,
from either the synthetic catalog or an explicitly loaded sanitized report. The key stays server-side;
missing-key and offline operation remain supported. AI output is informational and
cannot change deterministic security results. See [setup, privacy, limits and tests](docs/live-ai-advisory.md).
This feature is independent of live AWS connectivity. The owner reports a live
advisory demonstration; this hardening task makes no paid API requests.

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

Authenticated plan targets now fail closed outside the protected manual workflow
and its separately approved persistent ledger. They do not authorize local AWS
execution; see [authorization setup](docs/planning-authorization.md).

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

**PHASE 3 — COMPLETE** for the locally validated offline scope. Phase 4 is complete for the locally validated offline scope.

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

Phases 1, 2, 3 and 4 are COMPLETE for the locally validated offline scope. Phase 5 is IN PROGRESS.

| Sub-phase | Status |
|---|---|
| 4.1 Deterministic IAM analyzer | COMPLETE |
| 4.2 Network exposure | COMPLETE |
| 4.3 S3/data protection | COMPLETE |
| 4.4 Security graph | COMPLETE |
| 4.5 Posture integration | COMPLETE |

The offline IAM analyzer reads supplied Terraform plan JSON, identifies bounded
structural permissions/trust risks and preserves unsupported or unknown context
for review. It makes no AWS, AI or network calls. It does not resolve effective
permissions or modify the existing policy gates and risk model.

```sh
python scripts/analyze-iam.py --plan tests/fixtures/iam/admin.json --output reports/private/phase4/iam-report.json
```

See [IAM input, controls, CLI, compatibility and limitations](docs/phase4-iam.md).

The Phase 4.2 offline network component analyzes supplied security-group plan
rules without claiming runtime reachability. It supports inline, legacy and modern
rule resources, preserves UNKNOWN context, and provides a Phase 3-compatible
adapter. See [network controls, CLI and limits](docs/phase4-network.md).

```sh
python scripts/analyze-network.py --plan tests/fixtures/network/public-ssh.json --output reports/private/phase4/network-report.json
```

The Phase 4.3 S3 data-protection component correlates supported local bucket
companions and reports public-access, encryption, versioning, logging, transport
and multipart-cleanup posture. Missing and unknown configuration remain distinct.
See [S3 controls, CLI and limitations](docs/phase4-data-protection.md).

```sh
python scripts/analyze-data-protection.py --plan tests/fixtures/data/s3-secure.json --output reports/private/phase4/data-protection-report.json
```

The Phase 4.4 private security graph records exact known-value relationships among
supported plan resources and preserves unresolved references. Optional validated
analyzer reports attach findings to matching nodes without changing severity or
inferring exploitability. See [graph contract and CLI](docs/phase4-security-graph.md).

```sh
python scripts/build-security-graph.py --plan tests/fixtures/graph/connected.json --output reports/private/phase4/security-graph.json
```

## Phase 4 closure: posture integration

**PHASE 4 — COMPLETE. PHASE 5 — IN PROGRESS.**

The offline integrator validates four explicit analyzer/graph reports, checks
cross-report consistency, preserves findings and summarizes highest-known severity
with UNKNOWN/review tracked separately. It publishes one private posture file,
a bounded sanitized summary and a completion receipt written last.

```sh
python scripts/run-phase4.py --iam-report IAM.json --network-report NETWORK.json --data-report DATA.json --graph-report GRAPH.json
```

Prior report formats remain unchanged. Private SHA-256 report fingerprints identify
canonical content; same-plan, freshness and authenticity remain UNKNOWN. Phase 4
posture does not replace Phase 3 policy or risk authority. Completion covers local
offline implementation, not production readiness or deployed AWS security.
See [posture contract, CLI, limits and closure](docs/phase4-posture-integration.md)
and [executed evidence](docs/evidence.md). Hosted Phase 4 integration remains NOT RUN.

## Phase 5: production and portfolio release

**Phase 5 — IN PROGRESS.**

| Sub-phase | Status |
|---|---|
| 5.1 Hosted CI and GitHub Actions verification | COMPLETE — HOSTED OFFLINE CI VERIFIED |
| 5.2 AWS OIDC and real Terraform plan validation | BLOCKED — SECURITY VERDICT FAILED; AUTH / PLAN PASSED (OWNER EVIDENCE) |
| 5.3 Phase 4 sanitized reporting | HISTORICAL UPLOAD PASS (OWNER EVIDENCE); v1.2 HOSTED CHECK PENDING |
| 5.4 Release hardening and security documentation | CODED — BOUNDED AUTHORIZATION INACTIVE; FINAL VERIFICATION PENDING |
| 5.5 Portfolio demo and final release | OWNER-REPORTED IMPORT / AI DEMOS; FINAL RELEASE VERIFICATION PENDING |

The credential-free workflow retains read-only permissions, exact sanitized
artifact paths and all deterministic gates. A local reviewed-contract verifier
and explicit synthetic Phase 4 smoke check now exercise hosted prerequisites.

```sh
python scripts/verify-hosted-ci.py
python scripts/verify-phase4-fixtures.py
```

**Phase 5.1 hosted offline execution: PASS**, verified in
[run 41108638752](https://github.com/YenumulaAashish/cloudguard-ai/actions/runs/41108638752)
at commit `6ec68df80ea9012e09c6e223e0789896ec7f8ad9`. Authenticated planning was
skipped. The dashboard is a separate offline frontend; it does not complete
Phase 5.2 or publish Phase 4 artifacts from CI. Historical local-only checkpoints
above retain their original scope. See [CI contract and supply-chain limits](docs/phase5-hosted-ci.md).

The latest previously verified hosted offline run is
[45418546667](https://github.com/YenumulaAashish/cloudguard-ai/actions/runs/45418546667)
for `c216c427c711f7511a74ef9f98a1f247c9d05dfd`; it does not validate subsequent local changes.
The Phase 5 integration now processes the exported plan with all Phase 4 engines,
publishes closed sanitized finding/posture bundles, and supports reviewed actual
finding catalogs in the advisory service and dashboard. Authenticated planning is
manual/main-only and requires both enable and explicit review-approval variables.
**CG-SM-PLAN-001 is CONSUMED** by failed authenticated run
[45469018350](https://github.com/YenumulaAashish/cloudguard-ai/actions/runs/45469018350).
The owner reports CloudTrail confirmed an OIDC subject mismatch and the live trust
was manually corrected. Bootstrap code now matches that exact subject. Successful
authentication/planning after correction remains **NOT RUN** in this task.
**CG-SM-PLAN-002 is APPROVED_RESTRICTED_SCOPE**; no retry is authorized by the old
2026-12-01T18:30:00Z cutoff. See the [failure record and fresh approval handoff](docs/oidc-subject-mismatch.md).
See [Phase 5 audit, contracts and manual handoff](docs/phase5-integration.md) and
[Phase 6 provisioning architecture](docs/phase6-provisioning-architecture.md).

Current approval update: **CG-SM-PLAN-002 is APPROVED_RESTRICTED_SCOPE** by the owner
on 2026-11-25, through **2026-12-01T18:30:00Z**, for one read-only planning attempt.
Only environment self-review is approved; no independent PR/CODEOWNERS waiver is
granted by this approval. The new record amendment still requires its own protected
PR, passing hosted check and exact resulting main binding. Execution is NOT RUN.
See [the current approval handoff](docs/plan-002-approval.md).
