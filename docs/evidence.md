# Sanitized evidence and reproducibility

`python scripts/run-offline.py` starts a fresh evidence run, runs all offline gates, and generates reports even when a gate fails. It returns nonzero if a required check fails. `python scripts/aws-plan.py` explicitly performs authenticated planning after the same gates. CI can reuse only current passing preflight evidence using `--reuse-offline`.

`python scripts/generate-evidence.py` / `make evidence` rebuilds summaries from actual recorded results; it does not execute missing checks or turn them into passes. Every record has a run identifier and source fingerprint. Records from a different run or changed source become NOT RUN. Generated reports are ignored by Git.

| File in reports/phase2 | Contents |
|---|---|
| summary.json / summary.md | Gate status, commit/ref, dirty state, CI run ID, tool/provider versions and region |
| checks.json | Terraform, lint and Python-test statuses |
| checkov.json | Actual Checkov counts and rule/resource pairs; source snippets, values and messages excluded |
| checkov-exceptions.json | Expected/observed/source exception counts, missing/unexpected pairs and contract status |
| policy-tests.json | Actual OPA test counts and each fixture's expected/observed result |
| ci-safety.json | Static deployment-command guard result |
| plan-summary.json | Plan exit status, resource addresses/types/actions and create/update/delete/read counts |
| plan-policy.json | Conftest pass/failure/warning/exception counts, without violation messages or values |
| run-context.json | Local run ID, scope, source fingerprint and start time; not uploaded independently |

Plan files appear only after an explicit plan attempt. Missing plan records are represented as NOT RUN in the aggregate summary. The first local checkout has no commit, so the Git SHA is null rather than fabricated. A replacement increments both create and delete counts. No mutation, accuracy, precision, recall, recovery or coverage metric is inferred from these counts.

## Sensitive data boundary

Raw `terraform/tfplan`, `terraform/tfplan.json`, source-scan JSON and tool logs can contain infrastructure details or secrets. They remain in ignored local paths (`terraform/tfplan*`, `reports/private/`) and are never selected by artifact upload. Terraform stdout/stderr and Conftest raw messages are captured privately rather than printed in authenticated CI. The plan runner uses a restrictive POSIX umask; on native Windows filesystem ACLs determine access. Use an appropriately protected workspace.

Sanitization builds new objects from explicit allowed fields; it does not rely on Terraform's `sensitive` marker alone. Known sensitive values are still checked in memory by OPA, but are not emitted in evidence. Tests seed sentinel secrets and verify they do not appear in summaries. Resource addresses are retained as permitted identifiers; avoid secrets in Terraform labels or instance keys.

Workflows upload an explicit list of sanitized files with **three-day retention**, including on failed runs. They never upload `reports/**` or the working directory. No raw-plan debug upload is enabled. `make clean` removes the generated binary/JSON plan only, not state; ignored private logs remain available locally for authorized debugging. CI's ephemeral runner is discarded after the job.

A PASS offline summary means offline gates passed; it does not mean AWS authentication or a real plan ran. The authenticated workflow's overall evidence requires both plan generation and plan policy evaluation. GitHub job failure/cancellation also prevents an overall PASS. Hosted execution and IAM permission verification must be reported separately.

## Phase 3.1 private findings

`python scripts/normalize-findings.py` reads existing full Checkov/Conftest JSON
and writes `reports/private/phase3/normalized-findings.json` by default. It does
not change the Phase 2 evidence schema or gate status. Unlike sanitized summaries,
normalized findings retain selected source messages and paths and must remain
private; no workflow uploads them. See [Phase 3.1](phase3-normalization.md).

## Phase 3.3 private advisory analysis

`python scripts/analyze-security.py` verifies matching normalized/risk reports
and writes advisory JSON plus optional Markdown under `reports/private/phase3/`.
Verified deterministic context is copied unchanged; provider advice cannot change
gate decisions or exception/risk state. Original messages, paths and metadata
are omitted, but retained identity fields and advice remain private. No workflow
uploads these reports. Offline mode uses templates and no credentials or network.
See [Phase 3.3](phase3-analysis.md) for data minimization, validation and limitations.

## Phase 3.4 bounded PR summaries

`python scripts/render-pr-summary.py` emits only schema-approved aggregate fields
to ignored `reports/sanitized/`, outside private storage. It validates matching
normalized/risk/advisory reports before rendering. `--current-evidence` reads
current Phase 2 run/fingerprint records and binds source findings to raw scan
output; absent, stale or unrelated evidence becomes UNKNOWN. OPA/Conftest fixture
tests are shown separately from real-plan policy evaluation.

Offline CI now uploads exactly `pr-summary.json`, `pr-summary.md` and
`phase3-evidence.json` under `reports/sanitized/phase35/` in a separate three-day
artifact, only after integrated runner success. Phase 3 private intermediates
are never uploaded.
There is no automatic comment publisher, write-token escalation or gate-result
override. JSON/Markdown reproduction, schema checks, leakage tests and workflow
regression tests run locally; runtime reports remain uncommitted. See
[Phase 3.4](phase3-pr-reporting.md) for the publication trust boundary.

## Final Phase 3 local validation: 2026-10-30 (Asia/Calcutta)

The existing offline runner completed with PASS, followed by two successful
Phase 3 integrated CLI runs against the actual source scan. No AWS APIs, live AI,
PR comments, deployment or hosted workflows were invoked. Terraform used the
existing local provider mirror with checkpoint and metadata lookup disabled.

| Validation | Observed result |
|---|---|
| Python suite | 218 PASS, 0 skips (184 existing + 34 integration tests) |
| Terraform formatting, both roots | PASS |
| Workload backend-free init / validate | PASS / PASS |
| Bootstrap backend-free init / validate | PASS / PASS |
| TFLint including AWS rules | PASS |
| Checkov | 30 passed / 0 failed / 6 skipped / 0 parsing errors |
| Exception contract | PASS: expected 6, observed 6, missing 0, unexpected 0 |
| OPA | 35 PASS |
| Conftest fixtures | 6 PASS, including expected rejection cases |
| Destructive-command guard / offline runner | PASS / PASS |
| Phase 3 integrated chain | PASS |
| Five JSON Schemas | PASS |
| Phase 3.1 / 3.2 / 3.3 / 3.4 regression reproduction | Byte-identical to previous local outputs |
| Two complete Phase 3.5 runs | All seven JSON/Markdown files byte-identical |
| Workflow permissions, fork safety, exact artifact selection | PASS (static regression tests) |
| Privacy, leakage, failure cleanup, authority boundaries | PASS (regression tests) |

Recorded toolchain: Terraform 1.9.8, AWS provider 6.65.0, TFLint 0.59.1,
AWS ruleset 0.40.0, Checkov 3.2.471, OPA 1.0.1 and Conftest 0.60.0.
Existing schema libraries were jsonschema 4.26.0 and referencing 0.37.0;
PyYAML 6.0.3 supported workflow tests. No dependencies were added or installed.
These transitive Python libraries are recorded here, not independently pinned.

The unchanged sanitized baseline has six findings, zero failures, six approved
exceptions, risk 13 / LOW / requires_review true, and six offline advisory reviews.
Checkov, exception contract and policy tests are PASS. Real-plan OPA/Conftest is
UNKNOWN: passing fixtures do not demonstrate a real plan passed.

The completion receipt has fixed constants only and records actual component,
schema, consistency and reproduction completion, not policy approval. Phase 2
remains authoritative for tool versions and gate evidence. Runtime reports stay
ignored and are not committed. See [integration](phase3-integration.md) for the
strict schema, evidence binding and completion-last publication protocol.

The first new-test attempt hit Windows sandbox rename access denial; all 34 tests
passed with local filesystem access, without a code change to bypass validation.
The full 218-test suite then passed in that execution context. Hard interruption
can leave incomplete files; consumers require a valid receipt and successful
runner completion. This is not a two-directory atomic transaction or signed
attestation, and assumes a trusted workspace.

Hosted runner behavior, artifact upload service, PR UI rendering, OIDC exchange,
AWS authentication and real AWS planning: **NOT RUN / REQUIRES HOSTED VERIFICATION**.
Live AI: **NOT RUN / OUT OF SCOPE**. Phase 4 is not implemented.

## Phase 4.1 local validation: 2026-10-30

The IAM analyzer adds no dependencies, workflow changes, AWS access, live AI or
Terraform execution. It analyzes synthetic supplied plan JSON, not live AWS state.
The existing toolchain and provider mirror are reused. Source policies, exceptions,
Phase 3 schemas, risk model and production runner remain unchanged.

New IAM unit tests: 61 PASS. Complete Python suite: 279 PASS (218 existing + 61).
Standalone CLI schema validation and two-run byte-identical reproduction: PASS.
Normalized-schema/risk compatibility: PASS, including UNKNOWN warning handling.
No-network/execution, inert malicious input, private boundaries, no-overwrite,
unknowns, Deny, Conditions, bounds and schema-tampering regressions: PASS.

See [IAM analyzer](phase4-iam.md) for controls, limits and structural-analysis
limitations. No effective-permissions or confirmed-escalation claim is made.
Runtime IAM reports remain ignored under reports/private and are not staged.

Final-source offline regression: PASS. Terraform formatting and backend-free
init/validation for both roots: PASS. AWS TFLint: PASS. Checkov: 30 passed,
0 failed, 6 skipped, 0 parsing errors. Exception contract: PASS (6 expected,
6 observed, 0 missing, 0 unexpected). OPA: 35 PASS. Conftest: 6 fixtures PASS.
Destructive-command guard: PASS. Integrated offline runner: PASS.
Two fresh Phase 3 CLI runs: PASS, all seven outputs byte-identical both to each
other and to the Phase 3.5 baseline. Risk 13 / LOW / requires_review true,
six approved exceptions, zero failed findings and real-plan policy UNKNOWN remain
unchanged. The final source fingerprint matches the offline evidence context.

Phase 4.1 is locally validated; hosted CI, OIDC, AWS authentication, real AWS
plans and live AI were NOT RUN. Phase 4 remains IN PROGRESS; 4.2–4.5 not started.

## Phase 4.2 local validation: 2026-10-30

New network tests: 88 PASS. Complete Python suite: 367 PASS, 0 skips (279 existing
plus 88 new). Existing IAM tests: 61 PASS. Network schemas, normalized/risk adapter,
malformed/unknown input, direction/false-positive, bounds, inert injection,
no-execution/network and private no-overwrite regressions: PASS.

Terraform formatting and backend-free init/validation for both roots: PASS.
AWS TFLint: PASS. Checkov: 30 passed, 0 failed, 6 skipped, 0 parsing errors.
Exception contract: PASS (6 expected, 6 observed, 0 missing, 0 unexpected).
OPA: 35 PASS. Conftest: 6 fixtures PASS. Destructive-command guard and integrated
offline runner: PASS. Current evidence matches the final source fingerprint.

Two Phase 3 CLI runs: PASS. All seven files match each other and the Phase 3.5
baseline byte-for-byte. Risk 13 / LOW / requires_review true, six approved
exceptions, zero failed findings and real-plan OPA/Conftest UNKNOWN remain intact.
Two network CLI reports are byte-identical. IAM CLI output matches the Phase 4.1
baseline byte-for-byte after extraction of its unchanged plan projection into a
shared helper. IAM controls, schema and risk behavior are unchanged.

No dependencies or workflow changes were added. Terraform used cached providers
with checkpoint/metadata lookup disabled. No AWS, deployment, live AI, hosted
workflow trigger, PR comment or external policy lookup was performed. Hosted
execution, OIDC, AWS authentication, real plans and reachability: NOT RUN.
Runtime network/IAM reports remain ignored private files, not committed artifacts.
Privacy, staged-file and secret review passed. See [network analyzer](phase4-network.md)
for exact controls and limits. Phase 4.2 is locally complete; Phase 4 remains
IN PROGRESS and 4.3–4.5 remain NOT STARTED.

## Phase 4.3 local validation: 2026-10-30

New S3 data-protection tests: 81 PASS. Complete Python suite: 448 PASS, 0 skips
(367 existing + 81). Existing IAM tests: 61 PASS. Network tests: 88 PASS.
Data report schema, deterministic CLI bytes, normalized/risk compatibility,
missing/unknown mapping, policy/ACL false-positive defenses, bounds, inert input,
private output/no-overwrite and no-network/execution regressions: PASS.

Terraform formatting, workload and bootstrap backend-free init/validate: PASS.
AWS TFLint: PASS. Checkov: 30 passed, 0 failed, 6 skipped, 0 parsing errors.
Exception contract: PASS (6 expected, 6 observed, 0 missing, 0 unexpected).
OPA: 35 PASS. Conftest: 6 fixtures PASS. Destructive guard and integrated offline
runner: PASS. Evidence matches the final source fingerprint.

Two new Phase 3 CLI runs passed; all seven output files match each other and the
Phase 3.5 baseline byte-for-byte. Risk 13 / LOW / requires_review true, six approved
exceptions, zero failed findings and real-plan OPA/Conftest UNKNOWN remain intact.
IAM and network CLI outputs match their previous baselines byte-for-byte.
Two new S3 CLI reports are byte-identical. Reports remain ignored private files.

Final review added a regression for provider-shaped empty lifecycle filters with
null/empty defaults, preserving the existing global seven-day multipart cleanup
semantics. All validation above ran against that final implementation.

No dependencies, shared-helper, IAM/network, workflow, policy, exception or risk
model changes were made. Terraform used the existing local provider mirror with
checkpoint/metadata lookup disabled. AWS/S3/KMS APIs, deployment, live AI, external
policy lookup, PR comments, Git pushes and hosted triggers were not performed.
Hosted execution, OIDC, AWS authentication, real AWS plans and runtime/object
state: NOT RUN. Privacy, reviewed staging and secret checks passed.
See [S3 scope and controls](phase4-data-protection.md) for limits and uncertainty.
Phase 4.3 is locally complete; Phase 4 remains IN PROGRESS, 4.4/4.5 NOT STARTED.

## Phase 4.4 local validation: 2026-10-30

New graph tests: 80 PASS. Complete Python suite: 528 PASS, 0 skips (448 existing
plus 80). Existing IAM 61, network 88 and data-protection 81 tests remain PASS.
Graph schema, exact-value/ambiguity/unknown handling, typed provenance, cycles,
bounds, inert input, no network/execution and private no-overwrite tests: PASS.
Two graph CLI runs with all three optional analyzer reports produce byte-identical
reports. Finding associations preserve control/severity/status without rerunning
analyzers, inventing edges or producing new security findings: PASS.

Terraform formatting and both roots' backend-free init/validate: PASS. AWS TFLint:
PASS. Checkov: 30 passed, 0 failed, 6 skipped, 0 parsing errors. Exception contract:
PASS (6 expected, 6 observed, 0 missing, 0 unexpected). OPA: 35 PASS. Conftest:
6 fixtures PASS. Destructive guard and integrated offline runner: PASS. Final
source fingerprint matches the current evidence context.

Two fresh Phase 3 CLI runs passed; all seven files match each other and the
Phase 3.5 baseline byte-for-byte. Risk 13 / LOW / requires_review true, six approved
exceptions, zero failed findings and real-plan policy UNKNOWN remain unchanged.
Fresh IAM/network/data CLI outputs match their previous baselines byte-for-byte.
Prior analyzers, schemas, shared projection, security policies and risk model
were not modified. Graph-to-Phase-3 compatibility is NOT APPLICABLE because no
CGA_GRAPH security findings or new risk model were introduced.

No dependencies or workflow changes were added. All runtime graph/analyzer reports
remain private and ignored; synthetic topology fixtures are the only committed
plan-shaped data. Privacy, reviewed staging and secret checks passed. No AWS,
network lookup, deployment, live AI, hosted trigger, PR comment or Git push was
performed. Terraform used cached providers with checkpoint/metadata lookup disabled.
Hosted execution, OIDC, AWS authentication, real plans and runtime reachability:
NOT RUN. Associations prove exact-address matching only, not report freshness or
exploitability. See [graph contract](phase4-security-graph.md) for supported facts
and limits. Phase 4.4 is locally complete; Phase 4 remains IN PROGRESS and
Phase 4.5 remains NOT STARTED.

## Phase 4.5 and Phase 4 closure: local validation 2026-10-30

New posture/integration tests: 50 PASS. Complete Python suite: 578 PASS, 0 skips
(528 existing + 50). IAM 61, network 88, data 81 and graph 80 existing tests remain
PASS. All three new schemas, cross-report consistency, UNKNOWN preservation,
no-score authority boundaries, canonical fingerprints, leakage canaries,
completion-last ordering, no-overwrite and write/rename/readback cleanup: PASS.
Two integrated CLI runs produce all three files byte-identically.

Terraform formatting and workload/bootstrap backend-free init/validate: PASS.
AWS TFLint: PASS. Checkov: 30 passed, 0 failed, 6 skipped, 0 parsing errors.
Exception contract: PASS (6 expected, 6 observed, 0 missing, 0 unexpected).
OPA: 35 PASS. Conftest: 6 fixtures PASS. Destructive guard and integrated offline
runner: PASS. Final source fingerprint matches the current evidence context.

Two fresh Phase 3 runs match all seven baseline files byte-for-byte, retaining
risk 13 / LOW / requires_review true, six approved exceptions, zero failed findings
and real-plan policy UNKNOWN. Fresh IAM/network/data/graph CLI outputs match their
previous baselines byte-for-byte. All prior components, schemas, risk model,
policies, exceptions and workflows are unchanged. No dependencies were added.

The synthetic connected fixture produces highest-known category CRITICAL with
review required; this is separate from Phase 3 risk and policy gates. Context,
freshness and authenticity remain UNKNOWN. Canonical report SHA-256 records are
private content identifiers, not common-plan proof or a signed attestation.
Runtime posture/graph/analyzer reports remain ignored and were not staged.
Privacy, reviewed staging and secret checks passed. No real private plans or
reports are committed.

The completion receipt records only actual integration validations, not fabricated
upstream regression passes. This section records the separately executed regression
suite. Summary publication alone is incomplete; consumers require the final receipt
and validated bundle. Hard interruption can leave partial output, as documented.

AWS/API/network lookups, deployment, live AI, PR comments, hosted triggers and Git
pushes were not performed. Terraform used cached providers with checkpoint/metadata
lookup disabled. Hosted Phase 4 integration, artifact services, OIDC, AWS
authentication, real plans and runtime security: NOT RUN.

Phases 4.1–4.5 are COMPLETE for the locally validated offline scope. PHASE 4 is
COMPLETE; PHASE 5 remains NOT STARTED. See [closure contract](phase4-posture-integration.md)
for the exact authority, uncertainty, privacy, bounds and atomicity limitations.

## Phase 5.1: local CI preparation validation, 2026-10-30

LOCAL VALIDATION: PASS. New CI-security tests: 69 PASS. Complete Python suite:
647 PASS, 0 skips (578 existing + 69). IAM 61, network 88, data 81, graph 80 and
posture 50 existing tests remain PASS. Reviewed YAML/source/tool contract, fork
boundary, read-only permissions, checkout safety, no-deployment, exact artifacts,
malformed/inert YAML, bounded diagnostics and false-hosted-claim regressions: PASS.

Terraform formatting and both roots' backend-free init/validate: PASS. AWS TFLint:
PASS. Checkov: 30 passed, 0 failed, 6 skipped, 0 parsing errors. Exception contract:
PASS (6 expected, 6 observed, 0 missing, 0 unexpected). OPA: 35 PASS. Conftest:
6 fixtures PASS. Existing destructive guard and integrated offline runner: PASS.
Final source fingerprint matches the current evidence context.

Fresh Phase 3 runs match all seven outputs byte-for-byte, retaining risk 13 / LOW /
requires_review true, six approved exceptions, zero failed findings and real-plan
policy UNKNOWN. Fresh IAM/network/data/graph reports match prior baselines.
The exact new synthetic Phase 4 CI command passed locally. All three smoke-bundle
files match two other smoke runs and the Phase 4.5 baseline byte-for-byte. No
Phase 4 artifact upload was added. The version-1 Phase 4 receipt's historical
Phase 5 marker is preserved; README records the current roadmap.

Only the offline workflow changed: explicit ubuntu-24.04/bash, checkpoint/metadata
disabled, reviewed-contract verification and ephemeral Phase 4 fixture validation.
The authenticated-plan workflow, setup-tools, action tags, tool/provider pins,
private/sanitized artifact boundaries and three-day retention remain unchanged.
No dependencies were added or installed. Local Python: 3.12.0. Version tags,
Python patch selection, OS images and transitive dependencies retain documented
supply-chain/reproducibility limitations. No remote action SHA was guessed.

Privacy, reviewed staging and secret checks passed. Runtime reports, raw plans,
topology and private graph/posture files were not staged. No AWS/API access,
deployment, live AI, PR comments, hosted triggers or Git push was performed.
Terraform used cached providers with checkpoint/metadata lookup disabled.

GITHUB-HOSTED EXECUTION: NOT RUN / PENDING USER PUSH. Local workflow parsing and
security tests do not verify hosted action availability, Linux installation,
artifact service behavior, execution timing, OIDC or AWS authentication. For
5.1-only hosted verification, leave AWS_PLAN_ENABLED disabled and inspect the
offline run after a user-controlled push. See [hosted CI contract](phase5-hosted-ci.md).
Phase 5.1 implementation and local CI-security validation are COMPLETE; hosted
execution remains pending. Phase 5 is IN PROGRESS; 5.2–5.5 remain NOT STARTED.
