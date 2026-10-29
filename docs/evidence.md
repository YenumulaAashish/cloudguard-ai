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

Offline CI uploads only the exact `pr-summary.json` and `pr-summary.md` files in
a separate three-day artifact. Phase 3 private intermediates are never uploaded.
There is no automatic comment publisher, write-token escalation or gate-result
override. JSON/Markdown reproduction, schema checks, leakage tests and workflow
regression tests run locally; runtime reports remain uncommitted. See
[Phase 3.4](phase3-pr-reporting.md) for the publication trust boundary.
