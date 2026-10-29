# Phase 3.4: sanitized PR security reporting

**Deterministic tools decide. AI explains. PR reporting informs.**

**A PR report is informational and does not replace CI security gate conclusions.**

This reporting layer consumes existing Phase 3.1 normalized findings, the matching
Phase 3.2 risk report, and optionally Phase 3.3 advisory output. It creates fresh
aggregate objects, never copies private finding objects, and never changes policy,
exceptions, risk, review flags or gate evidence. It performs no networking, cloud
operations, AI requests, code execution, remediation or publication.

## Architecture and consistency

```text
normalized findings + risk report + optional advisory report
  -> existing complete Phase 3.3 consistency validation
  -> explicit primitive projection + matching current gate records
  -> strict sanitized schema validation
  -> ignored reports/sanitized/pr-summary.json and optional .md
```

The core reuses `consistent_risk` to compare the complete supplied risk report
against Phase 3.2 computation, including identity, model, scores, categories,
review flags, duplicate records and summary counts. It reuses
`validate_remediation` to bind advisory identities and deterministic context to
that verified risk report. Malformed, unsupported or mismatched reports fail
without producing a summary. Existing producers and their authority boundaries
are unchanged. No advisory provider is invoked by the reporter.

Missing optional advisory input is explicitly `NOT_RUN`, with zero reviewed
findings. A supplied advisory report must cover every finding. Its mode is copied;
its provider name, prose, examples, paths and metadata are never published.

## Gate authority

Without `--current-evidence`, every policy field is UNKNOWN. Risk LOW and zero
failed findings never imply policy PASS. There is no synthesized overall verdict.

With that flag, `pr_evidence.py` reads existing local Phase 2 run context and
structured gate records, without creating a context, running gates, parsing logs
or modifying evidence. A record must match the current source fingerprint and
run ID. Missing, stale, malformed, NOT RUN or unrelated records become UNKNOWN.

| Public field | Recorded source and binding |
|---|---|
| `checkov` | `checkov.json`; normalized Checkov findings must match the current private raw Checkov report |
| `exception_contract` | `checkov-exceptions.json`; same raw-to-normalized binding |
| `opa_conftest` | `plan-policy.json`; normalized Conftest findings must match private real-plan policy output, whose structured result/counts must agree |
| `policy_tests` | `policy-tests.json`; current source/run OPA unit tests and Conftest fixture results |

The Markdown distinguishes **OPA / Conftest real-plan policy** from **OPA /
Conftest tests**. Offline CI has no real plan, so its real-plan policy remains
UNKNOWN even when every fixture passes. Findings describe the supplied report's
sources, not unperformed scans. Exception counts are existing annotations, not new
approvals; their independent contract status remains visible.

The workspace, gate producers and caller must be trusted. Source fingerprints and
run IDs detect stale/mixed evidence; they are not signatures, proof of authenticity
or a defense against malicious code controlling its own checkout. The pure Python
API can accept an explicit trusted caller's validated status mapping; the CLI
provides no arbitrary gate JSON or manual PASS override. Neither this mapping nor
the resulting artifact can authorize deployment or replace GitHub check results.

## Sanitization, schema and size

`security/pr-summary.schema.json` is a closed Draft 2020-12 schema, version 1.0.
Every object rejects additional fields. The entire output has only:

- Fixed version/producer and `informational_only: true`.
- Four gate enums: PASS, FAIL, UNKNOWN.
- Total, failed and approved-exception counts: integers 0..1,000,000.
- Original risk score 0..100, category NONE/LOW/MEDIUM/HIGH/CRITICAL and review boolean.
- Advisory mode offline/ai/NOT_RUN and bounded reviewed count.

There are no arrays, arbitrary strings, identifiers, paths, links or metadata.
The runtime enforces the same closed contract plus count consistency. JSON and
Markdown are each capped at **4096 UTF-8 bytes**; aggregation keeps size independent
of finding count. Oversized counts fail instead of silently truncating or changing
facts. Tests include 3,000 findings. Input processing still scales with input size;
the output bound is not an input-memory sandbox.

Markdown is rendered only from validated primitives and fixed labels. Its fixed
marker is `<!-- cloudguard-ai-security-review -->`. Arbitrary messages, resource
names, source paths, HTML, headings, links, hidden markers and provider prose have
no route into its structure. JSON remains the machine-readable source of truth.

`reports/sanitized/` means eligible for this schema's reporting use, not universally
safe or authenticated. Even aggregate security posture may be organizationally
sensitive. Detailed inputs stay in ignored `reports/private/`; sanitized outputs
also remain uncommitted under existing ignore rules. No new dependency is needed.
Tests reuse jsonschema/PyYAML already installed with Checkov.

## CLI

Run from the repository root, choosing fresh output filenames:

```sh
python scripts/render-pr-summary.py --help
python scripts/render-pr-summary.py \
  --findings reports/private/phase3/normalized-findings-phase33-final.json \
  --risk reports/private/phase3/risk-report-phase33-final.json \
  --remediation reports/private/phase3/remediation-final.json \
  --current-evidence \
  --output reports/sanitized/pr-summary.json \
  --markdown reports/sanitized/pr-summary.md
```

The same CLI works on Windows; use one line or PowerShell continuation syntax.
JSON defaults to `reports/sanitized/pr-summary.json`; Markdown is opt-in.
`--risk-model` selects the existing reviewed model used for verification.
No token, AWS credential, API key, AI provider or network is required.

Existing files are never overwritten, including input files. Output paths cannot
be inside a resolved `reports/private` subtree, and JSON/Markdown paths must
differ. All validation precedes exclusive writes. A failed write rolls back only
new files owned by that invocation. Hard termination is not a multi-file atomic
transaction; inspect incomplete outputs after an interrupted process. Windows
inherits filesystem ACLs; protect the workspace.

Exit 0 means **report generation succeeded**, even if policy is FAIL. Exit 2 means
invalid input, an inconsistent report, unavailable I/O or an output collision.
Errors are fixed text and do not echo source values or local paths. Neither exit
code changes existing gate records or converts a failed CI check into success.

## GitHub Actions and forks

Only `.github/workflows/terraform-ci.yml` changes. Its existing triggers remain
`pull_request`, main `push`, and `workflow_dispatch`. Workflow permissions remain
`contents: read`, with no job permission override. Checkout still disables
credential persistence. No secrets, cloud credentials or AI keys are introduced.

After gate/evidence generation, an `always()` step runs the existing normalizer,
risk engine and offline advisory analyzer, then the new reporter. Private
intermediates use `reports/private/phase34/`. Only the two exact sanitized filenames
are added in a separate artifact, with three-day retention. Existing Phase 2
artifact lists remain unchanged. There are no directory wildcards or private
uploads. This does not automatically append artifact Markdown to a PR or job page.

Gate failure does not prevent an attempted report. No failure masking is added:
the original failed step still fails the job. If the scan cannot produce valid
input, reporting fails visibly and there is no fabricated green report. The
always-run uploads may report missing files. Fresh hosted runners avoid existing
output collisions; local reruns must use new output filenames.

Fork PRs use the same credential-free read-only offline job where GitHub permits
execution (first-contributor approval may be required). The existing separate
authenticated-plan workflow is unchanged: protected `aws-plan` environment,
explicit enable variables, same-repository PR/main restrictions and scoped OIDC
permission. Forks remain excluded. This task does not configure or execute it.

## Publication boundary

**Automatic PR commenting is not implemented.** This phase provides local/CI
artifacts for review without introducing a privileged artifact consumer or write
token. No `pull_request_target` or `workflow_run` publisher is added, and no real
comment is posted. The fixed marker prepares a future controlled publisher.

Any future publisher must treat PR artifacts as untrusted: verify run/repository/
PR association and origin, exact filename, bounded download/file size, version,
keys, primitive types, enums and ranges. Use trusted publisher code with no PR
checkout/execution, render Markdown itself from validated JSON, and only update
the appropriately owned comment. Never post artifact Markdown verbatim. Schema
validation alone does not prove reported gate truth. That publication design and
Phase 3.5 integration/evidence work are not implemented here.

## Validation evidence

The Phase 3.4 tests cover all requested behavior categories through individual
tests and parameterized cases: every policy state, risk/review preservation,
private report consistency, missing evidence, injection/leakage, bounded outputs,
schema rejection, determinism, CLI failures, no-overwrite behavior, and offline
workflow permission/artifact regressions. Full regression results are recorded in
the task report and local ignored evidence. Live GitHub execution/publication,
AWS authentication/planning and live AI validation are NOT RUN.

Local validation on 2026-10-30 passed with the existing toolchain:

| Check | Result |
|---|---|
| Python | 184 PASS: original 130 plus 54 new tests; zero skips |
| Terraform 1.9.8 / AWS provider 6.65.0 | Formatting, backend-free init and validation PASS for both roots |
| TFLint 0.59.1 / AWS ruleset 0.40.0 | PASS |
| Checkov 3.2.471 | 30 passed, 0 failed, 6 skipped, 0 parsing errors |
| Exception contract | PASS: expected 6, observed 6, missing 0, unexpected 0 |
| OPA 1.0.1 / Conftest 0.60.0 | 35 tests / six fixtures PASS |
| Destructive-command guard / integrated offline runner | PASS |
| Phase 3.1, 3.2 and 3.3 reproduction | Byte-identical to the previous private baseline |
| Four JSON Schemas / Phase 3.4 repeated JSON and Markdown | PASS / byte-identical |
| Workflow security and privacy regression tests | PASS |

Local init used an existing filesystem provider mirror with no direct download
method and checkpoint requests disabled. No AWS, GitHub or AI API was contacted.
No package installation was needed. The baseline JSON is 468 bytes and Markdown
820 bytes. It retains 13/LOW, review required, six approved exceptions, zero failed
findings and offline advice covering six findings. Current Checkov, exception and
policy-test records show PASS; real-plan policy is UNKNOWN.

Ignored runtime artifacts are `reports/private/phase34/{normalized,risk,advisory}.json`,
private `advisory.md`, and `reports/sanitized/pr-summary{,-repeat}.{json,md}`.
Only the exact non-repeat sanitized filenames are selected by the CI artifact
step; none of these runtime artifacts belong in the local implementation commit.
