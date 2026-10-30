# Phase 3.2: deterministic risk prioritization

**Risk scoring does not override policy enforcement.**

The standard-library engine consumes an existing Phase 3.1 normalized report,
validates it and writes a separate private risk report. Checkov, OPA/Conftest,
Terraform validation, exception verification and the destructive-command guard
remain authoritative. A zero score, an empty report, an approved exception or a
successful scoring command cannot approve a failed gate. No scans, subprocesses,
network requests, AWS credentials, cloud-context discovery or AI are used by the
engine. No Phase 3.1 producer, policy, exception contract or CI workflow changed.

## Integration and input

```text
existing tool JSON -> Phase 3.1 normalized findings -> Phase 3.2 risk report
existing deterministic security gates ----------------> enforcement unchanged
```

Implementation is in `scripts/cloudguard/risk.py`, with the thin standalone
`scripts/score-risk.py` CLI. Existing Python discovery includes the new tests.
The input is the complete normalized report (`schema_version: "1.0"`), not raw
Checkov/Conftest output, a Terraform plan or a Phase 2 sanitized summary. Required
fields, types, sources, severity values, inclusive line ranges and summary counts
are checked before scoring. Optional source fields remain null. Arbitrary JSON
metadata is retained privately. Duplicate object keys, nonfinite numbers,
inconsistent summaries and unsupported schema/model versions are rejected.

Phase 3.1 emits only `failed`, `warning`, `skipped`. This consumer additionally
handles exact `passed` and any other nonempty status string defensively, without
altering the Phase 3.1 schema or producer. Such inputs are an explicit consumer
extension outside the producer's current status enum. Their legacy normalized
summary still contains exactly the Phase 3.1 keys: known status counts must match
their records, and total/severity counts include all records. The risk summary
separately counts passes and unknown statuses. Unknown severity must be the
explicit `UNKNOWN` enum; an arbitrary severity label is malformed normalized
input, not a guessed severity. All original finding fields are copied unchanged.

## Model 1.0

The complete small model is in [`risk-model.json`](../security/risk-model.json).
These are explicit engineering prioritization choices, not calibrated breach
probabilities, CVSS scores, measured loss or claims of cloud exposure. They were
chosen to distinguish source severity, unresolved findings and documented skips,
while making unknowns visible for review. They are not fitted to a target baseline
score. Algorithm version and a SHA-256 of canonical model configuration are stored
in each output. Different reviewed weights within algorithm 1.0 have different
configuration hashes. Record the model file with any experiment.

| Phase 3.1 severity | Base priority |
|---|---:|
| INFO | 10 |
| LOW | 25 |
| MEDIUM | 50 |
| HIGH | 75 |
| CRITICAL | 95 |
| UNKNOWN | 50, explicitly provisional |

UNKNOWN retains its source label and `risk.severity_known: false`. Its base of
50 schedules manual review; it does not assert MEDIUM source severity. Unknowns
on active findings, including approved skips, set `requires_review: true`.
Passes can retain unknown severity without requiring active-finding review.
The review flag highlights uncertainty or inconsistent/unapproved status; it is
not an action-permission flag. Known-severity failures remain unresolved failures
regardless of that flag and still require the existing security-gate response.

Only these **exact source/control pairs** add priority:

| Source | Control IDs | Adjustment / concern |
|---|---|---|
| conftest | SSH, S3_PUBLIC | +10, public-exposure control concern |
| conftest | IAM | +10, IAM policy concern |
| conftest | S3_ENCRYPTION | +5, encryption control concern |
| checkov | CKV_AWS_24, CKV_AWS_25, CKV_AWS_277 | +10, unrestricted-ingress control concern |

These IDs exist in the current policy messages/Checkov checks. All other pairs
are neutral (+0), including logging/tagging controls without a reviewed adjustment.
Resource types, names, tags, source messages, keywords and metadata do not affect
scoring. A concern associated with a control is not proof that an actual cloud
resource is Internet-accessible or exploitable. No wildcard or keyword matching
is used; the same control string from a different source need not match.

## Exact algorithm and status handling

For each finding:

1. Read its base severity weight and exact source/control adjustment.
2. `bounded_base = min(100, max(0, base + adjustment))`.
3. Select the status class and its integer multiplier below.
4. Compute `scaled = (bounded_base * numerator + denominator - 1) // denominator`.
   This is exact ceiling division; no floating-point rounding is used.
5. For unknown status only, `score = max(scaled, 50)`; otherwise `score = scaled`.
6. Assign the category from the explicit thresholds below.

| Source status / exception flag | Status class | Multiplier | Treatment |
|---|---|---:|---|
| failed, either flag | failed | 1 | Unresolved; never discounted by exception flag |
| warning, either flag | warning | 1/2 | Warning remains distinct from failure |
| skipped, true | approved_exception | 1/4 | Visible accepted skip; never a pass |
| skipped, false | unapproved_skip | 1 | No approval inferred; manual review required |
| passed, either flag | passed | 0 | Zero priority; contradictory exception flag remains visible |
| Any other nonempty status | unknown | 1, minimum 50 | Preserve the status; require manual review |

The engine uses Phase 3.1's `exception` annotation only when status is `skipped`.
It does not expand/reverify the six-pair contract or authenticate a report. A true
flag on any other status is an `exception_conflict`, never an exception discount;
it also requires review. An unapproved skip cannot become approved. Unknowns and
conflicts remain represented regardless of score. The original status and flag
are preserved in every output. Existing gate results must be consulted separately.

Five ordered factors expose the base, adjustment, bounded base, status scaling
and final floor result, including fixed reasons and calculated values. Model
validation requires full priority for failed/unapproved/unknown classes, zero
for passed, and nonzero discounts for warnings/approved exceptions. Thresholds
must increase strictly; duplicate control mappings are rejected.

| Score | Risk priority category |
|---|---|
| 0 | NONE |
| 1-29 | LOW |
| 30-59 | MEDIUM |
| 60-84 | HIGH |
| 85-100 | CRITICAL |

## Aggregation and output

`overall.score` is the **maximum per-finding score**, or 0 for no findings.
`overall.category` uses the same thresholds. No average or count weighting can
hide one unresolved critical finding behind many low findings. Overall review
is true if any finding requires review. Duplicate findings remain represented;
their counts increase but they do not inflate the maximum score.

[`risk-report.schema.json`](../security/risk-report.schema.json) defines the
versioned output. It embeds the normalized identity fields plus `risk`, including
score/category, status class, source-severity knowledge, exception applicability,
conflict flag, review flag and calculation factors. Summary counts include all
categories, failed/warning/passed findings, approved exceptions, unapproved skips,
unknown statuses/severities, conflicts and review requirements. Category counts
and status-class counts each sum to total. These are prioritization counts, not
scan pass totals or unique vulnerability counts.

Every report has `informational_only: true` and `gate_decision: "NOT_EVALUATED"`.
The schema rejects a `PASS` gate claim. Risk scoring never reads or rewrites gate
evidence. CLI success means a report was generated, even with CRITICAL findings.
Reports sort findings, sources and JSON keys, retain duplicates, use LF newlines
and ASCII JSON escapes, and contain no timestamp. Reordered findings and model
mapping entries produce identical bytes. Inputs/model objects are not mutated.

## CLI, examples and privacy

```sh
python scripts/score-risk.py --help
python scripts/score-risk.py \
  --input reports/private/phase3/normalized-findings.json \
  --output reports/private/phase3/risk-report.json
```

The output above is also the default. Optional `--model PATH` selects a reviewed
local algorithm-1.0 configuration. Use a new output filename for each run.
Existing files, including input/model files, are never overwritten. All input
validation and serialization precede exclusive file creation. A write failure
removes only a partial file created by the current invocation. Exit 0 means
scoring completed; invalid input/model, I/O errors and existing output return 2.
`--help` returns 0. Public diagnostics never echo source values, messages or paths;
stdout contains only counts and overall priority. No model/CLI option changes
security-gate behavior.

For example, a neutral HIGH failed finding scores 75/HIGH. The same source
severity on an approved skip scores `ceil(75/4) = 19/LOW`, while its status remains
`skipped` and its exception flag remains true. An UNKNOWN Conftest SSH failure
scores `50 + 10 = 60/HIGH`, retaining UNKNOWN source severity and requiring review.
The combined Phase 3.1 synthetic example produces three findings and overall
75/HIGH, with two failures and one approved skip.

The six-skip Checkov baseline has UNKNOWN severity for each record and no mapped
adjustment. Each scores `ceil(50/4) = 13/LOW`, so overall is **13/LOW** with
`requires_review: true`, six approved exceptions, six unknown severities, six
review requirements, zero failures and zero passes. LOW is a prioritization
result, not a claim that the exception risk is known to be low or that AWS passed
security checks. The model was not changed to lower this baseline result.

Detailed reports retain private identifiers, file paths, messages and metadata;
they are **not sanitized for publication or external AI services**. They stay in
ignored `reports/private/phase3/` and are not added to public CI artifact lists.
POSIX files use mode 0600; Windows uses inherited ACLs. Protect the workspace.
No dependency was added for runtime scoring. JSON Schema tests use `jsonschema`
already supplied by Checkov; without that optional local toolchain those tests
explicitly skip. Full validation must use the existing toolchain to run them.

## Limits and Phase 3.3 handoff

The engine does not deduplicate cross-tool findings, discover cloud context,
estimate exploitation probability, infer missing severity, authenticate inputs
or prove exception approval. A small mapping covers current known concerns only.
Scores depend on the recorded configuration and the completeness/truth of input.
An empty report proves only that it contained no findings, not that scans ran.

The Phase 3.3 advisory consumer uses these scores and factors while retaining
unknowns and exception status. Phase 3.4 reports sanitized aggregates; Phase 3.5
integrates the chain. Neither priority nor CLI exit 0 means approval. No live
LLM/API provider or automated remediation is implemented. See
[Phase 3 integration](phase3-integration.md) for the completed offline pipeline.

## Local validation: 2026-10-29

| Check | Result |
|---|---|
| Python unit tests | PASS: 87, including all previous 53 and 34 new risk tests; no skips |
| Terraform workload and bootstrap formatting/init/validate | PASS with Terraform 1.9.8 and locked AWS provider 6.65.0 |
| TFLint 0.59.1 with AWS ruleset 0.40.0 | PASS |
| Checkov 3.2.471 | 30 passed, 0 failed, 6 skipped, 0 parsing errors |
| Six-exception contract | PASS: expected 6, observed 6, none missing/unexpected |
| OPA 1.0.1 | PASS: 35 tests |
| Conftest 0.60.0 | PASS: all six fixtures |
| Destructive-command guard and integrated offline runner/evidence | PASS |
| Fresh Phase 3.1 generation and normalized JSON Schema | PASS: six approved skips, zero failures |
| Risk generation and risk JSON Schema | PASS for baseline, repeated baseline and synthetic example |
| Repeated baseline serialization | Byte-for-byte identical |
| Baseline risk | 13/LOW; six unknown severities and review requirements, no gate decision |
| Hosted CI, AWS authentication and real AWS plan | NOT RUN for Phase 3.2 |

The existing `.tools/phase31-venv` Python 3.12 toolchain and Checkov executable
launcher were reused. No install or external API was required for this phase.
Initialization used a temporary ignored `TF_CLI_CONFIG_FILE` with only a
`filesystem_mirror` pointing to the already installed provider packages, no
`direct` provider installation method, and checkpoint checks disabled. The
established `scripts/run-offline.py` command and security configuration were not
modified. Phase 1/2 and Phase 3.1 security results did not regress.

Generated local artifacts (ignored and not uploaded):

- `reports/private/phase3/normalized-findings-phase32.json`
- `reports/private/phase3/risk-report.json`
- `reports/private/phase3/risk-report-repeat.json`
- `reports/private/phase3/risk-example.json`
