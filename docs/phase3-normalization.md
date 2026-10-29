# Phase 3.1: deterministic finding normalization

The normalizer reads existing tool JSON and produces a common reporting format
using only the Python standard library. It does not run scans, authenticate to
AWS, change findings, approve infrastructure or replace deterministic gates.
Phase 1/2 commands, policies, exceptions and artifact upload lists are unchanged.

## Supported sources

| Input | Accepted format | Normalized records |
|---|---|---|
| Checkov 3.2.471 | Full `checkov -d terraform --config-file .checkov.yml --output json` report; a single object or a multi-framework array with exactly one Terraform report | Failed checks and skipped checks; passed checks are omitted |
| Conftest 0.60.0 | `conftest test INPUT --policy policies/terraform --output json`, used by fixtures and real-plan evaluation | Failures and warnings; successes are omitted |

Checkov must include all three result groups and matching summary counts. Quiet,
truncated, inconsistent and parsing-error reports are rejected. Source status is
checked against its result group. The Phase 2 sanitized `reports/phase2/checkov.json`
is intentionally not accepted: messages and locations have already been removed.

OPA's existing `opa test policies --format json` output describes **unit tests**.
It is not normalized as infrastructure findings. Conftest runs the same Rego
policies against input data and provides actual violation messages. Do not feed
`reports/phase2/policy-tests.json` or `plan-policy.json` summaries to this adapter.
Nonempty Conftest errors or exceptions are rejected; this repository's Rego
policies define no exemptions. An empty result array is rejected, whereas an
ordinary successful input/namespace result produces zero findings.

Terraform plan JSON contains proposed resource values/actions, not security
findings. No standalone Terraform detector is implemented. Existing Conftest
results against a real plan can be normalized without loading the plan itself.
Future sources can add an explicit adapter to `build_report`; there is no
speculative Terraform rule or generic arbitrary JSON importer.

## Schema 1.0

The machine-readable contract is
[`security/normalized-findings.schema.json`](../security/normalized-findings.schema.json).
Each report has `schema_version`, `generated_by`, sorted `sources`, `summary`
and a `findings` array. Each finding contains:

| Field | Meaning |
|---|---|
| `schema_version` | String `1.0` |
| `source` | `checkov` or `conftest` |
| `control_id` | Checkov ID, existing Rego message family, policy query fallback, or null |
| `resource` | Source resource identifier, or null |
| `status` | `failed`, `warning` or `skipped`; never turns a skip into a failure |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` or `UNKNOWN` |
| `message` | Checkov check name / Conftest message, or null |
| `file` | Checkov source-relative path as supplied, or null |
| `line`, `line_end` | Inclusive source line range, or null |
| `exception` | True only for a Checkov skip whose exact ID/resource pair is in the existing six-pair `REVIEWED` contract |
| `metadata` | Explicit provenance fields; empty for Checkov; Conftest input filename, namespace and query |

Exception membership is a reporting annotation, **not evidence that the contract
verifier passed**, and never exempts a failed check. Unapproved skips remain
`skipped` with `exception: false`; the existing exception gate still rejects them.
There are no Conftest exceptions. Resource addresses are never remapped.

Current Rego control IDs come from existing prefixes `SSH`, `S3_PUBLIC`,
`S3_ENCRYPTION`, `TAGS`, `IAM`, `UNKNOWN`, `INPUT`. Resource extraction recognizes
only the current documented message templates and Terraform address syntax,
including indexed module/resource addresses. Unrecognized message shapes retain
their text but get a null resource. Unknown prefixes use the actual policy query
when available, otherwise a null control ID. Policy family IDs are coarser than
individual Rego rules; separate diagnostics are preserved even for the same ID
and resource. No unique rule ID is invented.

Conftest's `filename` identifies the tested JSON file, not its Terraform source.
It appears only as `metadata.input_file`; `file`, `line`, `line_end` stay null.
Missing optional data is null or an empty metadata object.

Only recognized Checkov severity strings are used (case/whitespace normalized).
Missing/unknown labels become `UNKNOWN`. The current Rego/Conftest output supplies
no severity, so its severity is always `UNKNOWN`. There is no LLM or guessed
severity mapping.

`summary.total` counts emitted records, including skips/warnings. Severity counts
sum to total; status counts sum to total. These are reporting counts, not source
pass counts, compliance scores, deduplicated vulnerabilities or coverage metrics.
Inputs, result rows and records can be reordered without changing output bytes.
Exact duplicate diagnostics are preserved; repeat an input and its findings are
counted again. Serialization sorts keys and findings, uses UTF-8 with ASCII JSON
escapes and LF newlines, and has no timestamp or machine-specific generated path.
Source paths/messages are retained as supplied; different source values produce
different output. Missing source inputs are never represented as successful scans.

## Commands

After running the existing offline source scan:

```sh
python scripts/normalize-findings.py --checkov reports/private/checkov-raw.json
```

Default output: `reports/private/phase3/normalized-findings.json`, following the
existing private-evidence boundary. Choose a new `--output` path for each run;
existing files (including input files) are never overwritten. All inputs are
validated and serialized before exclusive output creation. A write failure
removes only the partial file created by that invocation.

The committed fixtures illustrate both formats and can run without tool installs:

```sh
python scripts/normalize-findings.py --help
python scripts/normalize-findings.py \
  --checkov tests/fixtures/normalization/checkov.json \
  --conftest tests/fixtures/normalization/conftest.json \
  --output reports/private/phase3/example.json
python -m unittest discover -s tests/unit -v
```

For an already-created real plan, the existing plan policy command captures raw
Conftest results at `reports/private/plan-policy-raw.json`; pass that file with
`--conftest`. This command does not create a plan or require credentials. Both
input options may be repeated. Input JSON may contain a UTF-8 BOM. Duplicate
object keys, nonstandard JSON numbers and malformed/unsupported structures fail
with exit **2**, as do unreadable inputs and unavailable/existing output paths.
Exit **0** means normalization completed, even when the report contains failures.
It never means infrastructure passed security checks. CLI stdout prints only
the number of normalized findings, not finding text. Errors do not echo input
values. `--help` exits 0; usage errors exit 2.

Example finding from the synthetic Checkov fixture:

```json
{
  "schema_version": "1.0",
  "source": "checkov",
  "control_id": "CKV_AWS_18",
  "resource": "aws_s3_bucket.example",
  "status": "failed",
  "severity": "HIGH",
  "message": "Ensure the S3 bucket has access logging enabled",
  "file": "/main.tf",
  "line": 10,
  "line_end": 16,
  "exception": false,
  "metadata": {}
}
```

The combined fixture example emits three records: two failures and one approved
skip, with one HIGH severity and two UNKNOWN severities. The actual accepted
Checkov baseline emits six skips and zero failures, not 30 passing findings.

## Security boundary, validation and Phase 3.2 handoff

This output is **private**, not an addition to sanitized Phase 2 CI artifacts.
Source messages and paths may contain sensitive infrastructure details; the
normalizer cannot reliably redact arbitrary free text. Checkov code blocks,
suppression comments, tags, evaluations, absolute-path alternatives and arbitrary
source metadata are not copied. No Terraform values/state/plan JSON is loaded.
Do not publish or send this file to an external service without a separately
reviewed sanitization step. On POSIX the output is created with mode 0600; Windows
uses inherited ACLs. Use an appropriately protected workspace.

Existing CI already discovers `tests/unit/test_findings.py`. Tests exercise
fixtures, six-pair membership, failure/skip distinction, nullable fields, severity,
malformed inputs, empty findings, ordering, duplicates, summary counts, private
extra-field exclusion, non-overwriting CLI behavior and real local Conftest
output when available. No workflow permission or upload change is needed.

Phase 3.2 can read schema 1.0, validate required fields, retain unknowns and
provenance, and distinguish skipped/warning records from failures. It must not
interpret successful normalization as gate approval or overwrite original gate
results. Any AI explanation or remediation consumer requires a separate design
and privacy review. No Phase 3.2 functionality is implemented here.

## Local verification: 2026-10-29

| Check | Result |
|---|---|
| Python unit tests | PASS: 53, comprising the original 30 and 23 normalizer tests |
| Terraform formatting, backend-free read-only init and validation | PASS for workload and bootstrap roots |
| TFLint including AWS ruleset | PASS |
| Checkov 3.2.471 | PASS: 30 passed, 0 failed, 6 skipped, 0 parsing errors |
| Exception contract | PASS: expected 6, observed 6, no missing/unexpected pairs |
| OPA 1.0.1 | PASS: 35 tests |
| Conftest 0.60.0 | PASS: all six existing fixtures |
| CI destructive-command guard | PASS |
| Existing integrated offline runner and evidence | PASS |
| JSON Schema validation | PASS for the combined example and fresh Checkov report |
| Fresh source-scan normalization | PASS: six approved skips, no failures |
| Hosted CI, AWS authentication and real AWS plan | NOT RUN for Phase 3.1 |

The Terraform/provider/TFLint versions remained 1.9.8 / 6.65.0 / 0.59.1, with
AWS ruleset 0.40.0. No Phase 2 security result regressed. The old ignored virtual
environment referred to a removed Python 3.10 installation. Validation used an
isolated ignored Python 3.12 environment at `.tools/phase31-venv`, with pinned
Checkov 3.2.471 and an executable launcher in `.tools/phase31-bin` selected through
PATH. No dependency or launcher code was added to tracked files. JSON Schema was
checked using Checkov's existing transitive `jsonschema` package; the normalizer
and its tests do not require it.

The successful local PowerShell regression command was:

```powershell
$env:PATH = "$PWD/.tools/phase31-bin;$env:PATH"
$env:TFLINT_AWS = '1'
$env:TFLINT_PLUGIN_DIR = "$PWD/.tools/tflint-plugins"
$env:CHECKPOINT_DISABLE = '1'
$env:AWS_EC2_METADATA_DISABLED = 'true'
.tools/phase31-venv/Scripts/python.exe scripts/run-offline.py
```
