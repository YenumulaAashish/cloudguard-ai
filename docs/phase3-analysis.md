# Phase 3.3: advisory security explanation and remediation

**Deterministic tools decide. AI explains.**

**AI-generated remediation is advisory and does not override policy enforcement or risk scoring.**

This optional enrichment layer reads existing normalized findings and a matching
risk report. It does not change security gates, scores, categories, review flags,
finding status, exception state or existing reports. No Terraform code is edited
or executed, no cloud access is provided, and nothing is sent to a network.
The deterministic pipeline works unchanged without AI, keys or credentials.

## Architecture and trust boundary

```text
Phase 3.1 normalized report + Phase 3.2 risk report + reviewed local risk model
   -> validate complete deterministic agreement
   -> minimize provider request
   -> offline templates OR explicitly injected provider
   -> validate every advice entry and identity
   -> attach advice to unchanged deterministic context
   -> private remediation JSON and optional Markdown
```

`scripts/cloudguard/analysis.py` owns consistency, data minimization, response
validation and report construction. `scripts/cloudguard/advice.py` owns the
provider protocol, explicit system instructions and offline templates. The thin
`scripts/analyze-security.py` CLI performs only local JSON/model reads and new
report writes. Existing automatic unittest discovery covers the new tests; no
workflow permissions, uploads, gate code or earlier Phase 3 producer changed.

### Consistency and deterministic authority

The analyzer reuses Phase 3.2 input validation and pure risk computation. It
recomputes the expected report with the selected local model and requires typed
canonical JSON equality with the supplied risk report. All normalized identity
fields, messages, paths, metadata, duplicate multiplicities, source sets, risk
factors, scores, model hash, categories, review flags, counts and gate context
must agree. Reordered source/finding arrays are accepted. No mismatch is repaired
or silently combined. Unsupported versions, malformed data and missing required
identity keys fail. Nullable identities remain null rather than being invented.

Every output finding receives a local `finding-000001` style identifier, assigned
in canonical risk order. Duplicate records retain separate IDs and are not
suppressed. Original source/control/resource/status/severity/exception fields and
the entire deterministic per-finding `risk` object are copied by the core, never
accepted from provider output. Paths, original messages and metadata are omitted
from the remediation report because they are unnecessary for generic advice.
They remain unchanged in the original private inputs.

The top-level `deterministic_context` copies original model versions/hash, overall
risk, review flag, summary and `gate_decision: "NOT_EVALUATED"`. It is not a newly
inferred gate outcome. `informational_only` and `terraform_examples_advisory` are
always true. Input/model objects and existing gate evidence are never mutated.

## Provider interface and AI availability

`AnalyzerProvider` defines a small local protocol:

```python
name: str
analyze(request: dict) -> dict
```

The request contains separate `system_instructions`, `untrusted_data`, and a
`response_contract`. This is an internal interface, not a provider HTTP API.
The core accepts an explicitly injected provider only with `mode="ai"`; tests
use an obvious fake that makes no API/LLM calls. A provider receives deep copies,
not references to core inputs. For an empty report the provider is not called.

No live provider adapter, SDK, endpoint, model name, API credential handling or
network implementation is included. This is deliberate: a real integration
requires an explicitly selected provider, verified API contract and privacy
review. A future adapter can implement this protocol in a separate transport
module and parse its response into the required dictionary; the core need not
change. Adapter code itself must be trusted; this in-process interface is not a
sandbox for malicious Python code.

CLI `--mode ai` fails with exit 2 and a clear unconfigured-provider diagnostic.
It never silently falls back to offline. Injected-provider tests verify the AI
boundary; they are not evidence of live AI accuracy or a configured provider.

## Data minimization and prompt-injection defense

Providers receive only opaque finding IDs, recognized control IDs, source,
bounded status/severity enums, exception annotations and verified numeric risk
context/factors. Actual resource names become `resource-000001` aliases. Unknown
control IDs become null, and unfamiliar statuses become `unknown` in the request
only. Raw finding messages, paths, metadata, repository contents, Terraform files,
state, plans and credentials are never included. Unknown controls get neutral
generic guidance; no finding keywords are interpreted as infrastructure context.
The small explanation catalog describes existing known controls, not new rules.

System instructions explicitly require authoritative deterministic results,
unchanged scores/categories/review flags/status, no exception approval, no
gate-pass claims, no invented context, no secrets, advisory remediation and the
exact structured response. Data is labelled untrusted and never concatenated
into those instructions. Raw injection text in messages/resources/control IDs is
not forwarded. Structural immutability does not depend on the provider obeying
instructions: it cannot return replacements for deterministic fields.

Provider responses must contain exactly `schema_version` and `findings`, with
exactly one entry for every supplied ID. Each entry has only `finding_id` and
`analysis`. Unknown/duplicate/missing IDs, extra authority fields, invalid values,
empty or oversized text and invalid confidence/steps are rejected. Obvious
credential/private-key patterns, deployment commands, direct gate-pass claims
and instructions to change deterministic values or approve exceptions
in advice are rejected. Exceptions and invalid responses fail without printing
raw output, exception details or source values. No partial provider result is
accepted and no findings are dropped to make a report succeed.

These conservative text checks are not a proof that all natural-language advice
is correct, safe or secret-free. Provider prose remains untrusted and requires
human review. No live transport is present, so there is no external disclosure
path in this implementation. Any future external adapter needs a separate review.

## Honest offline mode and remediation safety

Offline mode defaults to `analysis_mode: "offline"`, provider
`offline-templates-v1`. It uses only known structured control/status/severity
fields to produce generic, deterministic explanations and verification guidance.
Approved skips explicitly remain skips and advise reviewing the existing
rationale/review trigger rather than approving a new exception. UNKNOWN severity
remains visible. Context is not fabricated for unknown controls or resources.

Offline confidence is always LOW and applies to advice only. Terraform examples
are null because complete configuration/context was not supplied. The analyzer
never fabricates a deployable configuration. A future provider may suggest an
example, but it is labelled advisory, remains plain report text and is never
written into `.tf` files, executed, patched, staged or verified as a remediation.
No probability percentages or measured remediation success are claimed.

## Schema and private reporting

[`remediation-report.schema.json`](../security/remediation-report.schema.json)
defines report version 1.0 and its separate `$defs/provider_response` contract.
Advice has exactly these fields:

- `summary`, `why_it_matters`, `potential_impact`, `recommended_action`
- nullable `terraform_example`
- a nonempty `verification_steps` array
- `confidence`: LOW, MEDIUM or HIGH, for explanatory text only

The standard-library runtime validates the closed shape, types, limits and
deterministic binding before returning/writing a report. Tests additionally
validate generated offline/fake-provider reports and provider responses using
the existing Checkov toolchain's `jsonschema` dependency; no dependency was added.
Without that optional test dependency schema tests explicitly skip; full project
validation uses the established toolchain and runs them.

Reports stay under ignored `reports/private/phase3/` by default. They are not
added to public CI artifacts and are not sanitized publication material. Local
identity fields and provider prose may still contain private data. Protect the
workspace: POSIX files use 0600, Windows inherits ACLs. No raw messages or provider
payloads are printed or logged. CLI stdout reports only count and analysis mode.

Optional Markdown is rendered from JSON, which remains the source of truth.
Identity/context/advice are enclosed in inert text fences that cannot be closed
by content backticks; embedded newlines are JSON escaped. Provider Markdown/HTML
is not rendered as active links, scripts, instructions or executable code.

## CLI and failure behavior

```sh
python scripts/analyze-security.py --help
python scripts/analyze-security.py \
  --findings reports/private/phase3/normalized-findings-phase32.json \
  --risk reports/private/phase3/risk-report.json \
  --output reports/private/phase3/remediation-report.json \
  --markdown reports/private/phase3/remediation-report.md \
  --mode offline
```

Default JSON output is the path above. `--markdown` is optional. `--risk-model`
selects the model used to verify a nondefault Phase 3.2 report. Use fresh output
names on each run; source/model/existing files are never overwritten. JSON and
Markdown destinations must differ. All data is validated/serialized first; if
either exclusive write fails, only new files created by that invocation are
removed. Existing files are retained. Interrupted writes are not a multi-file
filesystem transaction; inspect partial files after a hard process termination.

Exit 0 means advisory reporting completed, even for failed/critical findings.
Exit 2 covers invalid/inconsistent input, provider failures, unavailable AI mode,
unsafe/malformed response and output errors. `--help` exits 0. There is no success
exit code that changes deterministic gates. Offline output is byte-deterministic
for the same inputs/model; reordered findings remain deterministic and no
timestamps are introduced. Live-provider prose determinism is not promised.

## Limitations and Phase 3.4 boundary

Generic offline advice is not evidence of AI reasoning or a validated fix. Input
agreement proves consistency with the selected model, not authenticity of scan
results, actual cloud context or exception authorization. Source data remains
untrusted. Explanation coverage is intentionally small. No real AI provider was
configured or verified; live AI behavior is NOT RUN.

Phase 3.4 provides sanitized PR reporting; Phase 3.5 integrates and verifies the
complete offline chain. Neither implements automated remediation verification,
patch application, source edits or deployment. Deterministic tools remain the
only source of security decisions. See [integration](phase3-integration.md).

## Local validation: 2026-10-29

| Check | Result |
|---|---|
| Complete Python suite | PASS: 130 tests, including all previous 87 and 43 new Phase 3.3 tests; no skips |
| Terraform 1.9.8 workload/bootstrap formatting, init and validate | PASS with locked AWS provider 6.65.0 |
| TFLint 0.59.1 with AWS ruleset 0.40.0 | PASS |
| Checkov 3.2.471 | 30 passed, 0 failed, 6 skipped, 0 parsing errors |
| Six-exception contract | PASS: expected 6, observed 6, no missing/unexpected pairs |
| OPA 1.0.1 | PASS: 35 tests |
| Conftest 0.60.0 | PASS: all six fixtures |
| Destructive-command guard and integrated offline runner/evidence | PASS |
| Fresh normalized/risk JSON Schemas | PASS |
| Phase 3.1/3.2 baseline reproduction | Byte-identical to the prior private baseline |
| Phase 3.3 offline JSON/Markdown and schema | PASS; repeated bytes identical |
| AI mode without a configured provider | Expected refusal with exit 2; no output or fallback |
| Live AI provider, hosted CI, AWS authentication and real AWS plan | NOT RUN |

Validation reused the installed Python 3.12 toolchain. Provider initialization
used the existing filesystem mirror via an ignored temporary CLI configuration;
no registry/API call or dependency installation was required. No Terraform,
policy, exception, risk-model or CI workflow change was made. Provider tests use
test doubles and require no keys, network, AWS or paid AI calls.

The current private baseline advisory report contains six entries, all explicitly
approved skips, zero failed findings and no inferred passes. Overall context stays
13/LOW with `requires_review: true`; each original risk object is unchanged.
Advice confidence is LOW, examples are null, and actions recommend reviewing
existing exception rationale/triggers and running established deterministic
checks. This is honest offline guidance, not a claim of live AI execution.

Generated artifacts (ignored and excluded from the local commit):

- `reports/private/phase3/normalized-findings-phase33-final.json`
- `reports/private/phase3/risk-report-phase33-final.json`
- `reports/private/phase3/remediation-final.json` and `.md`
- `reports/private/phase3/remediation-final-repeat.json` and `.md`
