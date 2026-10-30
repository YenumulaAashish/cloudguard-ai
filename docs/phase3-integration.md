# Phase 3 closure: integration, evidence and reproducibility

**Deterministic tools decide. AI explains. PR reporting informs.**

Phase 3.5 composes the existing implementation; it adds no detection, scoring,
AI or policy engine. Phase 4 is not implemented. Live AI and automatic PR comments
remain out of scope. This closure covers locally verified offline behavior, not
deployment readiness or successful hosted/AWS execution.

## Architecture and authority

```text
existing Checkov / Conftest JSON + current optional Phase 2 evidence
   -> 3.1 normalized findings (private)
   -> 3.2 deterministic risk (private)
   -> 3.3 offline advisory JSON / Markdown (private)
   -> 3.4 bounded PR JSON / Markdown (sanitized)
   -> 3.5 schema / integrity / byte reproduction / readback checks
   -> completion receipt (sanitized, published last)
```

Policy gates own PASS/FAIL/UNKNOWN. The existing risk engine owns priority
0..100, category and review state. Offline advisory templates only explain.
Reporting only presents validated aggregates. A successful run can truthfully
contain a failed policy or nonzero risk: report completion is not gate success.
Neither LOW priority nor zero failed findings establishes policy PASS.

The normalizer retains exceptions as annotations; an approved skip never becomes
a pass. Phase 3.2's model is unchanged. Phase 3.3 is always invoked in offline
mode, without a provider/key/network option. Phase 3.4 output still excludes all
source identifiers, paths, raw findings, plan values, metadata and advisory prose.

## Gaps closed

Previously, CI ran four separate commands. Individual CLIs prevented overwrites,
but a later failure could leave earlier output and there was no common completion
receipt or formal schema validation for every stage within one invocation.
The new small runner calls the existing functions directly. Existing standalone
CLIs remain supported with unchanged semantics.

Repeated input/consistency checks are deliberate trust-boundary checks, not new
decision logic. Phase 3.3 and 3.4 already perform complete identity/model checks;
these are reused rather than replaced. The integration additionally binds the
normalizer output to raw inputs, validates the final summary against the complete
chain and checks written bytes. Earlier documentation's speculative handoffs have
been corrected without changing historical validation results.

## CLI and dependencies

Use the established Python/Checkov toolchain (Python 3.12 in CI):

```sh
python scripts/run-phase3.py --help
python scripts/run-phase3.py \
  --checkov reports/private/checkov-raw.json \
  --current-evidence --mode offline
```

On Windows use a single line or PowerShell continuation syntax. `--checkov` and
`--conftest` accept repeatable existing raw JSON inputs. At least one is required.
The runner never executes a scanner, Terraform, cloud command or external API.
`--risk-model` selects the reviewed model used by existing scoring/validation.
Only offline mode is available; no live-provider fallback exists.

Default fresh output directories:

- `reports/private/phase35/`: normalized.json, risk.json, advisory.json, advisory.md.
- `reports/sanitized/phase35/`: pr-summary.json, pr-summary.md, phase3-evidence.json.

Use `--private-output reports/private/NAME` and
`--sanitized-output reports/sanitized/NAME` for a second run. Both must be new
directories strictly inside their respective resolved repository boundaries.
Existing empty directories also count as collisions. No force/overwrite option
exists. The existing ignore rules exclude every runtime artifact.

Formal validation uses `jsonschema` and `referencing`, already supplied by the
pinned Checkov toolchain. No dependency was added or installed. Unlike optional
standalone schema tests, the integrated runner requires these libraries and fails
closed if unavailable. It never auto-installs them. Schema retrieval is restricted
to local references; external-reference retrieval is explicitly denied.

Exit 0 means a complete reporting bundle was published. Exit 2 means parsing,
schema, integrity, dependency, provider or filesystem failure. Diagnostics never
print raw exception messages, private values or filesystem paths.

## Integrity and evidence

Every intermediate passes its existing formal JSON Schema. Full canonical
comparison binds normalized findings to raw scanner inputs; `consistent_risk`
binds risk to normalized inputs and the selected model; `validate_remediation`
binds advisory identities/context to risk; recomputing the existing summary
projection binds sanitized output to all upstream facts and the selected evidence.
Missing or unrelated intermediate reports are hard errors. Duplicate findings,
status, exception flags and uncertainty remain visible.

With `--current-evidence`, the existing Phase 3.4 adapter reuses Phase 2 run IDs
and source fingerprints and compares matching source findings. Missing/stale/
unrelated evidence remains UNKNOWN. Fixture policy-test PASS stays distinct from
real-plan policy UNKNOWN unless matching real-plan Conftest evidence exists.
The runner snapshots the existing evidence files in memory and checks they did
not change during generation/publication. Changing evidence is a hard integrity
error. No new input hashes, run IDs or timestamps are introduced.

Each invocation computes the full chain twice, compares every JSON/Markdown
payload, then validates file readback before completion. Reproduction includes
private advisory Markdown, sanitized Markdown and deterministic JSON serialization.
This costs extra CPU/memory and is intentional for reproducible experiments.
No claim is made about determinism of a future live AI provider.

The strict `phase3-evidence.schema.json` defines the completion receipt. It has
fixed keys/constants only: version, phase, informational flag, COMPLETE, offline
mode, four component-completion statuses and schema/consistency/reproduction
statuses. These PASS values describe checks actually completed in this invocation,
not policy gates or an assertion that the infrastructure is secure. Failed runs
produce no successful receipt. No untrusted text, identifiers or details appear.

Existing Phase 2 evidence remains the source of tool/provider versions, validation
results, exception verification, OPA/Conftest tests and destructive-command guard
results. The new receipt does not duplicate that evidence or fabricate a separate
security-boundary PASS. Python regression results and workflow tests establish
privacy/permission boundaries. Public reports and the receipt are each <=4096
UTF-8 bytes. Large inputs still consume memory proportional to input size.

## Output completion and failure cleanup

All computation, schema checks and reproduction occur in memory before publishing.
The runner exclusively reserves two new directories, writes the known filenames,
flushes/fsyncs files, reads them back and verifies consistency/bytes. It then writes
a temporary receipt and renames it to `phase3-evidence.json` as the final step.
No existing output is replaced. On ordinary exceptions, only files and directories
created by this invocation are removed; there is no recursive deletion.

This is a completion protocol, not an atomic transaction spanning two directories.
A hard process termination or failed cleanup can leave incomplete files. A bundle
without a valid completion receipt is incomplete and must not be consumed or
uploaded. The receipt is written only after successful readback. CI additionally
requires a successful runner step before upload. File/directory permissions rely
on local filesystem semantics (including inherited Windows ACLs); protect private
storage. A malicious concurrent process controlling the workspace is out of scope.

## CI, forks and publication

The read-only offline workflow replaces the four commands with `run-phase3.py`.
The reporting step still uses `always()` so a failed gate can be reported. The
original gate step remains authoritative and no failure masking is introduced.
The Phase 3 artifact upload now requires `steps.phase3.outcome == 'success'` and
lists exactly the three sanitized filenames under `reports/sanitized/phase35/`.
No directory wildcard, private report or traversal path is uploaded. Retention
remains three days. Phase 2 uploads remain unchanged.

Workflow permissions remain `contents: read`, checkout credential persistence is
disabled, and fork validation needs no secrets. The separate opt-in authenticated
plan workflow and its protected environment/fork exclusion are unchanged. No
write-capable PR token, new OIDC operation, privileged trigger or publisher exists.
Static workflow tests were adapted to the new single command and strengthened to
assert completion-gated uploads; none of the original tests were removed.

Actual hosted-runner execution, artifact-service behavior, PR UI rendering, OIDC,
AWS authentication, real AWS planning and live AI are **NOT RUN / REQUIRES HOSTED
VERIFICATION**. No workflow was intentionally triggered. Any future comment
publisher still needs trusted code, strict untrusted-artifact validation, trusted
rendering and no PR-code execution. Posting artifact Markdown verbatim is unsafe.

## Closure criteria and Phase 4 handoff

Phase 3 is complete when the previous baseline remains intact, all new integration
and failure-path tests pass, the live local baseline reproduces all previous
Phase 3 bytes, all schemas and privacy/workflow regressions pass, and the reviewed
implementation is locally committed. Local completion does not claim hosted or
AWS verification, validated automated remediations, research accuracy metrics or
live AI capability. Future Phase 4 work requires its own scope; none is included.

## Closure validation

The 2026-10-30 local validation passed all 218 Python tests (184 existing + 34 new),
Terraform formatting/init/validation for both roots, AWS TFLint, Checkov 30/0/6
with zero parsing errors, the exact six-exception contract, 35 OPA tests, six
Conftest fixtures, the destructive-command guard and the integrated offline runner.
Two complete Phase 3 runs reproduced all seven output files byte-for-byte; the
six existing-stage outputs also match the previous Phase 3.4 baseline. All five
schemas passed. Workflow/fork/privacy/authority/failure regressions passed.
See [final evidence](evidence.md#final-phase-3-local-validation-2026-10-30-asiacalcutta)
for versions, execution limitations and the exact sanitized baseline.
