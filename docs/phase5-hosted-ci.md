# Phase 5.1: hosted CI preparation and local security verification

**Deterministic tools decide. AI explains. PR reporting informs.**

**Local workflow validation does not prove successful execution on a GitHub-hosted runner.**

This phase prepares the credential-free validation path. No workflow is triggered
and nothing is pushed. Actual hosted execution remains NOT RUN / PENDING USER
PUSH. AWS OIDC and real plans belong to 5.2, Phase 4 PR publication to 5.3,
release hardening to 5.4 and final release/demo to 5.5; none is started here.

## Workflow architecture and changes

Inspected terraform-ci.yml, terraform-plan.yml and the shared setup-tools composite
action. Existing offline CI already ran backend-free Terraform formatting/init/
validation for workload/bootstrap, AWS TFLint, full Python discovery, source
Checkov, exact exceptions, OPA/Conftest tests, sanitized evidence and Phase 3.
Unit discovery already included all Phase 4 domains, but there was no explicit
whole-Phase-4 hosted fixture command or reviewed CI-contract verifier.

Only terraform-ci.yml changes. The runner family is explicitly ubuntu-24.04,
run steps explicitly use bash, and checkpoint/metadata lookup are disabled. Two
small steps are added: verify-hosted-ci.py and verify-phase4-fixtures.py. Existing
gates, Phase 3 always-run reporting, failure propagation and exact artifact paths
remain intact. Timeout remains 20 minutes and cancellation groups remain scoped
to github.ref, used as workflow metadata rather than shell text.

Triggers remain pull_request, push to main and workflow_dispatch. Contents is
read-only, no job permission override exists, and checkout persist-credentials is
false. Offline steps do not reference secrets, AWS authentication, OIDC, AI keys,
write tokens, PR comments or untrusted PR text. There is no pull_request_target,
workflow_run publisher or new write permission. Fork execution may still require
GitHub's contributor approval; no bypass or privileged execution path is added.

The separate authenticated-plan workflow is unchanged and its reviewed contract
is frozen by local verification. It retains the repository check, explicit
AWS_PLAN_ENABLED/role variables, same-repository PR or main condition, protected
aws-plan environment and job-scoped id-token write. The offline workflow has no
id-token grant and cannot inherit the separate job's credentials. No AWS role,
provider, GitHub variable or environment is configured here. Real authentication
and IAM permissions remain unverified for 5.2.

## Local reviewed contract

verify-hosted-ci.py reads workflow/action YAML as data with existing PyYAML.
Duplicate keys, custom tags, anchors and aliases are rejected. Files are bounded
to 128 KiB and token count to 32768. Malformed/missing files fail closed with fixed
codes, never raw source, credentials or absolute paths in diagnostics.

The verifier compares canonical parsed YAML to reviewed SHA-256 allowlist entries
for offline CI, the protected AWS workflow and setup-tools. Comments/formatting
may change without changing semantic content; steps, commands, permissions,
triggers, action references, env, artifacts and arbitrary extra keys cannot.
It additionally fingerprints reviewed gate/full-test runner code, Phase 4 smoke
code, Checkov/TFLint configuration and both provider locks, normalizing LF. The
existing no-deployment/suppression guard must also pass.

This is deliberately a narrow reviewed contract, not a generic YAML linter or a
malicious-code sandbox. Legitimate changes require human review and an intentional
allowlist update in ci_security.py; there is no automatic refresh command. Negative
controls must still pass. Hashes identify reviewed local content, not trusted
remote action code, authentic PRs or successful hosted execution. PR code could
modify the verifier/tests too: read-only GitHub permissions and repository review
policy remain essential. No branch protection settings are changed or claimed.
The verifier runs after tool setup because PyYAML comes from Checkov; it cannot
retroactively sandbox installer actions. Its result always says LOCAL_STATIC_ONLY
and hosted_execution=NOT_RUN, even on PASS.

## Toolchain and supply chain

| Tool | Configured baseline |
|---|---|
| Terraform | 1.9.8, wrapper disabled |
| AWS provider | 6.65.0, committed lock hashes in both roots |
| TFLint / AWS plugin | 0.59.1 / 0.40.0 |
| OPA | 1.0.1 |
| Conftest | 0.60.0 |
| Checkov | 3.2.471 |
| Python | 3.12 minor in hosted setup; local validation uses 3.12.0 |

| Action | Retained release tag |
|---|---|
| actions/checkout | v7.0.1 |
| actions/upload-artifact | v7.0.1 |
| actions/setup-python | v7.0.0 |
| hashicorp/setup-terraform | v4.0.1 |
| terraform-linters/setup-tflint | v6.3.1 |
| open-policy-agent/setup-opa | v2.4.0 |
| aws-actions/configure-aws-credentials | v6.3.0, protected plan only |

These retain the previously documented tag policy/releases in setup.md; no guessed
SHA or blind upgrade is introduced. Exact references are checked locally. Release
tags remain mutable and are not equivalent to immutable commit-SHA pins. Remote
action availability/code was not re-verified in this phase. SHA pin review remains
an explicit future hardening decision, not a claim of complete supply-chain trust.

The composite action installs from the existing official action/project namespaces,
PyPI Checkov and GitHub Conftest releases. Conftest verifies the archive against
the downloaded release checksum list. That list shares the release trust boundary;
it is not independent source authentication. Terraform init uses backend=false,
readonly provider locks and recorded Linux/Windows checksums. TFLint AWS plugin
version/source remain fixed. There is no curl/wget-to-shell installation pattern.

No repository-defined dependency/executable cache is introduced. Action/tool-cache
and runner-image behavior remain part of GitHub's infrastructure boundary. Ubuntu
image updates, Python patch selection and transitive Python packages still float;
this is recorded, not described as fully hermetic reproduction. No dependencies
were added or installed locally. Local validation uses existing jsonschema,
referencing and PyYAML from the established Checkov environment. Hosted downloads,
TLS, registries, action runtimes and dependency resolution need hosted verification.

## Execution, artifacts and logs

run-offline.py remains the gate runner and discovers the entire Python suite.
No test subset replaces it. Existing no-deployment checks remain mandatory.
Terraform operations are fmt, backend-free init with readonly locks and validate;
no real plan, import, state mutation or deployment is added. Authenticated planning
is confined to the unchanged opt-in workflow, not this smoke path.

Phase 3 still runs its validated offline integration with current evidence.
The new Phase 4 smoke command reads only the existing synthetic connected fixture,
runs existing IAM/network/data/graph logic twice, compares canonical bytes and
publishes through the existing posture integrator. UNKNOWN context stays UNKNOWN.
Critical findings in a synthetic fixture demonstrate reporting semantics, not a
real AWS policy result. The unchanged version-1 Phase 4 completion receipt retains
its historical Phase 5 NOT_STARTED marker for byte compatibility; it is not the
current repository roadmap. README defines the active Phase 5 status. This integration success is distinct from gate PASS.
Outputs go to fresh ignored reports/private/ci-phase4 and
reports/sanitized/ci-phase4 directories. They remain ephemeral/unpublished.
Local reruns need new --private-output-dir / --sanitized-output-dir paths.

No Phase 4 artifact is added. Existing Phase 3 upload requires successful completion
and names only its three sanitized files. Existing Phase 2 evidence uses its exact
named allowlist, including on failure. Retention stays three days. There are no
private/report directory globs, raw plans, graph/posture uploads or debug dumps.
All significant jobs are time-bounded (offline 20 minutes, protected plan 25).
No continue-on-error, soft-fail or failure-masking shell fallback is introduced.

Logs use fixed verifier/smoke diagnostics and existing sanitized gate summaries.
No environment/token dump, shell tracing, policy body or graph topology is printed.
No PR title/body/branch/commit text is interpolated into run commands. Existing
GitHub ref/run expressions remain in metadata/action inputs, not untrusted shell.
GITHUB_TOKEN is not passed to scripts; checkout's normal read token is not persisted.

## Verification and user handoff

```sh
python scripts/verify-hosted-ci.py
python scripts/run-offline.py
python scripts/verify-phase4-fixtures.py
```

The verifier exits 0 for local contract PASS, 2 for FAIL. The fixture command exits
0 for completed deterministic fixture integration, 2 for input/output/integration
failure. Both make no network/AWS/AI calls. Windows local provider IPC and receipt
renames can need filesystem access; actual hosted Linux behavior is not implied.
Full executed results and baseline reproduction are recorded in evidence.md.

Phase 5.1 can be COMPLETE LOCALLY only after every local gate/reproduction passes.
GitHub-hosted execution is NOT RUN / PENDING USER PUSH. A user-controlled push can
then verify installer/network compatibility, all gate results, complete Python
execution, fixture completion, artifact paths/retention and cancellation/timeouts.
For offline-only 5.1 verification, leave AWS_PLAN_ENABLED disabled; do not treat a
passing offline run as OIDC or real-plan verification. Do not upload private logs
or reports while debugging. No push or hosted trigger is performed by this task.

Local YAML validation is not hosted success; Terraform validate is not a real plan;
synthetic fixtures are not runtime security; pinned versions are not complete
supply-chain trust; passing CI is not deployment authorization. Phase 5 remains
IN PROGRESS and 5.2–5.5 remain NOT STARTED.
