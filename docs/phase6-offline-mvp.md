# Phase 6 offline MVP: run and verify

All operations are MOCK_ONLY. The single operator's Deploy action authorizes the
exact gated mock plan, with no reviewer account or approval-management dashboard.
The architecture and roadmap documents define the updated requirements. FR-4/O4
mapping is based on the owner's instruction; original specification text is not
bundled or claimed independently verified.

## Start locally

Use the reviewed Python environment and pinned validation tools. Seed the cached
AWS provider using the existing offline setup first; this mock tool runner uses a
filesystem mirror only and never falls back to a remote backend/provider download.
Set a strong random 32–128 character CLOUDGUARD_OPERATOR_TOKEN in the SERVER process
environment privately. Do not commit/paste it into scripts or screenshots. Start:

```sh
python scripts/serve-provisioning-mock.py --budget-limit-usd 20.00
npm --prefix frontend run dev
```

The mock API listens only on 127.0.0.1:8790. The standard Vite loopback proxy uses
5173. Visit Provisioning (Mock), enter the operator secret in the password field,
and sign in. The key is cleared after requests, and no credential goes to advisory.
No automatic API request, cloud connection or paid AI request starts on page load.

Configure EC2/S3/VPC and usage/budget bounds, then Generate and preview. The real
local tools run privately; their stderr, HCL, policies and synthetic plan are never
returned to the browser. Missing tools/provider mirrors, cost context or failed
checks block Deploy. Do not mistake OPA/Conftest passing a synthetic plan for a
passing authenticated Terraform plan. New-source Checkov has zero accepted skips.

If all mandatory gates pass, Deploy mock plan simulates only local state changes.
For tests, an explicitly injected gate test double exercises successful worker
transitions; the shipped server exposes no option to select that test double or
bypass real checks. Default templates can legitimately remain blocked by Checkov.

## Drift, inventory and recovery

After a successful mock execution, refresh inventory/history. Detect drift compares
saved declared configuration to the separate mock observation. Simulate changed
control/missing resource/unavailable observation are fixed local-fixture scenarios;
they cannot modify AWS. UNKNOWN is not IN_SYNC or proof of a vulnerability.

Preview reconciliation targets the original declared configuration, reruns all
gates and needs a new Deploy action. No automatic remediation or unowned deletion.
Alerts remain open for UNKNOWN and resolve only after complete matching evidence.
Remove components through new configuration or Preview resource deletion. Type the
exact deletion count phrase; there is no force-empty or automatic data-loss path.
Faults/interruptions require fresh recovery previews and exact-plan authorization.

State, artifacts and private logs remain ignored under reports/private/phase6-mock.
Keep this local development store private. Production authentication, encrypted
remote state, AWS refresh/deployment, real pricing and external alerts are NOT RUN
or not implemented. No claim of current AWS connectivity or production readiness.

Run regression with the existing offline runner, frontend unit/build/browser tests,
backend loopback tests and the new tests/unit/test_phase6.py suite. Those tests use
synthetic state and mock price/gate fixtures without AWS credentials.

## Windows local setup

With the ignored portable validation environment used in this workspace:

```powershell
$env:PATH="$PWD/.tools/hardening-bin;$PWD/.tools/python312-runtime;$env:PATH"
$env:CLOUDGUARD_OPERATOR_TOKEN = Read-Host 'Private random mock operator secret' -MaskInput
.tools/python312-runtime/python.exe scripts/serve-provisioning-mock.py --budget-limit-usd 20.00
```

Use another terminal for npm --prefix frontend run dev. The prompt is manual; this
task does not create, log or publish a real operator secret. A normal reviewed
Python 3.12 environment with the existing backend requirements also works. Do not
use this local mock authentication/store as a production deployment service.

## Executed local validation

| Scope | Result |
|---|---|
| Full Python regression suite | 818 passed, including 37 new Phase 6 tests |
| Backend loopback HTTP | 5 passed (4 new Phase 6 tests) |
| Frontend unit tests / production build | 63 passed / PASS |
| Browser suite | 5 passed, including mock operator Deploy and drift alerts |
| Exporter tests | 8 passed |
| Legacy Terraform workload/bootstrap format, backend-free init and validate | PASS |
| Legacy TFLint AWS ruleset | PASS |
| Legacy Checkov | 30 passed / 0 failed / 6 skipped / 0 parsing errors |
| Existing exception contract | Six expected and observed; none missing/unexpected |
| Existing OPA / Conftest fixtures | 40 tests / 10 expected fixture outcomes passed |
| Reviewed CI contract / destructive guard / privacy / secret scan | PASS |
| Existing Phase 1-5 security fingerprints | All unchanged; 14 new Phase 6 files added to contract |
| Generated Phase 6 HCL with Terraform 1.9.8 / AWS 6.65.0 | Validation PASS |
| Generated Phase 6 Checkov source scan | 33 passed / 6 failed / 0 skipped / 0 parsing errors |
| Generated synthetic plan OPA / Conftest evaluation | PASS / PASS |
| Real AWS planning, deployment, inventory refresh and drift scan | NOT RUN |

The six generated-source failures are real blockers. No skips were introduced and
the shipped server keeps Deploy disabled for this fixture. Successful execution,
reconciliation, deletion and fault-recovery tests use explicit gate test doubles;
those results do NOT establish real template security compliance. The shipped CLI
has no switch to select the test doubles or skip checks.

Generated-source blocking rule IDs:

- CKV2_AWS_11
- CKV2_AWS_41
- CKV2_AWS_62
- CKV_AWS_144
- CKV_AWS_145
- CKV_AWS_18

These cover missing flow logs, an EC2 instance profile, S3 logging, replication,
customer-managed encryption and event notification controls. Supporting resources,
least-privilege permissions and real costs need a reviewed future architecture.
Existing Phase 1 exceptions are not silently extended to the new source.

Inspection also verified a generator compatibility issue: Checkov 3.2.471 directory
scanning did not discover .tf.json input. Native HCL is now generated instead, and
S3 companion source references are explicit. This fixed discovery/graph-linkage
implementation defects; remaining source findings were not suppressed.

The original specification is not bundled here. FR-4/O4 traceability is based on
the owner's stated requirements, not an invented quotation or compliance claim.

## Changed-file inventory

- README.md
- backend/test_phase6_http.py
- docs/phase6-offline-mvp.md
- docs/phase6-provisioning-architecture.md
- docs/phase6-roadmap.md
- frontend/scripts/check-safety.mjs
- frontend/src/App.tsx
- frontend/src/data/phase6-public.schema.json
- frontend/src/pages/Provisioning.test.tsx
- frontend/src/pages/Provisioning.tsx
- frontend/src/services/provisioning.ts
- frontend/tests/browser/dashboard.spec.ts
- frontend/vite.config.ts
- scripts/cloudguard/ci_security.py
- scripts/cloudguard/phase6/__init__.py
- scripts/cloudguard/phase6/config.py
- scripts/cloudguard/phase6/cost.py
- scripts/cloudguard/phase6/drift.py
- scripts/cloudguard/phase6/engine.py
- scripts/cloudguard/phase6/gates.py
- scripts/cloudguard/phase6/http.py
- scripts/cloudguard/phase6/store.py
- scripts/serve-provisioning-mock.py
- security/phase6-mock-prices.json
- security/phase6-public.schema.json
- tests/fixtures/phase6/configuration.json
- tests/unit/test_phase6.py
