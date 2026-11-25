# Phase 6 AWS integration preparation: local validation

Date: 26 November 2026 (IST). Branch: `codex/phase6-offline-mvp`.
Started from `64a66fac15285d6ffa6fd046d8d7e887af90b1dd`, a clean working tree with
an offline-only adapter and six generated-source Checkov failures. Existing partial
work was preserved. This change adds inactive native AWS components and repairs
the generated source without extending the six legacy exceptions.

## Final executed results

| Validation | Result |
|---|---|
| Integrated offline runner and fresh sanitized evidence | PASS |
| Complete Python suite | 864 passed in 182.241 seconds; includes 35 live-adapter tests plus expanded frozen-file cases |
| Terraform workload/bootstrap format, backend-free init and validate | PASS / PASS |
| TFLint 0.59.1 with AWS ruleset 0.40.0 | PASS |
| Legacy Checkov 3.2.471 | 30 passed / 0 failed / 6 skipped / 0 parsing errors |
| Legacy exception contract | 6 expected, 6 observed, 0 missing, 0 unexpected; no global suppression |
| OPA 1.0.1 | 40 / 40 tests passed |
| Conftest 0.60.0 | 10 / 10 expected secure/insecure fixture outcomes passed |
| Generated all-enabled source (Terraform 1.9.8 / AWS provider 6.65.0) | Validate PASS; Checkov 39 / 0 / 0, zero parsing errors; OPA/Conftest synthetic fixtures PASS |
| Generated S3-only source | Validate PASS; Checkov 20 / 0 / 0; OPA/Conftest PASS |
| Generated VPC-only source | Validate PASS; Checkov 6 / 0 / 0; OPA/Conftest PASS |
| Six deliberately missing generated controls | 6 / 6 rejected by the expected Checkov rule; zero skips/parsing errors |
| Native-backend HCL with fake private bindings, backend disabled | Validate PASS; Checkov 39 / 0 / 0 |
| Native `tfplan.json` policy route, provider-shaped secure/insecure fixtures | 2 / 2 expected outcomes; insecure public block rejected by OPA and Conftest |
| Frontend unit / production build | 65 passed / PASS |
| Browser regression | 5 passed, including mock Deploy/drift and imported-report authenticity warnings |
| Backend loopback HTTP / exporter | 5 passed / 8 passed |
| Privacy/secret boundary checks, closed schema parity | PASS |
| CI destructive-command guard / reviewed CI contract | PASS / PASS, LOCAL_STATIC_ONLY |
| Phase 1-5 security pins and Terraform/policy/workflow source | Preserved; 11 additional Phase 6 pins, including every live module |
| Git whitespace check | PASS |
| Hosted GitHub execution | NOT RUN |
| Live AWS identity/support verification, native authenticated plan, deployment, inventory, drift, remote lock/state operations | NOT RUN |

The native-policy fixture exercise uses actual local OPA/Conftest tools against
provider-shaped JSON; it is not a newly authenticated AWS plan. SDK/process doubles
exercise successful execution, expiry/revocation, failed gates, concurrent delivery,
replay, stale state/artifacts/prices, uncertain recovery and version-safe deletion.
They never invoke AWS or a real Terraform deployment command.

An intermediate full run overlapped hardening edits and failed frozen-file
consistency tests. The final run above used unchanged source and passed, with
fresh matching evidence. A final CI pin-name collision was repaired before that
run, and every live module is now checked by the contract coverage test.

The browser default port was already occupied; the successful isolated run used
`CLOUDGUARD_TEST_PORT=5198` without stopping that existing service. Public AWS,
HashiCorp and provider-source documentation was read. No AWS service/account API,
IAM change, deployment, paid AI request, push or merge occurred. Native S3 init was
not executed: all Terraform initialization in this task disabled the backend and
used the local provider mirror.

## Reproduce the safe checks

Use the existing pinned toolchain and local provider mirror:

```sh
python scripts/run-offline.py
python scripts/validate-phase6-source.py
python scripts/verify-hosted-ci.py
python scripts/verify-no-deployment-ci.py
python -m unittest discover -s backend -p 'test_*.py'
python -m unittest discover -s frontend/scripts -p test_export.py
npm --prefix frontend test
npm --prefix frontend run build
npm --prefix frontend run test:browser
```

Set `TFLINT_AWS=1` and the reviewed plugin directory for the integrated runner.
If needed use a separate browser test port. The native policy-route check used the
existing realistic-plan fixtures with `ToolGates.run(folder,native=True)`, a copied
actual backend-free validation result and a private `tfplan.json`; no authenticated
plan was substituted or claimed. Native backend tests inject every AWS/process
boundary. Do not turn the safe suite into a live test by supplying deployment
activation, cloud SDK test clients or real process execution to its fixtures.

## Readiness and remaining manual work

Live backend: CODED. Installation: NOT CONFIGURED. AWS verification: NOT VERIFIED.
Deployment activation is OFF: the checked-in grant is NOT_APPROVED and all operation
permissions are false. Passing offline tests does not authorize live execution.

Review [architecture](phase6-provisioning-architecture.md),
[control applicability/costs](phase6-generated-security.md) and
[owner IAM/state/environment setup](phase6-live-setup.md). Three fresh CMKs have a
base approximately USD 3/month total; EC2/EBS, monitoring, S3 replicas/requests,
transfer, logs and state/locking require a fresh regional owner-reviewed quote.
Missing/stale pricing blocks native Deploy. Forecast limits are not a billing cap.

The proposed isolated owner-hosted service avoids privileged GitHub runners; host
ACL/isolation, backup rollback resistance and actual IAM condition applicability
remain owner verification tasks. The existing Phase 5 authorization ledger and
runner-isolation blocker are not silently bypassed or declared externally resolved.
DynamoDB locking preserves Terraform 1.9.8; plan a separately tested future migration
because that backend locking method is deprecated in current HashiCorp guidance.

Before any real test, separately authorize and establish the trusted host, exact
IAM/support/state resources, reviewed AMI and price export. Review the two AWS-required
log-delivery wildcard actions, constrained by region and the fixed application
scope; do not give the worker audit policy mutation rights. Begin with a private
read-only installation grant and explicit connectivity verification. Then authorize
remote-lock planning, and only subsequently deployment/deletion after reviewing the
real results. No additional reviewer account or per-plan review dashboard exists.
The operator Deploy action still authorizes the exact fully gated saved plan.

## Files in this change

- `README.md`
- `backend/cloudguard_live/__init__.py`
- `backend/cloudguard_live/aws.py`
- `backend/cloudguard_live/engine.py`
- `backend/cloudguard_live/native.py`
- `backend/cloudguard_live/pricing.py`
- `backend/cloudguard_live/settings.py`
- `backend/requirements-live.txt`
- `backend/serve_platform.py`
- `docs/phase6-generated-security.md`
- `docs/phase6-integration-validation.md`
- `docs/phase6-live-setup.md`
- `docs/phase6-offline-mvp.md`
- `docs/phase6-provisioning-architecture.md`
- `docs/phase6-roadmap.md`
- `frontend/src/App.tsx`
- `frontend/src/data/phase6-public.schema.json`
- `frontend/src/pages/Provisioning.test.tsx`
- `frontend/src/pages/Provisioning.tsx`
- `frontend/src/services/provisioning.ts`
- `scripts/cloudguard/ci_security.py`
- `scripts/cloudguard/phase6/config.py`
- `scripts/cloudguard/phase6/cost.py`
- `scripts/cloudguard/phase6/engine.py`
- `scripts/cloudguard/phase6/gates.py`
- `scripts/cloudguard/phase6/http.py`
- `scripts/validate-phase6-source.py`
- `security/phase6-live-authorization.template.json`
- `security/phase6-live-settings.template.json`
- `security/phase6-mock-prices.json`
- `security/phase6-public.schema.json`
- `tests/unit/test_phase6.py`
- `tests/unit/test_phase6_live.py`
