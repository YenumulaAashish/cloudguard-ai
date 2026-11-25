# Phase 5 final hardening and verification

## Milestones and evidence quality

Owner-confirmed run 45484703135 / job 138766888056 at main
003a26a775ec651b415fe039267bc590bd8eb831 authenticated successfully and produced a
Terraform plan with exit 2 (18 creates, zero updates/deletes). Its security verdict
FAILED: Conftest 12 passes and one failure. Checkov was 30/0/6; Phase 4 reporting
and sanitized uploads succeeded. These are distinct milestones. CG-SM-PLAN-002 is
consumed. The exact old failed Rego rule remains unconfirmed.

The owner reports the policy fixes ffdf1f05bced811f4fe02a3c10f6ced44aa53bb0 were
merged and hosted offline CI passed. Local main/origin main were fetched and resolved
to merge 4aa3aae214738168f3ea7c63b72f42494e118291 before this hardening branch.
Hosted checks were not independently re-run/inspected by this task.

Successful dashboard import and live OpenAI advisory demonstration are recorded
as owner-reported project milestones requested in this task. No demonstration
run ID, dated recording or response evidence was provided for independent checking.
This task validates import/advisory with synthetic inputs and mock providers only;
no new live AWS connection, authenticated plan, paid AI request or deployment is
claimed. Earlier NOT RUN statements in old documents describe historical checkpoints.
Do not rewrite the failed real-plan verdict as passed based on subsequent offline
fixtures or a successful UI/advisory demonstration.

## Reporting architecture

Private plan -> unchanged deterministic engines -> Phase 3 normalized scanner
findings/risk AND separate Phase 4 IAM/network/S3 analyzer findings + graph ->
bounded sanitized dashboard bundle -> local file import. Neither scope is added
to the other to create a scan total. AUTHENTICATED_PLAN is an origin label, not a
signature, freshness timestamp or live connectivity check. UNKNOWN remains review
context and never becomes PASS from an AI answer or an import.

Dashboard v1.2 adds only policy_reasons: bounded allowlisted rule/reason/count
triples. Python and browser reject extra prose/fields, unknown codes, duplicates
and contradictory verdicts. Existing v1.0/v1.1 imports remain supported at their
original boundaries. Old reports without reasons explicitly display unavailable;
the UI cannot recover the old failed rule from aggregate counts.

The advisory service loads the server's own validated sanitized bundle. It uses
one reviewed catalog covering all 30 existing analyzer IDs and sends only safe
control/domain/severity/status/resource-type fields, static description, fixed
reason code, field-level remediation, source label and UNKNOWN context. Raw plans,
policy contents, names, addresses, account IDs, provenance fingerprints and browser
prose are not advisory input. Provider output cannot modify deterministic records.
Explicit click, existing rate limits, no retry, no storage and no tools remain.

## Load the same authenticated report in dashboard and advisory

1. Retrieve only the sanitized dashboard.json from the completed workflow artifact;
   verify run, reviewed SHA, origin and age separately in GitHub. Keep raw plan and
   private analyzer outputs out of downloads served by Vite, prompts and public logs.
2. Place dashboard.json under reports/sanitized/CHOSEN_RUN/dashboard.json. Open the
   dashboard and select Load sanitized bundle. Review the origin and UNKNOWN
   authenticity/freshness warnings, policy verdict/reasons and Phase 4 review flags.
3. Restart the loopback advisory service with CLOUDGUARD_CATALOG_PATH set to that
   absolute dashboard.json path. Run python scripts/serve-advisory.py. Keep API keys
   in the server environment only; never VITE variables or browser storage. Opening
   the service does not call OpenAI. Existing backend requirements remain pinned.
4. In AI Advisory click Load advisory finding selector. It loads the backend catalog,
   independently of browser imports. Confirm source/control selection matches your
   intended server report. A changed backend catalog requires service restart;
   opaque catalog IDs prevent stale selector replay. Only Explain with AI incurs a
   request, after separately approved paid use. This task performs no such request.

## Final authenticated verification checklist — NOT RUN

- Review/merge this branch through normal PR gates after explicit push approval.
- Obtain passing hosted offline checks on final main; bind a fresh grant to exact
  main SHA/fingerprint. Old grants are consumed or source-stale and cannot be reused.
- Provision and independently review the dedicated runner/volume and inactive-to-
  approved ledger procedure in planning-authorization.md. Verify all live protection,
  role, trust, sandbox and review constraints; no variable enablement is implicit.
- With separate owner authorization, dispatch one manual attempt, approve aws-plan,
  verify ledger spends it before STS, then inspect OIDC, plan exit 0/2, policy gate,
  safe reasons, all analyzer outputs and sanitized uploads as separate outcomes.
- Import that sanitized report; verify labels, preserved verdicts and warnings.
  If separately authorized for paid use, request one safe advisory and verify the
  unchanged deterministic result. Record run/SHA and sanitized demonstration evidence.
- Exercise denial cases offline, not by making extra unauthorized AWS attempts.
  Test hosted cancellation/recovery only under an explicit counted authorization.
- Disable switches/revoke when done; restore temporary review accommodations.

Phase 5 code readiness does not mean hosted ledger verification or a passing new
real-plan verdict. Those remain external release-verification blockers. Runner workflow isolation
may be unavailable on a personal public repository: verify eligibility first and
keep authorization inactive if it cannot be enforced. See the feasibility section
of planning-authorization.md; labels alone do not satisfy this requirement.

## Final executed local validation

| Validation | Result |
|---|---|
| Terraform workload and bootstrap fmt / backend-free init / validate | PASS / PASS |
| TFLint 0.59.1 with AWS ruleset 0.40.0 | PASS |
| Python full unit suite | 761 passed |
| Checkov 3.2.471 | 30 passed / 0 failed / 6 skipped / 0 parsing errors |
| Exception contract | Six expected, six observed, none missing/unexpected |
| OPA 1.0.1 | 40 passed |
| Conftest 0.60.0 | 10 expected fixture outcomes passed |
| Integrated offline runner and source-fingerprint binding | PASS |
| Reviewed CI contract / destructive-command guard | PASS / PASS |
| Frontend production build / unit tests / browser | PASS / 56 passed / 4 passed |
| Mock loopback advisory HTTP / exporter tests | 1 passed / 8 passed |
| Frontend source/build privacy and local secret scan | PASS |
| Synthetic Phase 4 smoke and repeated plan integration | PASS; five private and four sanitized files byte-identical |
| In-memory synthetic failed-policy reason publication | PASS; failed verdict preserved and private canary withheld |
| New hosted workflow, live approval API, authenticated plan, paid AI calls | NOT RUN |

The authorization suite has 27 retained tests, including separate-process/thread
concurrency, missing/corrupt/rolled-back storage, crash boundaries, stale locks,
quota/day/expiry limits, replay, exact scope, revoked grants, missing security
evidence, rejected/bot/self reviews and explicit fresh self-review approval. Three
additional deadline tests verify expiry stops Terraform subprocesses without retry.
Catalog and reason tests cover every supported analyzer ID and negative input shapes.

Local runtime: Python 3.12.10 / SQLite 3.49.1, Node 22.20.0 / npm 10.9.3,
Terraform 1.9.8 and cached AWS provider 6.65.0. The previously referenced Windows
Python installations were missing; an ignored portable runtime was used. No tool
binary, private plan, private ledger or populated authorization is committed.

This task contacted GitHub for the explicitly requested main fetch, public
Python/documentation sources and local loopback test servers. It made no AWS API
calls. Provider initialization used the existing filesystem mirror with metadata
and checkpoint calls disabled. No planning variables/settings changed; no approval
activated; no infrastructure provisioning or Phase 6 implementation occurred.

## Changed-file inventory

- .github/workflows/terraform-plan.yml
- Makefile
- README.md
- docs/architecture.md
- docs/frontend-dashboard.md
- docs/github-oidc.md
- docs/live-ai-advisory.md
- docs/phase5-integration.md
- docs/phase5-release.md
- docs/phase6-roadmap.md
- docs/planning-authorization.md
- frontend/scripts/check-safety.mjs
- frontend/src/App.test.tsx
- frontend/src/App.tsx
- frontend/src/components/ActualFindings.tsx
- frontend/src/data/control-descriptions.json
- frontend/src/data/policy-reasons.json
- frontend/src/pages/Aws.tsx
- frontend/src/pages/Overview.tsx
- frontend/src/pages/Scans.tsx
- frontend/src/services/hardening.test.tsx
- frontend/src/services/reports.ts
- frontend/src/types/reports.ts
- frontend/tests/browser/dashboard.spec.ts
- scripts/aws-plan.py
- scripts/clean.py
- scripts/cloudguard/authorization.py
- scripts/cloudguard/ci_security.py
- scripts/cloudguard/control_catalog.py
- scripts/cloudguard/live_advisory.py
- scripts/cloudguard/phase5.py
- scripts/cloudguard/planning.py
- scripts/cloudguard/policy_reporting.py
- scripts/manage-planning-ledger.py
- scripts/planning-authorization.py
- security/control-descriptions.json
- security/planning-authorization.template.json
- tests/unit/test_authorization.py
- tests/unit/test_ci_security.py
- tests/unit/test_hardening_contracts.py
- tests/unit/test_live_advisory.py
- tests/unit/test_oidc_subject.py
- tests/unit/test_phase5.py
- tests/unit/test_plan_deadline.py
- tests/unit/test_pr_reporting.py
