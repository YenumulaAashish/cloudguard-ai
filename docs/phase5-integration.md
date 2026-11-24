> **Current execution update**

CG-SM-PLAN-002 is **CONSUMED** by run 45484703135. Owner-confirmed OIDC authentication
and Terraform planning passed; the security verdict failed. Historical approval and
NOT RUN statements below describe earlier checkpoints, not current authorization.
See [the investigation](real-plan-context-investigation.md). No retry or standing authorization is active.

# Phase 5 integration and verification handoff

Status: implementation prepared locally; authenticated AWS verification **NOT RUN**.
The first authenticated attempt subsequently failed at OIDC exchange in run
45469018350. Post-correction verification remains NOT RUN; see the incident link below.
**CG-SM-PLAN-001 is CONSUMED**; **CG-SM-PLAN-002 is APPROVED_RESTRICTED_SCOPE**.
See [the OIDC mismatch incident and retry contract](oidc-subject-mismatch.md).
The original owner approval below is retained as historical evidence only. No GitHub
settings or AWS configuration were inspected or changed by this implementation.

## Audit and evidence

The starting checkout was clean at `c216c427c711f7511a74ef9f98a1f247c9d05dfd`.
Read-only GitHub API inspection confirmed [hosted offline run 45418546667](https://github.com/YenumulaAashish/cloudguard-ai/actions/runs/45418546667)
completed successfully for that exact commit. This does not verify the new changes.
The user reports the OIDC provider, dedicated plan role, repository variables,
protected environment and main ruleset are configured. Their live configuration
and effective permissions have not been independently verified here.

Observed implementation gaps and resolutions:

| Gap in the starting source | Current implementation |
|---|---|
| AWS runner stopped at Conftest | Same exported plan is passed to existing IAM/network/data/graph/posture engines |
| Failed policy prevented later analyzer reporting | Both evaluations run; either failure still fails the job |
| Phase 4 summaries remained private-only CI smoke output | Explicit bounded public artifacts for synthetic offline and authenticated-plan processing |
| UI supported only old aggregate offline bundle | Version 1.1 supplements unchanged existing schemas with a closed public finding catalog |
| Advisory selector always regenerated synthetic fixtures | Explicit server-side `CLOUDGUARD_CATALOG_PATH` accepts only validated completed sanitized bundles |
| AWS workflow could run on same-repository PRs/main pushes | Manual dispatch from protected main only, plus an explicit review-approval variable |

Existing work is reused: Phase 3 normalizer/risk/offline advice, Phase 4 analyzers,
posture validator, Conftest enforcement and publication helpers. No risk algorithm,
Rego policy, Checkov exception or IAM permission is changed. The old dashboard
version 1.0 remains supported. Static output remains informational, never a gate.

## Temporary single-maintainer security exception — APPROVED RESTRICTED SCOPE

`CG-SM-PLAN-001` was explicitly approved by repository owner **YenumulaAashish**
in the instruction to record approval in this conversation on **2026-11-25**
(Asia/Calcutta). This is the approval source; no exact time-of-day was supplied.
The machine-readable record is
[`security/maintainer-planning-exception.json`](../security/maintainer-planning-exception.json).

Scope: **one** manually dispatched read-only AWS sandbox planning run in
ap-south-1 on protected main through the protected `aws-plan` environment.
The approval binds to [PR #2](https://github.com/YenumulaAashish/cloudguard-ai/pull/2)
and reviewed baseline `bb97a1d6bbb7826c9ddd7501ea26ab909959b198`, plus this
approval-record documentation and consistency-test amendment only. Other executable,
workflow, Terraform, IAM or policy changes require renewed review and approval.
The owner reports that PR #2's required offline check passed. This new amendment
requires its own hosted check after a separately authorized push.

**Expiry: 2026-12-01T18:30:00Z**, equivalent to **2026-12-02 00:00 IST**.
This conservatively covers seven calendar dates, 25 November through 1 December,
without inventing an approval timestamp. Expiry occurs earlier when the one run
reaches any terminal outcome (success, failure or cancellation), the owner revokes
approval, scope/reviewed executable code changes, a security gate fails, effective
protection/trust/permission validation fails, or credential/private-evidence exposure
is suspected. A failed/cancelled run does not grant a free retry.

The owner **permits environment self-review** and temporarily accepts the absence
of independent PR and CODEOWNERS approval for this scope. Author and reviewer may
therefore be the same person; no independent review is claimed. CODEOWNERS remains
in the repository. This record does not claim that GitHub permits self-approval of
an authored PR, nor that any GitHub setting has been changed.

Required PRs, passing up-to-date automated security checks, main branch protection,
blocked force pushes/deletions, exact OIDC audience/environment subject, main-only
manual dispatch, read-only least-privilege IAM and all existing policy/exception
gates remain mandatory. No direct main push, broad ruleset bypass, failed-check
bypass or fork-controlled authenticated execution is authorized. Any future manual
review-setting accommodation must be narrowly scoped, recorded and restorable;
if GitHub cannot accommodate it while preserving the other controls, obtain an
independent reviewer rather than disabling protections.

**Not authorized:** infrastructure deployment, Terraform apply/destroy, state
mutation, resource or IAM modification, increased permissions, or privileged
Phase 6 operations. Approval is not evidence of AWS authentication or planning.
No AWS access, workflow dispatch, enable-variable or GitHub setting change is
performed by this approval-record task.

Before later execution, record the final reviewed PR head and resulting protected
main SHA, the successful required hosted check for that head, effective environment
and branch protections, exact trust/role permission review, and any narrowly scoped
review-setting accommodation/restoration procedure. These execution bindings are
pending and must not be replaced with guessed SHAs or fabricated verification.

Restoration owner: **YenumulaAashish**. On expiry/revocation, do not dispatch or
approve further runs; cancel any still-pending/running run safely, disable BOTH
`AWS_PLAN_ENABLED` and `AWS_PLAN_REVIEW_APPROVED`, restore any review-only settings
covered by the exception, and record the outcome/restoration evidence. No automatic
cleanup, resource deletion or state mutation is authorized. Variables remain
untouched in this task. The record and tests document scope; they are **not a
runtime expiry mechanism** or proof that external settings were restored.

## Public data and advisory contract

`security/public-findings.schema.json` is a new closed schema, not a modification
of existing Phase 3/4 schemas. Each row contains only a run-local opaque sequence
ID, known control ID, fixed analyzer domain, allowlisted AWS resource TYPE,
deterministic severity/status and requires-review boolean. No arbitrary strings,
messages, resource addresses, accounts, ARNs, IPs, paths, policies, topology or
private hashes are permitted. There are at most 256 public rows. `total_count`
and `omitted_count` make truncation explicit; omitted findings remain in private
engine outputs and posture counts. Unknown severity/status remains UNKNOWN.

`dashboard.json` version 1.1 contains the existing validated PR summary and receipt,
posture summary and receipt, plus this catalog. It is limited to 128 KiB, uses
exact keys and validates counts/domain distributions. It is published last only
after schema validation, consistency, repeated byte reproduction and readback.
Output directories must be fresh and under the existing private/sanitized roots.
Ordinary failures roll back owned files; hard interruption is not a transactional
filesystem guarantee. Consumers require the final completed dashboard bundle.

Source modes: SYNTHETIC (explicit repository fixture), OFFLINE (caller-supplied
plan JSON, no authentication performed), AUTHENTICATED_PLAN (authenticated runner's
processing path). The last is a source designation, **not a signed attestation**.
Copied/tampered valid artifacts cannot prove authentication. Schema validity does
not verify GitHub origin or AWS execution; same-plan/freshness/authenticity remain
UNKNOWN in the unchanged Phase 4 contracts. A successful report is not policy PASS.
Conftest's recorded real-plan verdict is retained separately and can be FAIL.

The authenticated runner exports one plan, evaluates Conftest and runs all four
analyzers against that path in the same process sequence. This operational
association does not upgrade the formal Phase 4 context contract to VERIFIED.
No raw plan or private intermediate is uploaded. CI artifacts list exact filenames,
use three-day retention and have read-only GitHub permissions. PR reporting means
downloadable sanitized artifacts; automatic comments and PR write tokens remain
unimplemented. Source/finding counts may themselves be sensitive: review publication.

For local offline integration, use fresh directories:

```sh
python scripts/integrate-plan.py --plan PATH_TO_LOCAL_PLAN_JSON --checkov PATH_TO_CHECKOV_JSON --source OFFLINE --private-output reports/private/NEW_RUN --public-output reports/sanitized/NEW_RUN
```

Load only the completed `dashboard.json` through the existing dashboard loader.
It remains an untrusted user-supplied snapshot. The backend never accepts uploaded
raw reports or browser-defined catalog entries. To enable advisory for that reviewed
sanitized bundle, set `CLOUDGUARD_CATALOG_PATH` to its local path before starting
`scripts/serve-advisory.py`. It must resolve below `reports/sanitized/` and have the
exact name `dashboard.json`. Startup rejects incomplete/invalid/private inputs.
The catalog is immutable for that server process; a new random catalog ID binds
requests to that instance and rejects stale selectors after restart. IDs are not
resource identifiers or private content hashes. Only five enum/allowlist fields
reach OpenAI; no review flag, receipt, risk, source identity or resource ID is sent.
Paid requests still require an explicit click and the existing rate limits/key.

## Manual authenticated validation — approved scope, prerequisites still required

1. PR #2 is already open; its required offline check passed according to the owner.
   Review this approval-record amendment and obtain separate push authorization.
   After the later push to that existing PR, wait for the exact final head's required
   hosted offline checks. This task does not push or merge.
2. CG-SM-PLAN-001 remains consumed. CG-SM-PLAN-002 is approved separately on
   2026-11-25 through 2026-12-01T18:30:00Z. Complete the approval amendment
   PR/check/main bindings before execution; the original approval is not reusable.
   Preserve required PRs, required passing/up-to-date offline checks, protected main,
   blocked force pushes/deletions and exact environment deployment refs. Do not
   remove CODEOWNERS or disable the ruleset to work around missing approval.
3. Manually verify the deployed role's inline AND attached policies and OIDC trust
   against the bootstrap code. No admin/broad policies, write permissions, role
   chaining or PassRole may be attached. The provider audience and exact environment
   subject must match. Review main-only environment rules. This task did not access AWS.
4. Merge through the protected PR process under the recorded approval, not by an
   unrecorded bypass. Verify the intended main commit and exact offline run result.
5. In repository Actions variables, confirm the exact plan role and bucket variables.
   Set `AWS_PLAN_REVIEW_APPROVED=true` only after recording approval. Then manually
   set `AWS_PLAN_ENABLED=true` for the single run. No code sets these variables.
6. Manually dispatch **Authenticated Terraform plan** on `main`, review the protected
   environment request for that SHA and approve only within the recorded scope.
   There are no push/PR triggers for this workflow. Forks cannot dispatch their code
   into the reviewed main-only job.
7. Inspect the job conclusion, credential-action step outcome, Terraform plan exit
   (0 or 2), JSON export, real-plan Conftest result and Phase 4 integration outcome.
   Download only the named public artifact and verify repository/run/SHA/source,
   exact file set, completion, schema and displayed UNKNOWN context. Record failures
   honestly. AccessDenied is a blocker, not authority to broaden the role.
8. Immediately set BOTH enable/review variables false again. Restore the review
   settings covered by the expired exception and record restoration evidence. Do
   not repeat a run beyond the approved scope without new authorization.

CODED: yes. CONFIGURED: user-reported, not independently inspected. VERIFIED:
NOT RUN. Phase 5 authenticated verification and final release remain incomplete
until the above execution and review provide actual evidence. The dashboard's AWS
status is deliberately not inferred from imported JSON or OIDC configuration code.

## Prior integration checkpoint validation (bb97a1d)

| Check | Observed result |
|---|---|
| Full offline runner | PASS; matching current-source run context |
| Python discovery | 681 tests PASS, zero skips (16 new integration tests and 6 additional frozen-file mutation tests) |
| Frontend | Build PASS; 50 tests PASS; source/build privacy checks PASS |
| Chrome browser checks | 3 PASS on dedicated loopback test port |
| Existing backend mocked HTTP / exporter tests | 1 / 8 PASS |
| Terraform workload/bootstrap format, init and validate | PASS using cached providers, backend disabled |
| TFLint including AWS ruleset | PASS |
| Checkov 3.2.471 | 30 passed, 0 failed, 6 skipped, 0 parsing errors |
| Exact exception contract | Expected 6, observed 6, missing 0, unexpected 0 |
| OPA / Conftest | 35 tests / 6 fixtures PASS |
| Destructive-command guard / reviewed CI contract | PASS / PASS in local static scope |
| Integrated Phase 3/4 plan reporting | PASS; private and public repeated outputs byte-identical |
| Phase 3 baseline | 13/LOW, review required, 6 approved exceptions, 0 failed; real-plan policy UNKNOWN |
| Dependency audits | npm and pinned backend: no known vulnerabilities |
| Secret scan | PASS for tracked/intended files; existing synthetic canaries recognized |

No paid AI call, AWS authentication/API call, protected workflow run, infrastructure
change, deployment execution, GitHub setting change, push or merge was performed.
Public documentation/dependency databases and the historical GitHub run metadata
were read. New hosted/authenticated validation remains NOT RUN; these local checks
do not authorize execution or complete the release; owner approval is recorded separately above.

## Approval-record amendment validation — 2026-11-25

The complete local regression suite passed: **687 Python tests, zero failures and
zero skips**, including six new approval-record consistency tests; **50 frontend
tests**; **3 browser checks**; **1 mocked backend HTTP test**; **8 exporter tests**.
The production frontend build and source/build privacy checks passed. Terraform
workload/bootstrap formatting, cached backend-free init and validation, TFLint
with AWS ruleset, destructive-command guard and reviewed local CI contract passed.
Checkov remained **30 passed / 0 failed / 6 skipped / 0 parsing errors**; the exact
exception contract remained expected 6, observed 6, missing 0, unexpected 0.
OPA **35 tests** and Conftest **6 fixtures** passed. Integrated offline Phase 3/4
private and public outputs reproduced byte-for-byte. Secret scan and diff checks
passed. No workflow, IAM, Terraform, policy or Checkov-exception files changed.

These are local results for the approval-record amendment, not hosted evidence
for its eventual PR head. Authenticated AWS planning remains **NOT RUN**. No AWS,
live AI, GitHub setting change, variable enablement, push, merge or deployment was
performed. The expiry and manual restoration obligations above remain in force.

Current approval update: **CG-SM-PLAN-002 is APPROVED_RESTRICTED_SCOPE** by the owner
on 2026-11-25 through **2026-12-01T18:30:00Z**. Only environment self-review is
approved. Amendment PR/check/main bindings remain pending; execution is NOT RUN.
See [the current approval handoff](plan-002-approval.md).
