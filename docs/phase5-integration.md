# Phase 5 integration and verification handoff

Status: implementation prepared locally; authenticated AWS verification **NOT RUN**.
The single-maintainer exception below is **PENDING USER APPROVAL**. No GitHub
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

## Temporary single-maintainer security exception — NOT APPROVED

Proposed identifier: `CG-SM-PLAN-001`. Scope: one manually dispatched, read-only
authenticated plan validation on protected main, within seven calendar days of
explicit approval. Expiry is the earlier of that run's completion or the end of
the approved seven-day window. Record exact UTC start/expiry before enabling.
This draft is not approval and must not be used to bypass unavailable protections.

The proposed exception covers only the absence of an independent reviewer for the
maintainer's own PR/CODEOWNERS approval and environment self-review. It recognizes
that the same person can author and approve trusted code. It does not assert
independent separation of duties. It must not permit direct pushes, force pushes,
deletions, bypassing failed required checks, changing AWS permissions, applying a
plan, trusting forks, or running unreviewed workflow/script changes.

Before approval, record: approver identity; exact reviewed commit and PR; protected
main SHA; offline run URL/conclusion; environment/branch settings reviewed; precise
review settings that cannot be satisfied; compensating controls; UTC expiry; owner
responsible for restoring review settings; rollback instructions and result.
Use a narrow, auditable repository/environment exception only if GitHub supports
it while keeping the other controls effective. If that is impossible, obtain an
independent reviewer; do not disable the broader ruleset or environment protections.

Suggested explicit approval text (must be supplied by the user, not generated as
an approval record): “I approve CG-SM-PLAN-001 for commit [SHA], PR [URL], one
read-only manual plan run, expiring [UTC time], accepting the documented lack of
independent review.” The placeholders must be replaced. No approval is currently
recorded. There is no blanket exception for future PRs, deployment or Phase 6.

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

## Manual authenticated validation — after explicit approval only

1. Review the local feature branch and its complete diff. Obtain separate push
   authorization; push, open a PR and wait for the exact commit's hosted offline
   checks. These changes have not been pushed by this task.
2. Record approval of the time-bounded exception above or obtain independent review.
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

## Executed local validation

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
do not approve the security exception or complete the release.
