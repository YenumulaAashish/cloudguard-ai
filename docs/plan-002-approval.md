# CG-SM-PLAN-002 — approved scope, pending amendment bindings

The repository owner explicitly approved CG-SM-PLAN-002 in this conversation on
**25 November 2026**. The [approval record](../security/maintainer-planning-exception-002.json)
records **APPROVED_RESTRICTED_SCOPE**. This authorizes exactly one authenticated,
read-only AWS sandbox Terraform planning attempt in ap-south-1, subject to all
remaining execution prerequisites. It does not authorize this agent to execute it.

Expiry: **2026-12-01T18:30:00Z (2 December 2026, 00:00 IST)**, or earlier on
completion, failure, cancellation, revocation or security violation. No success
requirement exists for consuming the attempt. CG-SM-PLAN-001 remains consumed by
failed run 45469018350; the new approval is a distinct owner decision, not reuse.

## Available evidence and its source

| Evidence | Provenance |
|---|---|
| Fix `b7b71ea7c60dceaa69991acb17bc319448bb385d` | Full SHA independently resolved from local git objects |
| Merge `ccc6adadf49cade9be2cd801fab42bc8cf67f004` | Full SHA and PR #3 merge message independently inspected locally |
| Fix ancestry and main/reference equality | Verified using local git; remote-reference freshness not queried |
| PR #3 successfully merged | Owner-confirmed; local merge object corroborates its identity/history |
| Required PR check and latest main offline CI passed | Owner-confirmed; run URLs/IDs not supplied and not invented |
| Live AWS IAM trust manually corrected | Owner-confirmed; no AWS inspection or successful post-fix token exchange performed here |

The recorded protected main SHA is the owner-approved baseline, **not** the unknown
main commit that will later contain this approval amendment. No remote check,
environment setting, role permission or variable state is independently verified
by local tests. Approval time-of-day is unspecified; the date and explicit expiry
are preserved without inventing a timestamp.

## Restricted authority

Only temporary environment self-review is approved. No independent PR approval or
CODEOWNERS waiver is inferred from the consumed approval or this owner's conditions.
Existing required PRs, passing up-to-date checks, main protection, exact StringEquals
OIDC subject/audience, protected environment and read-only IAM remain mandatory.
The exact subject is
`repo:YenumulaAashish@212769106/cloudguard-ai@1379194368:environment:aws-plan`;
the audience remains `sts.amazonaws.com`. No permission expansion is allowed.

Apply, destroy, state mutation, infrastructure deployment, resource/IAM changes,
security-gate bypass and Phase 6 implementation of any kind are prohibited. AI
cannot grant authority or change deterministic results. The amendment changes only
the approval record, documentation and consistency tests; other executable or
security changes require renewed review. No workflow/permission/trust code changes
are made by this amendment.

## Remaining manual steps before any attempt

1. Review this local amendment. Separately authorize a push and a new protected PR;
   PR #3 is already merged and cannot supply the amendment's final head/check.
   Do not bypass required PR/CODEOWNERS protections to land the record. If independent
   review cannot be obtained, that remains a blocker unless the owner explicitly
   authorizes a separate narrowly scoped accommodation preserving all other controls.
2. Obtain the required passing/up-to-date hosted check for the exact amendment head.
   Record its PR, full head SHA, check URL/conclusion and resulting protected main
   SHA after the separately authorized merge. `amendment_bindings` stays null here;
   neither this commit's own SHA nor a future merge SHA is guessed.
   Capture those post-merge bindings in the owner's execution checklist/audit
   record referencing this immutable approval amendment; do not create a recursive
   sequence of commits merely to embed each commit's own or future merge hash.
3. Confirm both previous enable/review switches are disabled before preparation,
   and prior review accommodations restored. Manually verify effective role inline
   AND attached permissions remain read-only, exact OIDC trust matches the confirmed
   subject/audience/provider, and environment/main rules remain protected. Record
   the permitted environment self-review accommodation and restoration procedure.
   This task does not inspect or alter any of these live settings.
4. Check the approval is unused, unexpired, unrevoked and all security gates pass.
   Only in a separately authorized manual execution session, enable
   `AWS_PLAN_REVIEW_APPROVED` and `AWS_PLAN_ENABLED`, dispatch the workflow on the
   exact reviewed protected main commit, and review its environment request. Do
   not rerun the old failed workflow as a substitute for the reviewed new main.
5. Inspect actual credential exchange, plan exit 0/2, JSON export, Conftest verdict
   and analyzer/report outcomes. Treat failures honestly; do not broaden IAM or
   weaken gates. Keep only sanitized evidence and record the run/consumption outcome.
6. On any terminal outcome or earlier expiry/revocation/security violation, disable
   both variables, restore any authorized review accommodation and record restoration.
   No automatic resource cleanup, state mutation or deployment is authorized.

The record is a governance approval, not a runtime expiry mechanism or an automatic
variable toggle. `execution_readiness` is **BLOCKED_FINAL_AMENDMENT_BINDINGS** and
`execution_status` remains **NOT RUN**. No push, merge, AWS contact, GitHub setting
change, variable enablement or authenticated execution is performed by this task.

## Local amendment validation

The complete offline runner passed against the final source context: **697 Python
tests, zero failures/skips**. Frontend build/privacy checks and **50 tests** passed;
**3 browser checks**, **1 mocked HTTP test** and **8 exporter tests** passed.
Workload/bootstrap formatting, cached backend-free init and validation, TFLint
with AWS ruleset, reviewed CI contract and destructive-command guard passed.
Checkov remained **30 passed / 0 failed / 6 skipped / 0 parsing errors**; exact
exceptions remained expected 6, observed 6, missing 0, unexpected 0. OPA **35 tests**
and Conftest **6 fixtures** passed. Offline Phase 3/4 outputs reproduced byte-for-byte.
Secret scan and diff checks passed. These local checks are not hosted evidence or
AWS authentication verification. No workflow, Terraform, IAM, policy or runtime
service files were changed.
