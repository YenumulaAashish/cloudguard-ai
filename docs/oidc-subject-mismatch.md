# OIDC subject mismatch — failed attempt and retry handoff

The first authenticated workflow [run 45469018350](https://github.com/YenumulaAashish/cloudguard-ai/actions/runs/45469018350)
failed at `sts:AssumeRoleWithWebIdentity` with **AccessDenied**. The owner supplied
CloudTrail confirmation that GitHub's actual subject for this repository/environment is:

```text
repo:YenumulaAashish@212769106/cloudguard-ai@1379194368:environment:aws-plan
```

The bootstrap previously expected the name-only subject without the two `@ID`
suffixes. Exact `StringEquals` could not match those distinct strings. This is the
confirmed mismatch; no claim is made about which GitHub setting or feature caused
that subject format. Do not assume a universal subject template or derive this
subject from `github.repository`. The workflow's ordinary repository/ref guards
still correctly use `YenumulaAashish/cloudguard-ai` and protected `main`.

The owner reports the live IAM trust policy was already manually corrected
successfully. This task updates the bootstrap source to match that correction; it
does not contact AWS, inspect CloudTrail, edit IAM or run bootstrap provisioning.
Successful STS authentication and real planning after correction remain **NOT RUN**
by this task. Updating a trust policy successfully is not a successful token exchange.

The condition stays exact and case-sensitive: `StringEquals` for both the complete
subject and audience `sts.amazonaws.com`. The existing GitHub provider principal,
protected `aws-plan` environment, main-only manual dispatch, enable/review gates,
and read-only IAM policy remain unchanged. No wildcard subject, `StringLike`,
alternate audience, broad permissions or new trust principal is introduced.
The reviewed CI contract now pins the entire bootstrap role/policy file; negative
tests reject subject/audience/operator/environment and permission changes.

## Approval status

`CG-SM-PLAN-001` is **CONSUMED**, regardless of its historical expiry. The failed
authentication attempt used its single run; no successful plan is required to
consume it. Its [original record](../security/maintainer-planning-exception.json)
retains the original date, scope and approval evidence and records this failed run.
The old activity flags describe the original recording task, not the later AWS
workflow. No retry is granted by its historical 2026-12-01T18:30:00Z cutoff.

The owner subsequently approved **CG-SM-PLAN-002** on **2026-11-25**, with
expiry **2026-12-01T18:30:00Z** or earlier on any terminal outcome, revocation or
security violation. The status is **APPROVED_RESTRICTED_SCOPE**, for exactly one
read-only sandbox planning attempt; execution remains **NOT RUN**. Only environment
self-review is approved. See [the current approval and evidence handoff](plan-002-approval.md)
and [record](../security/maintainer-planning-exception-002.json). The fix and PR #3
merge SHAs are resolved, but this new approval-record amendment still needs its
own protected PR, hosted check and final main binding before execution. No prior
independent PR/CODEOWNERS waiver is carried forward.

## Remaining manual actions

1. Review the new branch/diff and separately authorize pushing and opening its PR.
   Wait for required up-to-date hosted checks for the final fix commit. Nothing is
   pushed or merged by this task; new hosted validation is NOT RUN.
2. Confirm the previous enable/review switches are disabled and any prior temporary
   review-setting accommodations are restored. This task does not inspect or toggle
   them. Preserve main protection, required PRs/checks, CODEOWNERS and exact trust.
3. CG-SM-PLAN-002 is now explicitly approved. Complete the additional amendment
   PR/check/main bindings and live protection/permission verification described in
   the current handoff. Do not guess missing evidence or carry over the old approval.
4. Before a separately authorized retry, manually confirm the already-corrected
   trust matches the exact subject/audience and provider principal, and that inline
   AND attached IAM policies remain read-only and narrowly scoped. The code change
   does not authorize another IAM edit, bootstrap provisioning or permission expansion.
5. Only under that valid, unused approval and completed prerequisites, follow the existing manual enable/dispatch review
   procedure on protected main. Inspect actual credential-action, plan, Conftest and
   analyzer outcomes; retain only sanitized evidence. A denial stays a failure.
6. After the attempt or earlier revocation/expiry, disable both planning variables,
   restore any authorized review accommodations and record run/restoration evidence.

Phase 6 remains design-only. No infrastructure execution is part of this fix.

## Executed local validation

- Complete offline runner: PASS; **694 Python tests, zero failures/skips**, including
  six new exact-subject/consumption tests and one new frozen-bootstrap mutation test.
- Terraform workload and bootstrap: formatting, cached backend-free init and validate
  PASS; TFLint including the AWS ruleset PASS.
- Checkov: **30 passed / 0 failed / 6 skipped / 0 parsing errors**. Exact exceptions:
  expected 6, observed 6, missing 0, unexpected 0. OPA **35 tests**, Conftest **6 fixtures** PASS.
- Frontend production build, privacy checks and **50 tests** PASS; **3 Chrome browser
  checks**, **1 mocked backend HTTP test** and **8 exporter tests** PASS.
- Reviewed CI and destructive-command guards PASS. Offline Phase 3/4 integrated
  private/public bundles reproduce byte-for-byte. Secret scan and diff checks PASS.
- New hosted checks, AWS inspection, token exchange and post-correction real plan:
  **NOT RUN**. No enable variables, settings, AWS resources or permissions changed.

Repository audit: the obsolete full subject occurred only in bootstrap source and
the current OIDC guide; both are corrected. No obsolete full subject remains in
tracked files. Ordinary repository-name guards and historical checkpoint evidence
are retained intentionally. The bootstrap diff changes only the subject literal;
the entire read-only policy and provider principal are unchanged.
