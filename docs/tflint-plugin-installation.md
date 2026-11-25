# TFLint AWS plugin setup: GitHub API rate limiting

Owner-provided evidence: PR #6, workflow run 45671023523 failed twice in setup-tools
while installing AWS ruleset 0.40.0. The error was HTTP 403 API rate limit exceeded;
the second attempt reported 44m39s until reset. Phase 3 reporting subsequently lacked
its prerequisites because setup never completed. That is not evidence of a new
policy violation or a reason to ignore the setup failure. Run logs were not fetched
or independently re-executed by this task.

## Root cause and narrow correction

The composite action called tflint --init without GITHUB_TOKEN. TFLint 0.59.1
uses the GitHub API to resolve the pinned plugin release. Anonymous requests share
an IP quota on hosted runners, so another tenant can exhaust it even when this
repository makes few requests. Upstream documents this exact failure mode and the
[built-in job-token solution](https://github.com/terraform-linters/tflint/blob/v0.59.1/docs/user-guide/plugins.md#avoiding-rate-limiting).

The action now separates Checkov installation from plugin installation and supplies
GITHUB_TOKEN from github.token only to the plugin-install step. A missing/empty
token fails before the installer; there is no anonymous fallback, rate-limit sleep,
personal token, new cache or failure-masking retry. Nothing prints the token or
passes it as a command-line argument. Pip and subsequent composite steps do not
receive this explicitly exported token.

No workflow permission changes are needed. The offline workflow remains contents:
read with no AWS credentials, OIDC write permission or paid AI access. Fork PRs use
the normal restricted GitHub job token; no privileged PR trigger or secret is added.
The protected planning workflow retains its existing permissions and eligibility.
A GitHub release-download token is not an AWS credential.

TFLint remains 0.59.1; the AWS ruleset remains 0.40.0 from the same exact source in
.tflint.hcl. All other versions are unchanged. Native tflint --init is retained,
including its release checksum and existing signature/attestation verification
behavior. No manual unverified archive extraction or verification flag is added.
The pinned [upstream installer implementation](https://github.com/terraform-linters/tflint/blob/v0.59.1/plugin/install.go)
checks downloaded archives against release checksums before extraction. This fix
does not strengthen optional upstream verification modes or claim cached binaries
were freshly downloaded or reverified.

## Verification and remaining limitations

Regression tests check step-only token scope, unchanged read-only offline permissions,
pinned source/version and exact native command. Bash tests use a synthetic token
and stub installer to check argument quoting, environment propagation, no token
printing, missing/empty-token rejection and nonzero installer error propagation.
The CI contract rejects missing/replaced tokens or moving the token to a broader
scope. Only the reviewed setup-action fingerprint changes; other security contract
hashes stay unchanged.

An authenticated quota is finite; revoked tokens, GitHub outages or repository-local
quota exhaustion still fail the setup step. This change addresses shared anonymous
rate limiting, not arbitrary future network failures. No PAT or broader permissions
should be added to work around them.

The actual GitHub-hosted authenticated installation is NOT RUN locally: no real job
token was requested or used. Local TFLint validation uses the existing cached AWS
plugin. After the owner pushes the local commit to PR #6, rerun the required hosted
offline workflow and confirm setup, plugin version, all gates and Phase 3 reporting.
No push, merge, AWS call, planning-variable change or authorization activation is
performed by this task.

## Executed local results

- Full offline runner: PASS; current source fingerprint matches final evidence.
- Python: 767 tests PASS, including 95 CI-security tests and six new plugin cases.
- Workload/bootstrap Terraform format, backend-free init and validate: PASS.
- TFLint 0.59.1 with cached AWS ruleset 0.40.0: PASS.
- Checkov: 30 passed / 0 failed / 6 skipped / 0 parsing errors.
- Exception verification: six expected/observed; none missing or unexpected.
- OPA: 40 tests PASS; Conftest: ten expected fixture outcomes PASS.
- Reviewed CI contract, destructive-command guard and secret scan: PASS.
- Real GitHub-hosted authenticated plugin installation: NOT RUN.

Only setup in the CI contract's expected fingerprints changed. Workflow permission
blocks, tool version declarations, AWS configuration, policies and six accepted
exceptions remain unchanged. Frontend files are unchanged by this fix.
