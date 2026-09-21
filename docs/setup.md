# Setup and commands

Use Python 3.10+ and install the tools below in the same environment. CI uses Python 3.12 on Ubuntu. Bash/GNU Make is convenient on Linux, macOS or WSL; native Windows can run the portable Python entry points directly. A WSL launcher alone is not a Linux tool installation.

| Tool | Pinned executable version | Official installation source |
|---|---|---|
| Terraform | 1.9.8; both root configurations require exactly 1.9.8 | https://developer.hashicorp.com/terraform/install |
| AWS provider | 6.65.0 in both lock files; constraint ~>6.0 | https://registry.terraform.io/providers/hashicorp/aws/latest |
| TFLint | 0.59.1, AWS ruleset 0.40.0 | https://github.com/terraform-linters/tflint/releases |
| Checkov | 3.2.471 | https://www.checkov.io/2.Basics/Installing%20Checkov.html |
| OPA | 1.0.1, Rego v1 | https://github.com/open-policy-agent/opa/releases |
| Conftest | 0.60.0 | https://github.com/open-policy-agent/conftest/releases |

Executable versions preserve the tested Phase 1 toolchain; they are not claims to be latest. Provider locks were generated from verified provider packages, not invented. Both roots use the same compatible provider selection. Commit both lock files. Review upgrades and resulting checks deliberately; never hardcode Checkov passing counts.

Both provider locks include verified `h1` hashes for `linux_amd64` (hosted CI)
and `windows_amd64` (local development). Keep read-only initialization enabled.
When deliberately updating the provider or adding a platform, generate hashes
with Terraform rather than copying or inventing a checksum:

```sh
terraform -chdir=terraform get
terraform -chdir=terraform providers lock -platform=linux_amd64 -platform=windows_amd64
terraform -chdir=bootstrap/aws-plan-role providers lock -platform=linux_amd64 -platform=windows_amd64
```

The offline runner requests JSON validation diagnostics. Recognized diagnostic
summaries and the provider checksum error are printed in CI; arbitrary messages,
source snippets, expressions and values remain in ignored private logs and are
not uploaded. Unrecognized diagnostics fail the gate and report that their text
was withheld. See [validation-hosted.md](validation-hosted.md) for the reproduced
cross-platform lock failure and verification procedure.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install checkov==3.2.471
tflint --init --config="$PWD/.tflint.hcl"
TFLINT_AWS=1 make test
```

Native Windows, with tools installed on PATH or in the existing ignored local tool directories:

```powershell
$env:TFLINT_AWS = '1'
# If using the locally downloaded plugin:
$env:TFLINT_PLUGIN_DIR = "$PWD/.tools/tflint-plugins"
python scripts/run-offline.py
```

The Python launcher resolves tools on PATH first, then the previously downloaded `.tools/<name>/` or `.tools/` executables and project virtual environment. It contains no user-specific absolute paths. Local core lint can run without the optional AWS plugin using `.tflint-core.hcl`; it reports that AWS lint was NOT RUN. Hosted CI always initializes and requires the AWS plugin.

## Individual safe checks

```sh
terraform fmt -check -recursive terraform
terraform fmt -check -recursive bootstrap
terraform -chdir=terraform init -backend=false -input=false -lockfile=readonly
terraform -chdir=terraform validate
terraform -chdir=bootstrap/aws-plan-role init -backend=false -input=false -lockfile=readonly
terraform -chdir=bootstrap/aws-plan-role validate
TFLINT_AWS=1 bash scripts/lint.sh
python scripts/security-scan.py
python scripts/verify-checkov-exceptions.py
opa test policies
python scripts/policy-test.py
python scripts/verify-no-deployment-ci.py
python -m unittest discover -s tests/unit -v
python scripts/generate-evidence.py
```

`make test` executes the portable offline runner. The unit tests use isolated synthetic data and mocked subprocesses for plan exit handling; they do not contact AWS. Existing fixture files remain unchanged.

## Explicit authenticated commands

Use short-lived SSO/role credentials, copy `terraform/terraform.tfvars.example` to `terraform/terraform.tfvars`, and choose a unique bucket name matching the plan role policy. Region defaults to ap-south-1. Never store credentials in variables.

`make aws-plan`, `make plan`, and `make plan-json` all explicitly require AWS authentication; no generic test target invokes them. `make plan-policy` evaluates an existing real plan file without AWS calls. Planning handles exit 0/2 correctly and never deploys. Local raw logs are in reports/private; values are withheld from console output.

Follow [github-oidc.md](github-oidc.md) for account/provider discovery, reviewed role bootstrap and GitHub configuration. The bootstrap is administrator-controlled, not executable with the plan role. Remote state and deployments require a later design review.

## GitHub action versions

The following stable releases were verified against official release pages during implementation. Workflows use explicit release tags, matching the repository's tag-based approach; future SHA pinning can be reviewed separately. Hosted execution itself remains NOT RUN.

| Action | Selected release | Source |
|---|---|---|
| actions/checkout | v7.0.1 | https://github.com/actions/checkout/releases |
| actions/setup-python | v7.0.0 | https://github.com/actions/setup-python/releases |
| hashicorp/setup-terraform | v4.0.1 | https://github.com/hashicorp/setup-terraform/releases |
| terraform-linters/setup-tflint | v6.3.1 | https://github.com/terraform-linters/setup-tflint/releases |
| open-policy-agent/setup-opa | v2.4.0 | https://github.com/open-policy-agent/setup-opa/releases |
| aws-actions/configure-aws-credentials | v6.3.0 | https://github.com/aws-actions/configure-aws-credentials/releases |
| actions/upload-artifact | v7.0.1 | https://github.com/actions/upload-artifact/releases |

Terraform's action wrapper is disabled so native detailed exit codes are preserved. Use current GitHub-hosted runners for these action runtimes. The shared composite action only installs tools; it requests no AWS credentials.
