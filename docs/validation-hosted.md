# Hosted validation checksum failure

On 2026-09-21, hosted run 35578453622 at commit
`256f668ff6aff240b003ee04b25daa1c63c6bc03` passed initialization but failed
validation for both Terraform roots. The original runner did not publish the
private validation logs, so the historical hosted diagnostic cannot be recovered
from the public job log.

The failure was reproduced for both roots on Linux x86-64 using the committed
source and locks, checksum-verified Terraform 1.9.8 and registry-signed AWS
provider 6.65.0. Initialization used `-backend=false -input=false -lockfile=readonly`.
It succeeded with `Warning: Provider lock file not updated`. Both subsequent
`terraform validate -no-color` commands produced exactly:

```text
Error: registry.terraform.io/hashicorp/aws: the cached package for registry.terraform.io/hashicorp/aws 6.65.0 (in .terraform/providers) does not match any of the checksums recorded in the dependency lock file
```

Windows validation passed with the same versions. The committed lock files had
the Windows package's `h1` hash and signed archive `zh` hashes, but no Linux
package `h1` hash. Read-only initialization could verify the downloaded archive
but could not record the Linux package hash needed by subsequent validation.

The fix adds Terraform-generated, registry-verified Linux hashes to both locks.
It retains the Windows hash, all archive hashes, AWS provider 6.65.0 and Terraform
1.9.8. Both roots now require exactly Terraform 1.9.8, matching CI. No resources,
Checkov exceptions or policies were changed.

Verification: initialize both roots read-only and validate on Linux and Windows;
run the complete offline suite with the AWS TFLint plugin enabled. The next
GitHub-hosted execution is still required after the user commits and pushes;
local Linux verification is not a claim that hosted CI was rerun.
