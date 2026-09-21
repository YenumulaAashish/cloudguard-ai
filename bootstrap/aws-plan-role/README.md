# Plan-role bootstrap (code only)

This isolated Terraform root creates one read-only plan role and its inline policy. It accepts an existing GitHub OIDC provider ARN and exact sandbox bucket name. It creates no OIDC provider, VPC, bucket or compute resource. It is never automatically applied or included in workload planning.

Offline CI validates its Terraform syntax. An administrator must separately review and authorize provisioning it. The plan role cannot provision itself. Follow [the OIDC setup instructions](../../docs/github-oidc.md) for discovery, trust/environment protections, permissions and configuration order.

The dummy account number in terraform.tfvars.example is a placeholder, not a real account selection. Bootstrap state is sensitive and ignored; keep it in protected storage.
