variable "github_oidc_provider_arn" {
  description = "Existing account OIDC provider ARN; this module never creates an OIDC provider."
  type        = string
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:oidc-provider/token.actions.githubusercontent.com$", var.github_oidc_provider_arn))
    error_message = "Use the existing GitHub OIDC provider ARN in the intended AWS account."
  }
}
variable "sandbox_bucket_name" {
  description = "Exact sandbox bucket name allowed for read-only metadata access; must match the root configuration."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.sandbox_bucket_name))
    error_message = "Provide the exact DNS-safe bucket name without wildcards."
  }
}
