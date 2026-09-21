variable "project_name" {
  description = "Lowercase project name used in resource names and tags."
  type        = string
  default     = "cloudguard-ai"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}$", var.project_name))
    error_message = "Use 3-31 lowercase letters, digits or hyphens, starting with a letter."
  }
}
variable "environment" {
  description = "Sandbox environment identifier."
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "test", "staging"], var.environment)
    error_message = "Choose dev, test or staging."
  }
}
variable "aws_region" {
  description = "AWS region for the sandbox."
  type        = string
  default     = "ap-south-1"
}
variable "allowed_ssh_cidrs" {
  description = "Trusted IPv4 SSH ranges; empty disables SSH. World access is forbidden."
  type        = set(string)
  default     = []
  validation {
    condition     = alltrue([for cidr in var.allowed_ssh_cidrs : can(cidrnetmask(cidr)) && !endswith(cidr, "/0")])
    error_message = "Supply valid IPv4 CIDRs narrower than /0."
  }
}
variable "required_tags" {
  description = "Additional organization tags; baseline tags cannot be overridden."
  type        = map(string)
  default     = {}
}
variable "enable_ec2" {
  description = "Reserved for a future explicitly reviewed compute module; Phase 1 requires false."
  type        = bool
  default     = false
  validation {
    condition     = !var.enable_ec2
    error_message = "EC2 is not implemented in Phase 1. Keep enable_ec2=false."
  }
}
variable "bucket_name" {
  description = "Globally unique S3 name. Replace the example before any authenticated plan."
  type        = string
  default     = "cloudguard-ai-example-change-me"
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "Use a 3-63 character lowercase DNS-safe bucket name without dots."
  }
}
