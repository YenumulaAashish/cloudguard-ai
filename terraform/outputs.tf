output "vpc_id" {
  description = "Sandbox VPC identifier."
  value       = module.network.vpc_id
}
output "bucket_id" {
  description = "Private sandbox bucket identifier."
  value       = module.storage.bucket_id
}

output "compute_enabled" {
  description = "Confirms compute remains disabled in the Phase 1 sandbox."
  value       = var.enable_ec2
}
