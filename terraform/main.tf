locals {
  name = "${var.project_name}-${var.environment}"
  tags = merge(var.required_tags, {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  })
}
module "network" {
  source = "./modules/network"
  name   = local.name
  tags   = local.tags
}
module "security" {
  source            = "./modules/security"
  name              = local.name
  vpc_id            = module.network.vpc_id
  allowed_ssh_cidrs = var.allowed_ssh_cidrs
  tags              = local.tags
}
module "storage" {
  source      = "./modules/storage"
  bucket_name = var.bucket_name
  tags        = local.tags
}
