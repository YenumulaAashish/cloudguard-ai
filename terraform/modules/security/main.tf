resource "aws_security_group" "this" {
  #checkov:skip=CKV2_AWS_5:Standalone sandbox guardrail; no compute is permitted in Phase 1. See docs/security-exceptions.md.
  name_prefix = "${var.name}-"
  description = "Sandbox default deny; optional trusted SSH only"
  vpc_id      = var.vpc_id
  # Manage the complete rule set so an initial plan has no unknown ingress.
  ingress = [for cidr in var.allowed_ssh_cidrs : {
    description      = "SSH from explicitly trusted network"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = [cidr]
    ipv6_cidr_blocks = []
    prefix_list_ids  = []
    security_groups  = []
    self             = false
  }]
  egress = []
  tags   = merge(var.tags, { Name = var.name })
}
