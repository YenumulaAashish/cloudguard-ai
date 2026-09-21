output "aws_plan_role_arn" {
  description = "Set as the GitHub AWS_PLAN_ROLE_ARN repository variable after separately approved bootstrap."
  value       = aws_iam_role.plan.arn
}
