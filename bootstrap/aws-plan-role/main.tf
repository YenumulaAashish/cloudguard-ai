provider "aws" {
  region = "ap-south-1"
}

resource "aws_iam_role" "plan" {
  name                 = "cloudguard-ai-plan"
  description          = "Read-only Terraform planning for the protected CloudGuard GitHub environment"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = var.github_oidc_provider_arn }
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:YenumulaAashish/cloudguard-ai:environment:aws-plan"
        }
      }
    }]
  })
  tags = {
    Project     = "cloudguard-ai"
    Environment = "bootstrap"
    ManagedBy   = "Terraform"
  }
}

resource "aws_iam_role_policy" "plan_read" {
  name = "cloudguard-sandbox-plan-read"
  role = aws_iam_role.plan.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CallerIdentity"
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity"]
        Resource = "*"
      },
      {
        Sid    = "VpcMetadataInMumbai"
        Effect = "Allow"
        Action = [
          "ec2:DescribeVpcs", "ec2:DescribeVpcAttribute", "ec2:DescribeSubnets",
          "ec2:DescribeInternetGateways", "ec2:DescribeRouteTables",
          "ec2:DescribeSecurityGroups", "ec2:DescribeSecurityGroupRules", "ec2:DescribeTags"
        ]
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = "ap-south-1" } }
      },
      {
        Sid    = "ExactSandboxBucketMetadata"
        Effect = "Allow"
        Action = [
          "s3:ListBucket", "s3:GetBucketLocation", "s3:GetBucketAcl",
          "s3:GetBucketPolicy", "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock",
          "s3:GetEncryptionConfiguration", "s3:GetBucketVersioning", "s3:GetBucketOwnershipControls",
          "s3:GetBucketTagging", "s3:GetLifecycleConfiguration", "s3:GetBucketLogging",
          "s3:GetBucketNotification", "s3:GetReplicationConfiguration", "s3:GetBucketCORS",
          "s3:GetBucketWebsite", "s3:GetBucketRequestPayment", "s3:GetAccelerateConfiguration",
          "s3:GetBucketObjectLockConfiguration"
        ]
        Resource = "arn:aws:s3:::${var.sandbox_bucket_name}"
      }
    ]
  })
}
