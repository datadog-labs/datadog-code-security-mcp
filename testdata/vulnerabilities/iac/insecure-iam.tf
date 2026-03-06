# Terraform configuration with overly permissive IAM policies
# This file demonstrates IAM misconfigurations for E2E testing

# VULNERABLE: IAM policy with wildcard actions and resources
resource "aws_iam_policy" "admin_everything" {
  name        = "admin-everything"
  description = "Full admin access to everything"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "FullAdmin"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
    ]
  })
}

# VULNERABLE: IAM role with overly broad assume role policy
resource "aws_iam_role" "overly_permissive" {
  name = "overly-permissive-role"

  # VULNERABLE: Any AWS account can assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = "sts:AssumeRole"
      },
    ]
  })
}

# VULNERABLE: IAM user with inline policy granting full S3 access
resource "aws_iam_user_policy" "full_s3_access" {
  name = "full-s3-access"
  user = "data-engineer"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "*"
      },
    ]
  })
}

# VULNERABLE: IAM policy allowing privilege escalation
resource "aws_iam_policy" "privilege_escalation" {
  name        = "escalation-risk"
  description = "Policy that allows privilege escalation"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:CreateUser",
          "iam:CreateRole",
          "iam:AttachUserPolicy",
          "iam:AttachRolePolicy",
          "iam:PutUserPolicy",
          "iam:PutRolePolicy",
        ]
        Resource = "*"
      },
    ]
  })
}
