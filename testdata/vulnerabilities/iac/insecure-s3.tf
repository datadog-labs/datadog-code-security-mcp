# Terraform configuration with insecure S3 bucket settings
# This file demonstrates common IaC misconfigurations for E2E testing

# VULNERABLE: S3 bucket with public access enabled
resource "aws_s3_bucket" "public_data" {
  bucket = "my-public-data-bucket"

  tags = {
    Environment = "production"
    Team        = "data-engineering"
  }
}

# VULNERABLE: ACL granting public read access
resource "aws_s3_bucket_acl" "public_data_acl" {
  bucket = aws_s3_bucket.public_data.id
  acl    = "public-read"
}

# VULNERABLE: No server-side encryption configured
resource "aws_s3_bucket_versioning" "public_data_versioning" {
  bucket = aws_s3_bucket.public_data.id
  versioning_configuration {
    status = "Disabled"
  }
}

# VULNERABLE: Bucket policy allows public access
resource "aws_s3_bucket_policy" "public_data_policy" {
  bucket = aws_s3_bucket.public_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.public_data.arn}/*"
      },
    ]
  })
}

# VULNERABLE: S3 bucket without logging enabled
resource "aws_s3_bucket" "no_logging" {
  bucket = "my-unlogged-bucket"
}

# VULNERABLE: S3 bucket without encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "weak_encryption" {
  bucket = aws_s3_bucket.public_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = false
  }
}
