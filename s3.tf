# Create the Secure FinTech Data Bucket
resource "aws_s3_bucket" "fintech_storage" {
  bucket = "simulated-fintech-customer-data-2026"

  tags = {
    Environment = "Production"
    DataClass   = "PII-PHI"
  }
}

# REMEDIATION F-01: Explicitly enabling ALL Public Access Blocks
resource "aws_s3_bucket_public_access_block" "secure_block" {
  bucket = aws_s3_bucket.fintech_storage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Secure Bucket Policy: Restricting access to a specific internal IAM Role instead of "*"
resource "aws_s3_bucket_policy" "restrict_internal_only" {
  bucket = aws_s3_bucket.fintech_storage.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowInternalAppRoleOnly"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:role/FinTechCoreAppRole"
        }
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.fintech_storage.arn}/*"
      }
    ]
  })
}