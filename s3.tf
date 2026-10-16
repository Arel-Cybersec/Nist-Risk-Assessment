data "aws_caller_identity" "current" {}

# REMEDIATION F-03: Customer-managed KMS key with rotation for data at rest (SC-12, SC-28).
resource "aws_kms_key" "data" {
  description             = "Encrypts FinTech customer data, CloudTrail and CloudWatch logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudTrailEncrypt"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt", "kms:DescribeKey"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
      },
      {
        Sid       = "AllowEventBridgeToEncryptedTopics"
        Effect    = "Allow"
        Principal = { Service = ["events.amazonaws.com", "config.amazonaws.com"] }
        Action    = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
      },
      {
        Sid       = "AllowCloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "data" {
  name          = "alias/fintech-data"
  target_key_id = aws_kms_key.data.key_id
}

# ── Customer data bucket ─────────────────────────────────────────────
resource "aws_s3_bucket" "fintech_storage" {
  #checkov:skip=CKV_AWS_144:Cross-region replication is a DR decision outside this assessment's scope
  #checkov:skip=CKV2_AWS_62:Event notifications are not required by any finding in the risk register
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

# ACLs disabled: the bucket owner owns every object
resource "aws_s3_bucket_ownership_controls" "fintech_storage" {
  bucket = aws_s3_bucket.fintech_storage.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# REMEDIATION F-03: SSE-KMS encryption and versioning
resource "aws_s3_bucket_server_side_encryption_configuration" "fintech_storage" {
  bucket = aws_s3_bucket.fintech_storage.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "fintech_storage" {
  bucket = aws_s3_bucket.fintech_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "fintech_storage" {
  bucket = aws_s3_bucket.fintech_storage.id
  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# REMEDIATION F-04: Server access logging
resource "aws_s3_bucket_logging" "fintech_storage" {
  bucket        = aws_s3_bucket.fintech_storage.id
  target_bucket = aws_s3_bucket.audit_logs.id
  target_prefix = "s3-access/fintech-storage/"
}

# Secure Bucket Policy: only the internal app role, and only over TLS (F-01, F-05)
resource "aws_s3_bucket_policy" "restrict_internal_only" {
  bucket     = aws_s3_bucket.fintech_storage.id
  depends_on = [aws_s3_bucket_public_access_block.secure_block]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowInternalAppRoleOnly"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.app_role.arn }
        Action    = ["s3:GetObject", "s3:PutObject"]
        Resource  = "${aws_s3_bucket.fintech_storage.arn}/*"
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.fintech_storage.arn, "${aws_s3_bucket.fintech_storage.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

# ── Audit log bucket (S3 access logs + CloudTrail) ───────────────────
resource "aws_s3_bucket" "audit_logs" {
  #checkov:skip=CKV_AWS_18:This is the log destination; logging it to itself would loop
  #checkov:skip=CKV_AWS_144:Cross-region replication is a DR decision outside this assessment's scope
  #checkov:skip=CKV_AWS_145:S3 server access log delivery only supports SSE-S3 on the target bucket
  #checkov:skip=CKV2_AWS_62:Event notifications are not required by any finding in the risk register
  bucket = "simulated-fintech-audit-logs-2026"

  tags = {
    Environment = "Production"
    DataClass   = "Audit"
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    id     = "retain-then-archive"
    status = "Enabled"
    filter {}
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    expiration {
      days = var.log_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "audit_logs" {
  bucket     = aws_s3_bucket.audit_logs.id
  depends_on = [aws_s3_bucket_public_access_block.audit_logs]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "S3ServerAccessLogs"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.audit_logs.arn}/s3-access/*"
        Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
      },
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.audit_logs.arn
      },
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.audit_logs.arn}/cloudtrail/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
      },
      {
        Sid       = "ConfigAclCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource  = aws_s3_bucket.audit_logs.arn
        Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
      },
      {
        Sid       = "ConfigWrite"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.audit_logs.arn}/config/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
        Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.audit_logs.arn, "${aws_s3_bucket.audit_logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}
