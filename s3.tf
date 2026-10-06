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

# REMEDIATION NIST-06: Versioning so overwrites and deletes are recoverable (CP-9)
resource "aws_s3_bucket_versioning" "fintech_storage" {
  bucket = aws_s3_bucket.fintech_storage.id

  versioning_configuration {
    status = "Enabled"
  }
}

# REMEDIATION NIST-03: Server access logs for every request against the PII bucket (AU-12)
resource "aws_s3_bucket_logging" "fintech_storage" {
  bucket        = aws_s3_bucket.fintech_storage.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3/${aws_s3_bucket.fintech_storage.id}/"
}

# Secure Bucket Policy: Restricting access to a specific internal IAM Role instead of "*"
# REMEDIATION NIST-02: Refuse any request that is not HTTPS with TLS 1.2 or later (SC-8)
resource "aws_s3_bucket_policy" "restrict_internal_only" {
  bucket = aws_s3_bucket.fintech_storage.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "AllowInternalAppRoleOnly"
          Effect = "Allow"
          Principal = {
            AWS = "arn:aws:iam::123456789012:role/FinTechCoreAppRole"
          }
          Action   = "s3:GetObject"
          Resource = "${aws_s3_bucket.fintech_storage.arn}/*"
        }
      ],
      local.pii_tls_only_statements
    )
  })

  depends_on = [aws_s3_bucket_public_access_block.secure_block]
}

locals {
  pii_tls_only_statements = [
    {
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = { AWS = "*" }
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.fintech_storage.arn, "${aws_s3_bucket.fintech_storage.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    },
    {
      Sid       = "DenyOutdatedTLS"
      Effect    = "Deny"
      Principal = { AWS = "*" }
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.fintech_storage.arn, "${aws_s3_bucket.fintech_storage.arn}/*"]
      Condition = { NumericLessThan = { "s3:TlsVersion" = "1.2" } }
    }
  ]
}

# ── Cross-region replica (REMEDIATION NIST-06: CP-6 alternate storage site) ──

resource "aws_s3_bucket" "fintech_storage_replica" {
  provider = aws.replica
  bucket   = "simulated-fintech-customer-data-2026-replica"

  tags = {
    Environment = "Production"
    DataClass   = "PII-PHI"
    Role        = "replica"
  }
}

resource "aws_s3_bucket_public_access_block" "fintech_storage_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.fintech_storage_replica.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "fintech_storage_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.fintech_storage_replica.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "fintech_storage_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.fintech_storage_replica.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.fintech_storage_replica.arn, "${aws_s3_bucket.fintech_storage_replica.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyOutdatedTLS"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.fintech_storage_replica.arn, "${aws_s3_bucket.fintech_storage_replica.arn}/*"]
        Condition = { NumericLessThan = { "s3:TlsVersion" = "1.2" } }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.fintech_storage_replica]
}

resource "aws_iam_role" "s3_replication" {
  name = "FinTech-S3-Replication"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "sts:AssumeRole"
        Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
      }
    ]
  })
}

resource "aws_iam_role_policy" "s3_replication" {
  name = "ReplicatePiiBucket"
  role = aws_iam_role.s3_replication.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadSourceConfiguration"
        Effect   = "Allow"
        Action   = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
        Resource = aws_s3_bucket.fintech_storage.arn
      },
      {
        Sid      = "ReadSourceObjectVersions"
        Effect   = "Allow"
        Action   = ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging"]
        Resource = "${aws_s3_bucket.fintech_storage.arn}/*"
      },
      {
        Sid      = "WriteReplicaObjects"
        Effect   = "Allow"
        Action   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"]
        Resource = "${aws_s3_bucket.fintech_storage_replica.arn}/*"
      }
    ]
  })
}

resource "aws_s3_bucket_replication_configuration" "fintech_storage" {
  bucket = aws_s3_bucket.fintech_storage.id
  role   = aws_iam_role.s3_replication.arn

  rule {
    id     = "replicate-all-to-secondary-region"
    status = "Enabled"

    filter {}

    delete_marker_replication {
      status = "Enabled"
    }

    destination {
      bucket        = aws_s3_bucket.fintech_storage_replica.arn
      storage_class = "STANDARD_IA"
    }
  }

  # Both sides must have versioning enabled before replication can be configured
  depends_on = [
    aws_s3_bucket_versioning.fintech_storage,
    aws_s3_bucket_versioning.fintech_storage_replica
  ]
}
