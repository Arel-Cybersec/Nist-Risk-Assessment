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

# Object-created events go to EventBridge (also used by GuardDuty Malware Protection)
resource "aws_s3_bucket_notification" "fintech_storage" {
  bucket      = aws_s3_bucket.fintech_storage.id
  eventbridge = true
}

# REMEDIATION NIST-19: Customer-managed KMS key by default (SC-28(1))
resource "aws_s3_bucket_server_side_encryption_configuration" "fintech_storage" {
  bucket = aws_s3_bucket.fintech_storage.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.pii.arn
    }
    bucket_key_enabled = true
  }
}

# REMEDIATION NIST-14: Retention hygiene (MP-6, SI-12)
resource "aws_s3_bucket_lifecycle_configuration" "fintech_storage" {
  bucket = aws_s3_bucket.fintech_storage.id

  rule {
    id     = "expire-transient-uploads"
    status = "Enabled"

    filter {
      prefix = "tmp/"
    }

    expiration {
      days = 7
    }
  }

  rule {
    id     = "expire-old-versions-and-abandoned-uploads"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.fintech_storage]
}

# REMEDIATION NIST-03: Server access logs for every request against the PII bucket (AU-12)
resource "aws_s3_bucket_logging" "fintech_storage" {
  bucket        = aws_s3_bucket.fintech_storage.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3/${aws_s3_bucket.fintech_storage.id}/"
}

# Bucket policy
# - F-01 / NIST-22: only the Terraform-managed application role is granted object reads
# - NIST-02: refuse any request that is not HTTPS with TLS 1.2 or later (SC-8)
# - NIST-16: the application role may only reach the bucket through the VPC endpoint
# - NIST-19: writes may not downgrade encryption; objects under phi/ must use the PHI key
resource "aws_s3_bucket_policy" "restrict_internal_only" {
  bucket = aws_s3_bucket.fintech_storage.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid       = "AllowInternalAppRoleOnly"
          Effect    = "Allow"
          Principal = { AWS = aws_iam_role.fintech_core_app.arn }
          Action    = "s3:GetObject"
          Resource  = "${aws_s3_bucket.fintech_storage.arn}/*"
        },
        {
          Sid       = "DenyAppRoleOutsideVpcEndpoint"
          Effect    = "Deny"
          Principal = { AWS = "*" }
          Action    = "s3:*"
          Resource  = [aws_s3_bucket.fintech_storage.arn, "${aws_s3_bucket.fintech_storage.arn}/*"]
          Condition = {
            StringEquals    = { "aws:PrincipalArn" = aws_iam_role.fintech_core_app.arn }
            StringNotEquals = { "aws:SourceVpce" = aws_vpc_endpoint.s3.id }
          }
        },
        {
          Sid       = "DenyNonKmsEncryption"
          Effect    = "Deny"
          Principal = { AWS = "*" }
          Action    = "s3:PutObject"
          Resource  = "${aws_s3_bucket.fintech_storage.arn}/*"
          Condition = { StringNotEqualsIfExists = { "s3:x-amz-server-side-encryption" = "aws:kms" } }
        },
        {
          Sid       = "DenyForeignKmsKey"
          Effect    = "Deny"
          Principal = { AWS = "*" }
          Action    = "s3:PutObject"
          Resource  = "${aws_s3_bucket.fintech_storage.arn}/*"
          Condition = {
            StringNotEqualsIfExists = {
              "s3:x-amz-server-side-encryption-aws-kms-key-id" = [aws_kms_key.pii.arn, aws_kms_key.phi.arn]
            }
          }
        },
        {
          Sid       = "RequirePhiKeyUnderPhiPrefix"
          Effect    = "Deny"
          Principal = { AWS = "*" }
          Action    = "s3:PutObject"
          Resource  = "${aws_s3_bucket.fintech_storage.arn}/phi/*"
          Condition = {
            StringNotEquals = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.phi.arn }
          }
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
  #checkov:skip=CKV2_AWS_62:Replication target; objects are scanned on arrival in the primary bucket
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

resource "aws_s3_bucket_server_side_encryption_configuration" "fintech_storage_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.fintech_storage_replica.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.replica_pii.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "fintech_storage_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.fintech_storage_replica.id

  rule {
    id     = "expire-old-versions-and-abandoned-uploads"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.fintech_storage_replica]
}

resource "aws_s3_bucket_logging" "fintech_storage_replica" {
  provider      = aws.replica
  bucket        = aws_s3_bucket.fintech_storage_replica.id
  target_bucket = aws_s3_bucket.replica_access_logs.id
  target_prefix = "s3/${aws_s3_bucket.fintech_storage_replica.id}/"
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

# Access logs for the replica must stay in the replica's region
resource "aws_s3_bucket" "replica_access_logs" {
  #checkov:skip=CKV_AWS_145:S3 server access logs can only be delivered to SSE-S3 buckets
  #checkov:skip=CKV_AWS_144:This bucket already lives in the secondary region and holds only request logs
  #checkov:skip=CKV2_AWS_62:Log delivery bucket; nothing consumes object-created events
  provider = aws.replica
  bucket   = "simulated-fintech-access-logs-2026-replica"

  tags = {
    Environment = "Production"
    DataClass   = "Audit"
  }
}

resource "aws_s3_bucket_public_access_block" "replica_access_logs" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica_access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "replica_access_logs" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica_access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "replica_access_logs" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica_access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "replica_access_logs" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica_access_logs.id

  rule {
    id     = "retain-request-logs-400-days"
    status = "Enabled"

    filter {}

    expiration {
      days = 400
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.replica_access_logs]
}

resource "aws_s3_bucket_policy" "replica_access_logs" {
  provider = aws.replica
  bucket   = aws_s3_bucket.replica_access_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "S3ServerAccessLogDelivery"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.replica_access_logs.arn}/s3/*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
          ArnLike      = { "aws:SourceArn" = aws_s3_bucket.fintech_storage_replica.arn }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.replica_access_logs.arn, "${aws_s3_bucket.replica_access_logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.replica_access_logs]
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
      },
      {
        Sid       = "DecryptSourceObjects"
        Effect    = "Allow"
        Action    = "kms:Decrypt"
        Resource  = [aws_kms_key.pii.arn, aws_kms_key.phi.arn]
        Condition = { StringEquals = { "kms:ViaService" = local.s3_via_primary } }
      },
      {
        Sid       = "EncryptReplicaObjects"
        Effect    = "Allow"
        Action    = ["kms:Encrypt", "kms:GenerateDataKey"]
        Resource  = [aws_kms_key.replica_pii.arn, aws_kms_key.replica_phi.arn]
        Condition = { StringEquals = { "kms:ViaService" = local.s3_via_replica } }
      }
    ]
  })
}

# PHI and PII keep separate keys in the replica too: the higher-priority phi/ rule wins
resource "aws_s3_bucket_replication_configuration" "fintech_storage" {
  bucket = aws_s3_bucket.fintech_storage.id
  role   = aws_iam_role.s3_replication.arn

  rule {
    id       = "replicate-phi-with-phi-key"
    priority = 2
    status   = "Enabled"

    filter {
      prefix = "phi/"
    }

    delete_marker_replication {
      status = "Enabled"
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket        = aws_s3_bucket.fintech_storage_replica.arn
      storage_class = "STANDARD_IA"

      encryption_configuration {
        replica_kms_key_id = aws_kms_key.replica_phi.arn
      }
    }
  }

  rule {
    id       = "replicate-all-to-secondary-region"
    priority = 1
    status   = "Enabled"

    filter {}

    delete_marker_replication {
      status = "Enabled"
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket        = aws_s3_bucket.fintech_storage_replica.arn
      storage_class = "STANDARD_IA"

      encryption_configuration {
        replica_kms_key_id = aws_kms_key.replica_pii.arn
      }
    }
  }

  # Both sides must have versioning enabled before replication can be configured
  depends_on = [
    aws_s3_bucket_versioning.fintech_storage,
    aws_s3_bucket_versioning.fintech_storage_replica
  ]
}
