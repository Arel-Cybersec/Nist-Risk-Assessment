# REMEDIATION F-12: Customer data survives the loss of a whole region.
# Objects replicate to a second region within minutes (S3 CRR), and daily backups are copied
# there too (backup.tf). Compute is rebuilt from Terraform in either region.
# (RC.RP-02, RC.RP-03, ID.AM-08; SP 800-53 CP-6, CP-9, CP-10)

resource "aws_kms_key" "dr" {
  provider                = aws.dr
  description             = "Encrypts replicated customer data and backup copies in the DR region"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountAdministration"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}

resource "aws_s3_bucket" "replica" {
  provider = aws.dr
  #checkov:skip=CKV_AWS_18:Replica only receives writes from S3 replication; object access is recorded by CloudTrail data events (logging.tf)
  #checkov:skip=CKV_AWS_144:This is the replication destination
  #checkov:skip=CKV2_AWS_62:Event notifications are not required by any finding in the risk register
  bucket = "simulated-fintech-customer-data-2026-dr"

  tags = {
    Environment = "Production"
    DataClass   = "PII-PHI"
    Role        = "DR-Replica"
  }
}

resource "aws_s3_bucket_public_access_block" "replica" {
  provider = aws.dr
  bucket   = aws_s3_bucket.replica.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "replica" {
  provider = aws.dr
  bucket   = aws_s3_bucket.replica.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "replica" {
  provider = aws.dr
  bucket   = aws_s3_bucket.replica.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "replica" {
  provider = aws.dr
  bucket   = aws_s3_bucket.replica.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.dr.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "replica" {
  provider = aws.dr
  bucket   = aws_s3_bucket.replica.id
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

resource "aws_s3_bucket_policy" "replica" {
  provider   = aws.dr
  bucket     = aws_s3_bucket.replica.id
  depends_on = [aws_s3_bucket_public_access_block.replica]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.replica.arn, "${aws_s3_bucket.replica.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# ── Replication ──────────────────────────────────────────────────────
resource "aws_iam_role" "replication" {
  name = "FinTechS3Replication"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "replication" {
  name = "ReplicateCustomerData"
  role = aws_iam_role.replication.id

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
        Sid      = "ReadSourceVersions"
        Effect   = "Allow"
        Action   = ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging"]
        Resource = "${aws_s3_bucket.fintech_storage.arn}/*"
      },
      {
        Sid      = "WriteReplica"
        Effect   = "Allow"
        Action   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"]
        Resource = "${aws_s3_bucket.replica.arn}/*"
      },
      {
        Sid      = "DecryptSource"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = aws_kms_key.data.arn
      },
      {
        Sid      = "EncryptReplica"
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.dr.arn
      }
    ]
  })
}

resource "aws_s3_bucket_replication_configuration" "fintech_storage" {
  bucket     = aws_s3_bucket.fintech_storage.id
  role       = aws_iam_role.replication.arn
  depends_on = [aws_s3_bucket_versioning.fintech_storage, aws_s3_bucket_versioning.replica]

  rule {
    id     = "replicate-all-to-dr"
    status = "Enabled"
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
      bucket        = aws_s3_bucket.replica.arn
      storage_class = "STANDARD"

      encryption_configuration {
        replica_kms_key_id = aws_kms_key.dr.arn
      }
    }
  }
}
