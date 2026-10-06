# REMEDIATION NIST-06: Point-in-time backups of the PII bucket in a locked vault (CP-9, CP-10)

resource "aws_kms_key" "backup" {
  description             = "Encrypts recovery points in the FinTech backup vault"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "KeyAdministrationOnly"
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
        Action    = local.key_admin_actions
        Resource  = "*"
      },
      {
        Sid       = "BackupServiceUse"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.backup.arn }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = { StringEquals = { "kms:ViaService" = "backup.${var.aws_region}.amazonaws.com" } }
      },
      {
        Sid       = "AccountCreatesBackupGrants"
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
        Action    = "kms:CreateGrant"
        Resource  = "*"
        Condition = {
          Bool         = { "kms:GrantIsForAWSResource" = "true" }
          StringEquals = { "kms:ViaService" = "backup.${var.aws_region}.amazonaws.com" }
        }
      },
      {
        Sid       = "BackupServiceGrants"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.backup.arn }
        Action    = "kms:CreateGrant"
        Resource  = "*"
        Condition = { Bool = { "kms:GrantIsForAWSResource" = "true" } }
      }
    ]
  })
}

resource "aws_kms_alias" "backup" {
  name          = "alias/fintech-backup"
  target_key_id = aws_kms_key.backup.key_id
}

resource "aws_backup_vault" "fintech" {
  name        = "fintech-backup-vault"
  kms_key_arn = aws_kms_key.backup.arn
}

# Recovery points cannot be deleted early, even by administrators, which protects against ransomware
resource "aws_backup_vault_lock_configuration" "fintech" {
  backup_vault_name  = aws_backup_vault.fintech.name
  min_retention_days = 7
  max_retention_days = 365
}

resource "aws_backup_plan" "fintech" {
  name = "fintech-daily"

  rule {
    rule_name         = "daily-35-day-retention"
    target_vault_name = aws_backup_vault.fintech.name
    schedule          = "cron(0 5 * * ? *)"

    lifecycle {
      delete_after = 35
    }
  }
}

resource "aws_iam_role" "backup" {
  name = "FinTech-AWS-Backup"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "backup.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  for_each = toset([
    "service-role/AWSBackupServiceRolePolicyForBackup",
    "service-role/AWSBackupServiceRolePolicyForRestores",
    "AWSBackupServiceRolePolicyForS3Backup",
    "AWSBackupServiceRolePolicyForS3Restore",
  ])

  role       = aws_iam_role.backup.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/${each.value}"
}

resource "aws_backup_selection" "pii_bucket" {
  name         = "pii-bucket"
  plan_id      = aws_backup_plan.fintech.id
  iam_role_arn = aws_iam_role.backup.arn
  resources    = [aws_s3_bucket.fintech_storage.arn]

  # AWS Backup for S3 requires versioning on the source bucket
  depends_on = [aws_s3_bucket_versioning.fintech_storage]
}
