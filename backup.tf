# REMEDIATION F-11: Backups that are proven to restore.
# Daily recovery points of the application volume go to a locked, KMS-encrypted vault and are
# copied to the DR region (dr.tf). AWS Backup restore testing then restores the latest point
# every week and reports the result to the security alert topic, so "can we restore?" is
# answered continuously instead of during an incident.
# (PR.DS-11, RC.RP-03; SP 800-53 CP-9, CP-4, CP-10)

resource "aws_backup_vault" "main" {
  name        = "fintech-vault"
  kms_key_arn = aws_kms_key.data.arn
}

# Governance-mode lock (no changeable_for_days): recovery points cannot be deleted early or
# kept beyond a year without the special bypass permission.
resource "aws_backup_vault_lock_configuration" "main" {
  backup_vault_name  = aws_backup_vault.main.name
  min_retention_days = 7
  max_retention_days = 365
}

resource "aws_backup_vault" "dr" {
  provider    = aws.dr
  name        = "fintech-vault-dr"
  kms_key_arn = aws_kms_key.dr.arn
}

resource "aws_backup_vault_lock_configuration" "dr" {
  provider           = aws.dr
  backup_vault_name  = aws_backup_vault.dr.name
  min_retention_days = 7
  max_retention_days = 365
}

resource "aws_backup_plan" "main" {
  name = "fintech-daily"

  rule {
    rule_name         = "daily-35-days"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 5 * * ? *)" # 05:00 UTC every day

    lifecycle {
      delete_after = 35
    }

    copy_action {
      destination_vault_arn = aws_backup_vault.dr.arn
      lifecycle {
        delete_after = 35
      }
    }
  }
}

resource "aws_iam_role" "backup" {
  name = "FinTechBackup"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_backup_selection" "app_volume" {
  name         = "app-root-volume"
  plan_id      = aws_backup_plan.main.id
  iam_role_arn = aws_iam_role.backup.arn
  resources = [
    "arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:volume/${aws_instance.app_server.root_block_device[0].volume_id}"
  ]
}

# ── Automated restore tests ──────────────────────────────────────────
resource "aws_backup_restore_testing_plan" "weekly" {
  name                = "fintech_weekly_restore_test"
  schedule_expression = "cron(0 7 ? * MON *)" # Mondays 07:00 UTC

  recovery_point_selection {
    algorithm             = "LATEST_WITHIN_WINDOW"
    include_vaults        = [aws_backup_vault.main.arn]
    recovery_point_types  = ["SNAPSHOT"]
    selection_window_days = 7
  }
}

# Restore tests create a temporary volume and delete it afterwards. A dedicated role scoped to
# that job, instead of a broad managed policy.
resource "aws_iam_role" "restore_test" {
  name = "FinTechBackupRestoreTest"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "restore_test" {
  name = "RestoreTestVolumes"
  role = aws_iam_role.restore_test.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Describe* calls do not support resource-level permissions
        Sid      = "Inspect"
        Effect   = "Allow"
        Action   = ["ec2:DescribeSnapshots", "ec2:DescribeVolumes"]
        Resource = "*"
      },
      {
        Sid    = "RestoreAndCleanUpVolumes"
        Effect = "Allow"
        Action = ["ec2:CreateVolume", "ec2:DeleteVolume", "ec2:CreateTags"]
        Resource = [
          "arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:volume/*",
          "arn:aws:ec2:${var.region}::snapshot/*"
        ]
      },
      {
        Sid      = "UseDataKeyForEncryptedVolumes"
        Effect   = "Allow"
        Action   = ["kms:CreateGrant", "kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKeyWithoutPlaintext", "kms:ReEncrypt*"]
        Resource = aws_kms_key.data.arn
      }
    ]
  })
}

resource "aws_backup_restore_testing_selection" "app_volume" {
  name                      = "app_root_volume"
  restore_testing_plan_name = aws_backup_restore_testing_plan.weekly.name
  protected_resource_type   = "EBS"
  iam_role_arn              = aws_iam_role.restore_test.arn
  protected_resource_arns   = [one(aws_backup_selection.app_volume.resources)]
  validation_window_hours   = 1
}

# Restore test outcomes go to the same alert topic as GuardDuty and Config
resource "aws_backup_vault_notifications" "main" {
  backup_vault_name   = aws_backup_vault.main.name
  sns_topic_arn       = aws_sns_topic.security_alerts.arn
  backup_vault_events = ["RESTORE_JOB_COMPLETED"]
}
