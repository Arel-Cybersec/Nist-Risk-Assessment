# REMEDIATION F-07: Runtime threat detection and configuration drift monitoring.
# Static scans (scan.py, Checkov, conftest) check the code; these check the live account,
# including changes made by hand outside Terraform.
# (DE.CM-01, DE.CM-09, DE.AE-02, DE.AE-06; SP 800-53 SI-4, CM-3, CM-6, CA-7)

# ── Managed threat detection ─────────────────────────────────────────
resource "aws_guardduty_detector" "main" {
  #checkov:skip=CKV2_AWS_3:Org-wide GuardDuty is delegated in org/main.tf; this is the workload-account detector
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_guardduty_detector_feature" "s3" {
  detector_id = aws_guardduty_detector.main.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "ebs_malware" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
}

# ── Continuous configuration monitoring (AWS Config) ─────────────────
resource "aws_iam_role" "config" {
  name = "FinTechAwsConfig"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  name     = "fintech-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "fintech-delivery"
  s3_bucket_name = aws_s3_bucket.audit_logs.id
  s3_key_prefix  = "config"
  sns_topic_arn  = aws_sns_topic.security_alerts.arn

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.main, aws_s3_bucket_policy.audit_logs]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

# AWS managed rules mirroring the risk register (28 rules). Identifiers verified against AWS's
# "Operational Best Practices for NIST CSF / NIST 800-53 rev 5" conformance packs
# (github.com/awslabs/aws-config-rules).
locals {
  config_rules = {
    "s3-public-read-prohibited"  = "S3_BUCKET_PUBLIC_READ_PROHIBITED"           # F-01
    "s3-public-write-prohibited" = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"          # F-01
    "iam-no-admin-statements"    = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS" # F-02
    "root-account-mfa"           = "ROOT_ACCOUNT_MFA_ENABLED"                   # F-02
    "iam-root-access-key"        = "IAM_ROOT_ACCESS_KEY_CHECK"                  # F-02
    "s3-sse-enabled"             = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"   # F-03
    "ebs-encrypted-volumes"      = "ENCRYPTED_VOLUMES"                          # F-03
    "kms-key-rotation"           = "CMK_BACKING_KEY_ROTATION_ENABLED"           # F-03
    "cloudtrail-multi-region"    = "MULTI_REGION_CLOUD_TRAIL_ENABLED"           # F-04
    "cloudtrail-log-validation"  = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"    # F-04
    "vpc-flow-logs"              = "VPC_FLOW_LOGS_ENABLED"                      # F-04
    "s3-access-logging"          = "S3_BUCKET_LOGGING_ENABLED"                  # F-04
    "ssh-restricted"             = "INCOMING_SSH_DISABLED"                      # F-05
    "common-ports-restricted"    = "RESTRICTED_INCOMING_TRAFFIC"                # F-05
    "default-sg-closed"          = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"          # F-05
    "s3-tls-only"                = "S3_BUCKET_SSL_REQUESTS_ONLY"                # F-05
    "ec2-imdsv2"                 = "EC2_IMDSV2_CHECK"                           # F-06
    "guardduty-enabled"          = "GUARDDUTY_ENABLED_CENTRALIZED"              # F-07
    "ebs-in-backup-plan"         = "EBS_IN_BACKUP_PLAN"                         # F-11
    "backup-points-encrypted"    = "BACKUP_RECOVERY_POINT_ENCRYPTED"            # F-11
    "s3-replication-enabled"     = "S3_BUCKET_REPLICATION_ENABLED"              # F-12
    "acm-cert-expiration"        = "ACM_CERTIFICATE_EXPIRATION_CHECK"           # F-13
    "elb-https-only"             = "ELB_TLS_HTTPS_LISTENERS_ONLY"               # F-13
    "alb-drop-invalid-headers"   = "ALB_HTTP_DROP_INVALID_HEADER_ENABLED"       # F-13
    "alb-waf-enabled"            = "ALB_WAF_ENABLED"                            # F-13
    "elb-logging-enabled"        = "ELB_LOGGING_ENABLED"                        # F-13
    "elb-deletion-protection"    = "ELB_DELETION_PROTECTION_ENABLED"            # F-13
    "ec2-no-public-ip"           = "EC2_INSTANCE_NO_PUBLIC_IP"                  # F-13
  }
}

resource "aws_config_config_rule" "managed" {
  for_each = local.config_rules
  name     = each.key

  source {
    owner             = "AWS"
    source_identifier = each.value
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# ── Alerting ─────────────────────────────────────────────────────────
resource "aws_sns_topic" "security_alerts" {
  name              = "fintech-security-alerts"
  kms_master_key_id = aws_kms_key.data.id
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowEventBridgeConfigAndBackup"
      Effect    = "Allow"
      Principal = { Service = ["events.amazonaws.com", "config.amazonaws.com", "backup.amazonaws.com"] }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.security_alerts.arn
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
}

resource "aws_sns_topic_subscription" "security_email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# GuardDuty findings of Medium severity (4.0) and above
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "fintech-guardduty-findings"
  description = "GuardDuty findings, severity >= 4"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail        = { severity = [{ numeric = [">=", 4] }] }
  })
}

# A resource drifts out of compliance with any Config rule (e.g. a manual console change)
resource "aws_cloudwatch_event_rule" "config_noncompliant" {
  name        = "fintech-config-noncompliant"
  description = "Config rule evaluation changed to NON_COMPLIANT"
  event_pattern = jsonencode({
    source        = ["aws.config"]
    "detail-type" = ["Config Rules Compliance Change"]
    detail        = { newEvaluationResult = { complianceType = ["NON_COMPLIANT"] } }
  })
}

# Someone tries to switch off the audit or detection tooling
resource "aws_cloudwatch_event_rule" "security_tampering" {
  name        = "fintech-security-tampering"
  description = "Attempts to stop or delete CloudTrail, GuardDuty or Config"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["cloudtrail.amazonaws.com", "guardduty.amazonaws.com", "config.amazonaws.com"]
      eventName = [
        "StopLogging", "DeleteTrail", "UpdateTrail",
        "DeleteDetector", "UpdateDetector",
        "StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteDeliveryChannel", "DeleteConfigRule"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "alerts" {
  for_each = {
    guardduty = aws_cloudwatch_event_rule.guardduty_findings.name
    config    = aws_cloudwatch_event_rule.config_noncompliant.name
    tampering = aws_cloudwatch_event_rule.security_tampering.name
  }
  rule = each.value
  arn  = aws_sns_topic.security_alerts.arn
}
