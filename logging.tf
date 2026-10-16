# REMEDIATION F-04: Audit logging and network monitoring (AU-2, AU-9, AU-12, SI-4)

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/fintech/cloudtrail"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.data.arn
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/fintech/vpc-flow-logs"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.data.arn
}

# ── CloudTrail ───────────────────────────────────────────────────────
resource "aws_iam_role" "cloudtrail_to_cw" {
  name = "FinTechCloudTrailToCloudWatch"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_to_cw" {
  name = "WriteTrailLogs"
  role = aws_iam_role.cloudtrail_to_cw.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

resource "aws_sns_topic" "cloudtrail" {
  name              = "fintech-cloudtrail-delivery"
  kms_master_key_id = aws_kms_key.data.id
}

resource "aws_sns_topic_policy" "cloudtrail" {
  arn = aws_sns_topic.cloudtrail.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudTrailPublish"
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.cloudtrail.arn
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "fintech-audit-trail"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  s3_key_prefix                 = "cloudtrail"
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.data.arn
  sns_topic_name                = aws_sns_topic.cloudtrail.name
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_to_cw.arn

  # Object-level access to the PII bucket is recorded, not just management events
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.fintech_storage.arn}/", "${aws_s3_bucket.replica.arn}/"]
    }
  }

  depends_on = [aws_s3_bucket_policy.audit_logs, aws_sns_topic_policy.cloudtrail]
}

# ── VPC Flow Logs ────────────────────────────────────────────────────
resource "aws_iam_role" "flow_logs" {
  name = "FinTechVpcFlowLogs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "WriteFlowLogs"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "vpc" {
  vpc_id          = aws_vpc.fintech_vpc.id
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn    = aws_iam_role.flow_logs.arn
}
