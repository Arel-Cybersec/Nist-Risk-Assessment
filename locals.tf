data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  # Built from strings rather than resource references so the KMS key policy
  # can name the trail without a dependency cycle (key -> trail -> key).
  trail_name = "fintech-audit-trail"
  trail_arn  = "arn:${local.partition}:cloudtrail:${var.aws_region}:${local.account_id}:trail/${local.trail_name}"
}
