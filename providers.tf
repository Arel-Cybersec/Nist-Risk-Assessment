terraform {
  required_version = ">= 1.10.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# REMEDIATION NIST-15: No credentials in code. The provider uses the standard AWS
# credential chain (environment variables, shared profile, SSO or instance role).
# For LocalStack, export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test.
locals {
  # null leaves an endpoint at its AWS default when use_localstack is false
  localstack_endpoint = var.use_localstack ? "http://localhost:4566" : null

  default_tags = {
    Project   = "nist-risk-assessment"
    Owner     = var.owner
    ManagedBy = "terraform"
  }
}

provider "aws" {
  region                      = var.aws_region
  s3_use_path_style           = var.use_localstack
  skip_credentials_validation = var.use_localstack
  skip_metadata_api_check     = var.use_localstack
  skip_requesting_account_id  = var.use_localstack

  default_tags {
    tags = local.default_tags
  }

  endpoints {
    acm            = local.localstack_endpoint
    autoscaling    = local.localstack_endpoint
    backup         = local.localstack_endpoint
    cloudtrail     = local.localstack_endpoint
    cloudwatch     = local.localstack_endpoint
    cloudwatchlogs = local.localstack_endpoint
    ec2            = local.localstack_endpoint
    elbv2          = local.localstack_endpoint
    eventbridge    = local.localstack_endpoint
    guardduty      = local.localstack_endpoint
    iam            = local.localstack_endpoint
    kms            = local.localstack_endpoint
    macie2         = local.localstack_endpoint
    s3             = local.localstack_endpoint
    securityhub    = local.localstack_endpoint
    sns            = local.localstack_endpoint
    ssm            = local.localstack_endpoint
    sts            = local.localstack_endpoint
    wafv2          = local.localstack_endpoint
  }
}

# Second region for cross-region replication of the PII bucket (CP-6, CP-9)
provider "aws" {
  alias                       = "replica"
  region                      = var.replica_region
  s3_use_path_style           = var.use_localstack
  skip_credentials_validation = var.use_localstack
  skip_metadata_api_check     = var.use_localstack
  skip_requesting_account_id  = var.use_localstack

  default_tags {
    tags = local.default_tags
  }

  endpoints {
    iam = local.localstack_endpoint
    kms = local.localstack_endpoint
    s3  = local.localstack_endpoint
    sts = local.localstack_endpoint
  }
}
