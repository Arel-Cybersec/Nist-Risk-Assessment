terraform {
  required_version = ">= 1.10.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  localstack_endpoint = "http://localhost:4566"
}

provider "aws" {
  access_key                  = "mock_access_key"
  secret_key                  = "mock_secret_key"
  region                      = var.aws_region
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  # Redirect all AWS API calls used by this configuration to LocalStack running on localhost
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
    s3             = local.localstack_endpoint
    securityhub    = local.localstack_endpoint
    sns            = local.localstack_endpoint
    sts            = local.localstack_endpoint
  }
}

# Second region for cross-region replication of the PII bucket (CP-6, CP-9)
provider "aws" {
  alias                       = "replica"
  access_key                  = "mock_access_key"
  secret_key                  = "mock_secret_key"
  region                      = var.replica_region
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    iam = local.localstack_endpoint
    s3  = local.localstack_endpoint
    sts = local.localstack_endpoint
  }
}
