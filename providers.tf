terraform {
  required_version = ">= 1.9.0" # cross-variable validation in variables.tf
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.68"
    }
  }
}

# LocalStack by default (no AWS account needed). Set use_localstack = false to deploy to a
# real account: the endpoints and mock credentials below then become null, so the provider
# uses its normal credential chain (e.g. GitHub OIDC in .github/workflows/drift.yml).
locals {
  ls = var.use_localstack ? var.localstack_endpoint : null
}

provider "aws" {
  access_key                  = var.use_localstack ? var.localstack_access_key : null
  secret_key                  = var.use_localstack ? var.localstack_secret_key : null
  region                      = var.region
  s3_use_path_style           = var.use_localstack
  skip_credentials_validation = var.use_localstack
  skip_metadata_api_check     = var.use_localstack
  skip_requesting_account_id  = var.use_localstack

  endpoints {
    acm            = local.ls
    backup         = local.ls
    cloudtrail     = local.ls
    cloudwatch     = local.ls
    cloudwatchlogs = local.ls
    config         = local.ls
    ec2            = local.ls
    elbv2          = local.ls
    eventbridge    = local.ls
    guardduty      = local.ls
    iam            = local.ls
    kms            = local.ls
    route53        = local.ls
    s3             = local.ls
    sns            = local.ls
    sts            = local.ls
    wafv2          = local.ls
  }

  default_tags {
    tags = {
      Project   = "nist-risk-assessment"
      ManagedBy = "terraform"
    }
  }
}

# Second region for disaster recovery (F-12): replica data bucket and backup copies.
provider "aws" {
  alias                       = "dr"
  access_key                  = var.use_localstack ? var.localstack_access_key : null
  secret_key                  = var.use_localstack ? var.localstack_secret_key : null
  region                      = var.dr_region
  s3_use_path_style           = var.use_localstack
  skip_credentials_validation = var.use_localstack
  skip_metadata_api_check     = var.use_localstack
  skip_requesting_account_id  = var.use_localstack

  endpoints {
    acm            = local.ls
    backup         = local.ls
    cloudtrail     = local.ls
    cloudwatch     = local.ls
    cloudwatchlogs = local.ls
    config         = local.ls
    ec2            = local.ls
    elbv2          = local.ls
    eventbridge    = local.ls
    guardduty      = local.ls
    iam            = local.ls
    kms            = local.ls
    route53        = local.ls
    s3             = local.ls
    sns            = local.ls
    sts            = local.ls
    wafv2          = local.ls
  }

  default_tags {
    tags = {
      Project   = "nist-risk-assessment"
      ManagedBy = "terraform"
    }
  }
}
