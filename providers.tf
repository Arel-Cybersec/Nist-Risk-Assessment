terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Credentials come from variables (LocalStack accepts any value) so no keys live in source.
provider "aws" {
  access_key                  = var.localstack_access_key
  secret_key                  = var.localstack_secret_key
  region                      = var.region
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  # Redirect all AWS API calls to LocalStack running on localhost
  endpoints {
    cloudtrail = var.localstack_endpoint
    cloudwatch = var.localstack_endpoint
    ec2        = var.localstack_endpoint
    iam        = var.localstack_endpoint
    kms        = var.localstack_endpoint
    logs       = var.localstack_endpoint
    s3         = var.localstack_endpoint
    sns        = var.localstack_endpoint
    sts        = var.localstack_endpoint
  }

  default_tags {
    tags = {
      Project   = "nist-risk-assessment"
      ManagedBy = "terraform"
    }
  }
}
