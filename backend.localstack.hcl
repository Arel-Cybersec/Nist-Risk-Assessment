# Backend settings for LocalStack. Create the bucket once before the first init:
#   awslocal s3 mb s3://fintech-terraform-state
# Credentials come from the environment (AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test).
# For real AWS, copy this file, drop the endpoint and skip_* lines, and set kms_key_id.
bucket       = "fintech-terraform-state"
key          = "nist-risk-assessment/terraform.tfstate"
region       = "us-east-1"
encrypt      = true
use_lockfile = true

use_path_style              = true
skip_credentials_validation = true
skip_metadata_api_check     = true
skip_requesting_account_id  = true
skip_region_validation      = true

endpoints = {
  s3  = "http://localhost:4566"
  sts = "http://localhost:4566"
}
