# REMEDIATION NIST-06: Remote, encrypted, locked Terraform state (CP-9, CM-3)
# Settings are supplied at init time so each environment can point at its own state bucket:
#   terraform init -backend-config=backend.localstack.hcl
terraform {
  backend "s3" {}
}
