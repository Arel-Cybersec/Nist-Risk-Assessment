terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.68"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  description = "Region for the Organizations API client."
  type        = string
  default     = "us-east-1"
}

variable "target_id" {
  description = "OU or account ID the guardrails attach to (e.g. ou-xxxx-xxxxxxxx)."
  type        = string
}

variable "allowed_regions" {
  description = "Regions workloads may use. Global services are exempt."
  type        = list(string)
  default     = ["us-east-1"]
}

variable "security_account_id" {
  description = "Account that becomes the delegated GuardDuty administrator for the organization."
  type        = string
}

variable "break_glass_role_name" {
  description = "Role exempt from the guardrails for emergency administration."
  type        = string
  default     = "OrgBreakGlass"
}

locals {
  exempt = { ArnNotLike = { "aws:PrincipalArn" = "arn:aws:iam::*:role/${var.break_glass_role_name}" } }
}

# F-08: Security tooling cannot be disabled, the account cannot leave the org, and the
# root user cannot be used for day-to-day actions.
resource "aws_organizations_policy" "security_guardrails" {
  name        = "fintech-security-guardrails"
  description = "Protect audit and detection services; block org exit and root usage"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ProtectDetectiveControls"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors",
          "guardduty:DeleteDetector", "guardduty:UpdateDetector", "guardduty:DisassociateFromMasterAccount",
          "config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder", "config:DeleteDeliveryChannel",
          "config:DeleteConfigRule"
        ]
        Resource  = "*"
        Condition = local.exempt
      },
      {
        Sid      = "DenyLeavingOrganization"
        Effect   = "Deny"
        Action   = "organizations:LeaveOrganization"
        Resource = "*"
      },
      {
        Sid       = "DenyRootUser"
        Effect    = "Deny"
        Action    = "*"
        Resource  = "*"
        Condition = { StringLike = { "aws:PrincipalArn" = "arn:aws:iam::*:root" } }
      }
    ]
  })
}

# Workloads stay in approved regions; global services (IAM, Organizations, STS, etc.) are exempt.
resource "aws_organizations_policy" "region_restriction" {
  name        = "fintech-region-restriction"
  description = "Deny regional actions outside the approved regions"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenyOutsideApprovedRegions"
      Effect = "Deny"
      NotAction = [
        "iam:*", "organizations:*", "sts:*", "support:*", "budgets:*",
        "cloudfront:*", "route53:*", "waf:*", "globalaccelerator:*", "health:*"
      ]
      Resource = "*"
      Condition = merge(
        { StringNotEquals = { "aws:RequestedRegion" = var.allowed_regions } },
        local.exempt
      )
    }]
  })
}

# Org-wide threat detection: a dedicated security account administers GuardDuty for every
# member account, so a compromised workload account cannot hide its own findings.
resource "aws_guardduty_organization_admin_account" "security" {
  admin_account_id = var.security_account_id
}

resource "aws_organizations_policy_attachment" "security_guardrails" {
  policy_id = aws_organizations_policy.security_guardrails.id
  target_id = var.target_id
}

resource "aws_organizations_policy_attachment" "region_restriction" {
  policy_id = aws_organizations_policy.region_restriction.id
  target_id = var.target_id
}
