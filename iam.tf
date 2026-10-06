# Create the Secure FinTech Developer Group
resource "aws_iam_group" "fintech_dev_group" {
  name = "FinTech-Developers"
}

# REMEDIATION NIST-04: Account-wide password policy (IA-5(1))
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}

# REMEDIATION F-02, NIST-01, NIST-04, NIST-13: Least-privilege developer policy
# - No direct access to the PII-PHI bucket; reads go through the MFA-gated break-glass role
# - Every action except MFA self-enrolment is denied until the caller has signed in with MFA
# - Start/Stop only on instances explicitly tagged as non-production
resource "aws_iam_group_policy" "secure_developer_policy" {
  name  = "SecureDevPolicy"
  group = aws_iam_group.fintech_dev_group.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowViewAccountInfo"
        Effect   = "Allow"
        Action   = ["iam:GetAccountPasswordPolicy", "iam:ListVirtualMFADevices"]
        Resource = "*"
      },
      {
        Sid      = "AllowManageOwnPasswordAndMFA"
        Effect   = "Allow"
        Action   = ["iam:ChangePassword", "iam:GetUser", "iam:DeactivateMFADevice", "iam:EnableMFADevice", "iam:ListMFADevices", "iam:ResyncMFADevice"]
        Resource = "arn:${local.partition}:iam::${local.account_id}:user/$${aws:username}"
      },
      {
        Sid      = "AllowCreateOwnVirtualMFADevice"
        Effect   = "Allow"
        Action   = "iam:CreateVirtualMFADevice"
        Resource = "arn:${local.partition}:iam::${local.account_id}:mfa/*"
      },
      {
        Sid    = "DenyAllExceptMFASetupWithoutMFA"
        Effect = "Deny"
        NotAction = [
          "iam:ChangePassword",
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetAccountPasswordPolicy",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "sts:GetSessionToken"
        ]
        Resource  = "*"
        Condition = { BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" } }
      },
      {
        Sid      = "RestrictedEC2Describe"
        Effect   = "Allow"
        Action   = "ec2:DescribeInstances"
        Resource = "*"
      },
      {
        Sid      = "RestrictedEC2PowerNonProduction"
        Effect   = "Allow"
        Action   = ["ec2:StartInstances", "ec2:StopInstances"]
        Resource = "arn:${local.partition}:ec2:*:${local.account_id}:instance/*"
        Condition = {
          StringEquals = { "aws:ResourceTag/Environment" = ["Development", "Staging"] }
        }
      },
      {
        Sid      = "AssumePiiBreakGlassReadWithRecentMFA"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_role.pii_breakglass_read.arn
        Condition = {
          Bool            = { "aws:MultiFactorAuthPresent" = "true" }
          NumericLessThan = { "aws:MultiFactorAuthAge" = "3600" }
        }
      }
    ]
  })
}

# REMEDIATION NIST-01: Time-boxed, MFA-gated read path to PII for incident or support work.
# Object reads only (no ListBucket) so the role cannot enumerate and bulk-copy the bucket.
resource "aws_iam_role" "pii_breakglass_read" {
  name                 = "FinTech-PII-BreakGlass-Read"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "TrustAccountPrincipalsWithRecentMFA"
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
        Action    = "sts:AssumeRole"
        Condition = {
          Bool            = { "aws:MultiFactorAuthPresent" = "true" }
          NumericLessThan = { "aws:MultiFactorAuthAge" = "3600" }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "pii_breakglass_read" {
  name = "PiiObjectReadOnly"
  role = aws_iam_role.pii_breakglass_read.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadPiiObjects"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.fintech_storage.arn}/*"
      }
    ]
  })
}

# Create the developer user account
resource "aws_iam_user" "vulnerable_user" {
  name = "dev-analyst-01"
}

# REMEDIATION NIST-13: Non-exclusive membership, so memberships managed elsewhere are not silently removed
resource "aws_iam_user_group_membership" "team" {
  user   = aws_iam_user.vulnerable_user.name
  groups = [aws_iam_group.fintech_dev_group.name]
}
