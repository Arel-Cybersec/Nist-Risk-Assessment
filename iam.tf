# ── Application role (replaces the hardcoded account-123456789012 principal) ──
resource "aws_iam_role" "app_role" {
  name = "FinTechCoreAppRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Session Manager replaces SSH entirely (F-05)
resource "aws_iam_role_policy_attachment" "app_ssm" {
  role       = aws_iam_role.app_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Objects are SSE-KMS encrypted, so reading and writing them needs the data key
resource "aws_iam_role_policy" "app_data_key" {
  name = "UseDataKey"
  role = aws_iam_role.app_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
      Resource = aws_kms_key.data.arn
    }]
  })
}

resource "aws_iam_instance_profile" "app" {
  name = "FinTechCoreAppProfile"
  role = aws_iam_role.app_role.name
}

# ── Developer access ─────────────────────────────────────────────────
# REMEDIATION F-02: No long-lived IAM users. Developers assume a role, and only with MFA.
resource "aws_iam_role" "developer" {
  name                 = "FinTechDeveloperRole"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
      Action    = "sts:AssumeRole"
      Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
    }]
  })
}

# REMEDIATION F-02: Scoped least-privilege policy (no administrative wildcards)
resource "aws_iam_policy" "secure_developer_policy" {
  name        = "SecureDevPolicy"
  description = "Least-privilege developer access to the FinTech application tier"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RestrictedS3Access"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.fintech_storage.arn,
          "${aws_s3_bucket.fintech_storage.arn}/*"
        ]
      },
      {
        # Describe* actions do not support resource-level permissions in IAM
        Sid      = "ReadOnlyEC2Inventory"
        Effect   = "Allow"
        Action   = "ec2:DescribeInstances"
        Resource = "*"
      },
      {
        Sid      = "StartStopTaggedAppInstancesOnly"
        Effect   = "Allow"
        Action   = ["ec2:StartInstances", "ec2:StopInstances"]
        Resource = "arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:instance/*"
        Condition = {
          StringEquals = { "aws:ResourceTag/Name" = "FinTech-Core-App" }
        }
      },
      {
        Sid      = "UseDataKey"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.data.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "developer" {
  role       = aws_iam_role.developer.name
  policy_arn = aws_iam_policy.secure_developer_policy.arn
}
