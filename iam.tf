# Create the Secure FinTech Developer Group
resource "aws_iam_group" "fintech_dev_group" {
  name = "FinTech-Developers"
}

# REMEDIATION F-02: Scoped Least-Privilege Policy (No administrative wildcards)
resource "aws_iam_group_policy" "secure_developer_policy" {
  name  = "SecureDevPolicy"
  group = aws_iam_group.fintech_dev_group.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RestrictedS3Access"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::simulated-fintech-customer-data-2026",
          "arn:aws:s3:::simulated-fintech-customer-data-2026/*"
        ]
      },
      {
        Sid    = "RestrictedEC2Access"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:StartInstances",
          "ec2:StopInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

# Create the developer user account
resource "aws_iam_user" "vulnerable_user" {
  name = "dev-analyst-01"
}

# Add the user to the secure group
resource "aws_iam_group_membership" "team" {
  name = "dev-group-membership"

  users = [
    aws_iam_user.vulnerable_user.name
  ]

  group = aws_iam_group.fintech_dev_group.name
}