# F-02: Full administrative wildcard granted to the developer group.
resource "aws_iam_group" "fintech_dev_group" {
  name = "FinTech-Developers"
}

resource "aws_iam_group_policy" "admin_policy" {
  name  = "DevAdminPolicy"
  group = aws_iam_group.fintech_dev_group.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user" "vulnerable_user" {
  name = "dev-analyst-01"
}

resource "aws_iam_group_membership" "team" {
  name  = "dev-group-membership"
  users = [aws_iam_user.vulnerable_user.name]
  group = aws_iam_group.fintech_dev_group.name
}
