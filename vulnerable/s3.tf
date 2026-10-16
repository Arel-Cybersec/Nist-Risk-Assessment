# F-01: Public access blocks disabled and a wildcard principal on a PII bucket.
# F-03: No server-side encryption, versioning or access logging.
resource "aws_s3_bucket" "fintech_storage" {
  bucket = "simulated-fintech-customer-data-2026"

  tags = {
    Environment = "Production"
    DataClass   = "PII-PHI"
  }
}

resource "aws_s3_bucket_public_access_block" "open_block" {
  bucket = aws_s3_bucket.fintech_storage.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.fintech_storage.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.fintech_storage.arn}/*"
      }
    ]
  })
}
