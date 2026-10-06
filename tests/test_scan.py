"""Unit tests for scan.py. Run with: python3 -m unittest discover -s tests"""
import io
import json
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import scan  # noqa: E402


def run_scan(files, *args):
    """Write {name: hcl} into a temp dir, scan it, return (exit code, findings by rule)."""
    with tempfile.TemporaryDirectory() as d:
        for name, body in files.items():
            Path(d, name).write_text(textwrap.dedent(body), encoding="utf-8")
        sarif = Path(d, "out.sarif")
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = scan.main([d, "--sarif", str(sarif), *args])
        results = json.loads(sarif.read_text()) if sarif.exists() else {"runs": [{"results": []}]}
    rules = {}
    for r in results["runs"][0]["results"]:
        rules.setdefault(r["ruleId"], []).append(r)
    return code, rules


SECURE_BUCKET = """
resource "aws_s3_bucket" "data" {
  bucket = "data"
}
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = jsonencode({
    Statement = [
      {
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "s3:*"
        Resource  = "${aws_s3_bucket.data.arn}/*"
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}
"""


class ScannerTests(unittest.TestCase):
    def test_no_tf_files_fails_closed(self):
        code, _ = run_scan({"README.md": "nothing here"})
        self.assertEqual(code, 2)

    def test_comment_mentioning_wildcard_is_not_a_finding(self):
        code, rules = run_scan({"s3.tf": "# restrict access instead of \"*\" and 0.0.0.0/0\n" + SECURE_BUCKET})
        self.assertNotIn("TF-AC6-01", rules)
        self.assertNotIn("TF-SC7-01", rules)

    def test_world_open_ssh_is_critical_and_fails(self):
        code, rules = run_scan({"main.tf": """
            resource "aws_security_group" "sg" {
              ingress {
                from_port   = 22
                to_port     = 22
                protocol    = "tcp"
                cidr_blocks = ["0.0.0.0/0"]
              }
            }
        """})
        self.assertEqual(code, 1)
        self.assertEqual(rules["TF-SC7-01"][0]["level"], "error")
        self.assertEqual(rules["TF-SC7-01"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 3)

    def test_world_open_https_is_allowed_but_world_egress_is_flagged(self):
        _, rules = run_scan({"main.tf": """
            resource "aws_security_group" "alb" {
              ingress {
                from_port   = 443
                to_port     = 443
                protocol    = "tcp"
                cidr_blocks = ["0.0.0.0/0"]
              }
              egress {
                from_port   = 0
                to_port     = 0
                protocol    = "-1"
                cidr_blocks = ["0.0.0.0/0"]
              }
            }
        """})
        self.assertNotIn("TF-SC7-01", rules)
        self.assertIn("TF-SC7-02", rules)

    def test_ipv6_world_ingress_is_caught(self):
        _, rules = run_scan({"main.tf": """
            resource "aws_vpc_security_group_ingress_rule" "rdp" {
              from_port   = 3389
              to_port     = 3389
              ip_protocol = "tcp"
              cidr_ipv6   = "::/0"
            }
        """})
        self.assertIn("TF-SC7-01", rules)

    def test_wildcard_actions_are_caught_but_deny_statements_are_not(self):
        _, rules = run_scan({"iam.tf": """
            resource "aws_iam_group_policy" "p" {
              policy = jsonencode({
                Statement = [
                  { Effect = "Allow", Action = "s3:*", Resource = "*" },
                  {
                    Effect    = "Deny"
                    NotAction = ["iam:ChangePassword"]
                    Resource  = "*"
                  },
                  {
                    Effect   = "Allow"
                    Action   = ["kms:Describe*"]
                    Resource = "*"
                  }
                ]
              })
            }
        """})
        self.assertEqual(len(rules["TF-AC6-01"]), 1)
        self.assertNotIn("TF-AC6-02", rules)

    def test_public_access_block_disabled_with_any_spacing(self):
        _, rules = run_scan({"s3.tf": SECURE_BUCKET.replace(
            "block_public_acls       = true", "block_public_acls = false")})
        self.assertIn("TF-AC3-04", rules)

    def test_bucket_missing_versioning_and_tls_policy(self):
        code, rules = run_scan({"s3.tf": 'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n'})
        self.assertEqual(code, 1)
        for rule in ("TF-AC3-03", "TF-CP9-01", "TF-SC8-01"):
            self.assertIn(rule, rules)

    def test_secure_bucket_has_no_high_findings(self):
        code, rules = run_scan({"s3.tf": SECURE_BUCKET, "audit.tf": """
            resource "aws_cloudtrail" "t" {
              enable_log_file_validation = true
              is_multi_region_trail      = true
            }
            resource "aws_guardduty_detector" "g" {
              enable = true
            }
        """})
        self.assertEqual(code, 0, rules)

    def test_http_listener_must_redirect(self):
        _, rules = run_scan({"lb.tf": """
            resource "aws_lb_listener" "plain" {
              protocol = "HTTP"
              default_action {
                type = "forward"
              }
            }
            resource "aws_lb_listener" "redirect" {
              protocol = "HTTP"
              default_action {
                type = "redirect"
              }
            }
        """})
        self.assertEqual(len(rules["TF-SC8-02"]), 1)

    def test_iam_user_requires_mfa_enforcement_and_password_policy(self):
        _, rules = run_scan({"iam.tf": 'resource "aws_iam_user" "u" {\n  name = "u"\n}\n'})
        self.assertIn("TF-IA2-01", rules)
        self.assertIn("TF-IA5-01", rules)

    def test_fail_on_threshold(self):
        hcl = {"main.tf": """
            resource "aws_launch_template" "lt" {
              image_id = "ami-123"
            }
            resource "aws_guardduty_detector" "g" {
              enable = true
            }
            resource "aws_cloudtrail" "t" {
              enable_log_file_validation = true
              is_multi_region_trail      = true
            }
        """}
        self.assertEqual(run_scan(hcl)[0], 0)
        self.assertEqual(run_scan(hcl, "--fail-on", "MEDIUM")[0], 1)

    def test_repository_terraform_passes_high_gate(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = scan.main([str(REPO)])
        self.assertEqual(code, 0, out.getvalue())


if __name__ == "__main__":
    unittest.main()
