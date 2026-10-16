"""Run: python3 -m unittest -v"""
import tempfile
import unittest
from pathlib import Path

import scan

ROOT = Path(__file__).parent


def scan_text(tf):
    with tempfile.TemporaryDirectory() as d:
        Path(d, "t.tf").write_text(tf)
        return {(f["id"], f["severity"], f["message"]) for f in scan.scan(d) if f["resource"] != "(project)"}


class ScanTest(unittest.TestCase):
    def test_vulnerable_baseline_flags_every_finding(self):
        ids = {f["id"] for f in scan.scan(ROOT / "vulnerable")}
        self.assertEqual(ids, {"F-01", "F-02", "F-03", "F-04", "F-05", "F-06"})
        self.assertEqual(scan.main([str(ROOT / "vulnerable")]), 1)

    def test_hardened_root_is_clean(self):
        self.assertEqual(scan.scan(ROOT), [])
        self.assertEqual(scan.main([str(ROOT)]), 0)

    def test_whitespace_does_not_hide_disabled_block(self):
        hits = scan_text('resource "aws_s3_bucket_public_access_block" "b" {\n  block_public_acls=false\n}')
        self.assertIn("F-01", {h[0] for h in hits})

    def test_open_https_and_deny_statements_are_not_flagged(self):
        hits = scan_text('''
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_s3_bucket_policy" "p" {
  policy = jsonencode({ Statement = [{ Effect = "Deny", Principal = "*", Action = "s3:*" }] })
}
resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "ec2:DescribeInstances", Resource = "*" }] })
}''')
        self.assertEqual(hits, set())

    def test_all_protocols_open_counts_as_management_exposure(self):
        hits = scan_text('''
resource "aws_security_group" "x" {
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["::/0"]
  }
}''')
        self.assertIn(("F-05", "CRITICAL", "Management port (22/3389) open to the internet"), hits)

    def test_commented_out_code_is_ignored(self):
        self.assertEqual(scan_text('# resource "aws_iam_user" "u" { name = "x" }\n'), set())


if __name__ == "__main__":
    unittest.main()
