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
        # F-08 needs a human-assumable role, which the baseline does not have (it uses an IAM user)
        self.assertEqual(ids, {"F-01", "F-02", "F-03", "F-04", "F-05", "F-06", "F-07", "F-09"})
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

    def test_standalone_ingress_rules_are_checked(self):
        tf = '''
resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
resource "aws_vpc_security_group_ingress_rule" "rdp" {
  from_port   = 3389
  to_port     = 3389
  ip_protocol = "tcp"
  cidr_ipv4   = "0.0.0.0/0"
}
resource "aws_security_group_rule" "egress_ok" {
  type        = "egress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}'''
        with tempfile.TemporaryDirectory() as d:
            Path(d, "t.tf").write_text(tf)
            flagged = sorted(f["resource"] for f in scan.scan(d) if f["id"] == "F-05")
        self.assertEqual(flagged, ["aws_security_group_rule.ssh", "aws_vpc_security_group_ingress_rule.rdp"])

    def test_human_role_needs_permissions_boundary(self):
        trust = 'assume_role_policy = jsonencode({ Statement = [{ Principal = { AWS = "arn:aws:iam::1:root" } }] })'
        hits = scan_text(f'resource "aws_iam_role" "dev" {{\n  {trust}\n}}')
        self.assertIn(("F-08", "HIGH", "Human-assumable role without a permissions boundary"), hits)
        bounded = f'resource "aws_iam_role" "dev" {{\n  {trust}\n  permissions_boundary = aws_iam_policy.b.arn\n}}'
        self.assertNotIn("F-08", {h[0] for h in scan_text(bounded)})
        service = 'resource "aws_iam_role" "svc" {\n  assume_role_policy = jsonencode({ Statement = [{ Principal = { Service = "ec2.amazonaws.com" } }] })\n}'
        self.assertNotIn("F-08", {h[0] for h in scan_text(service)})

    def test_missing_detection_and_lock_file_are_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "t.tf").write_text('resource "aws_vpc" "v" {\n  cidr_block = "10.0.0.0/16"\n}\n')
            missing = {(f["id"], f["message"]) for f in scan.scan(d) if f["resource"] == "(project)"}
        self.assertIn(("F-07", "No enabled GuardDuty detector (no runtime threat detection)"), missing)
        self.assertIn(("F-07", "No AWS Config recorder (configuration drift is not monitored)"), missing)
        self.assertIn(("F-09", "No .terraform.lock.hcl (provider checksums are not pinned)"), missing)

    def test_commented_out_code_is_ignored(self):
        self.assertEqual(scan_text('# resource "aws_iam_user" "u" { name = "x" }\n'), set())


if __name__ == "__main__":
    unittest.main()
