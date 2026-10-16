"""Policy-as-code scanner for the risk register findings F-01 … F-13 (F-10 is a process control).

Checks the *.tf files in each given directory (not recursive) and exits 1 if any
CRITICAL or HIGH finding is present, so it can gate a CI pipeline.

    python3 scan.py [DIR ...] [--json]

Limitations: policies built with the aws_iam_policy_document data source or
inline_policy blocks, and heredoc strings, are not parsed.

Standard library only. It understands Terraform's block structure (braces), so a
rule looks at one resource, one ingress block or one policy statement at a time
instead of matching single lines. It complements Checkov: Checkov checks each
resource it can see, while the project-level rules here also catch controls that
are missing entirely (for example, no CloudTrail at all).
"""
import json
import re
import sys
from pathlib import Path

FAIL_ON = {"CRITICAL", "HIGH"}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
IAM_POLICY_TYPES = {
    "aws_iam_policy", "aws_iam_role_policy", "aws_iam_group_policy", "aws_iam_user_policy",
}
OPEN_CIDRS = ('"0.0.0.0/0"', '"::/0"')


def strip_comments(text):
    """Remove #, // and /* */ comments while leaving string contents alone."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif c == "#" or text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            out.append("\n" * text.count("\n", i, end))  # keep line numbers stable
            i = end
            continue
        else:
            out.append(c)
        i += 1
    return "".join(out)


def block_end(text, open_idx):
    """Index just past the brace that closes the '{' at open_idx."""
    depth, in_str = 0, False
    for i in range(open_idx, len(text)):
        c = text[i]
        if in_str:
            if c == '"' and text[i - 1] != "\\":
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


def enclosing_block(text, idx):
    """(start, end) of the innermost {...} that contains idx."""
    depth = 0
    for i in range(idx, -1, -1):
        if text[i] == "}":
            depth += 1
        elif text[i] == "{":
            if depth == 0:
                return i, block_end(text, i)
            depth -= 1
    return 0, len(text)


def sub_blocks(body, name):
    """Yield the bodies of nested blocks such as `ingress { ... }`."""
    for m in re.finditer(r"\b%s\s*\{" % name, body):
        yield body[m.end() - 1:block_end(body, m.end() - 1)]


def attr(body, name):
    m = re.search(r"\b%s\s*=\s*(\"[^\"]*\"|[\w.\-]+)" % name, body)
    return m.group(1).strip('"') if m else None


def load_resources(directory):
    resources = []
    for path in sorted(Path(directory).glob("*.tf")):
        text = strip_comments(path.read_text(encoding="utf-8"))
        for m in re.finditer(r'resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{', text):
            start = m.end() - 1
            resources.append({
                "type": m.group(1),
                "name": m.group(2),
                "file": str(path),
                "line": text.count("\n", 0, m.start()) + 1,
                "body": text[start:block_end(text, start)],
            })
    return resources


def policy_statements(body):
    """Yield (effect, statement_text) for each statement in a jsonencode policy."""
    for m in re.finditer(r'\bEffect\s*=\s*"(Allow|Deny)"', body):
        s, e = enclosing_block(body, m.start())
        yield m.group(1), body[s:e]


def port_range_covers(block, port):
    if (attr(block, "protocol") or attr(block, "ip_protocol")) in ("-1", "all"):
        return True
    lo, hi = attr(block, "from_port"), attr(block, "to_port")
    try:
        return int(lo) <= port <= int(hi)
    except (TypeError, ValueError):
        return False


def scan(directory):
    resources = load_resources(directory)
    findings = []

    def add(fid, sev, res, msg):
        findings.append({"id": fid, "severity": sev, "file": res["file"], "line": res["line"],
                         "resource": f'{res["type"]}.{res["name"]}', "message": msg})

    by_type = {}
    for r in resources:
        by_type.setdefault(r["type"], []).append(r)

    def referenced(res_type, target, ref_attr="bucket"):
        """True if any resource of res_type points at target via ref_attr."""
        ref = f'{target["type"]}.{target["name"]}.'
        return any(ref in (re.search(r"\b%s\s*=\s*([^\n]+)" % ref_attr, r["body"]) or [""])[0]
                   for r in by_type.get(res_type, []))

    for r in resources:
        t, b = r["type"], r["body"]

        # F-01 Public data exposure
        if t == "aws_s3_bucket_public_access_block":
            for a in ("block_public_acls", "block_public_policy", "ignore_public_acls",
                      "restrict_public_buckets"):
                if attr(b, a) == "false":
                    add("F-01", "CRITICAL", r, f"S3 public access block disabled ({a} = false)")
        if t == "aws_s3_bucket_policy":
            for effect, st in policy_statements(b):
                if effect == "Allow" and re.search(r'\bPrincipal\s*=\s*("\*"|\{[^}]*"\*")', st):
                    add("F-01", "CRITICAL", r, "Bucket policy allows any principal (\"*\")")
        if t == "aws_s3_bucket" and not referenced("aws_s3_bucket_public_access_block", r):
            add("F-01", "HIGH", r, "S3 bucket has no public access block")

        # F-02 Excessive privilege (identity policies only; key and bucket policies are resource policies)
        if t in IAM_POLICY_TYPES:
            for effect, st in policy_statements(b):
                if effect != "Allow":
                    continue
                action = re.search(r"\bAction\s*=\s*(\[[^\]]*\]|\"[^\"]*\")", st)
                actions = re.findall(r'"([^"]*)"', action.group(1)) if action else []
                if "*" in actions:
                    add("F-02", "CRITICAL", r, 'IAM policy allows all actions (Action = "*")')
                elif any(a.endswith(":*") for a in actions):
                    add("F-02", "HIGH", r, "IAM policy allows a whole service (service:*)")
        if t == "aws_iam_user":
            add("F-02", "MEDIUM", r, "Long-lived IAM user; use federated roles with MFA")

        # F-03 Unencrypted data at rest
        if t == "aws_s3_bucket" and not referenced("aws_s3_bucket_server_side_encryption_configuration", r):
            add("F-03", "HIGH", r, "S3 bucket has no server-side encryption configuration")
        if t == "aws_instance":
            root = next(sub_blocks(b, "root_block_device"), "")
            if attr(root, "encrypted") != "true":
                add("F-03", "HIGH", r, "EC2 root volume is not encrypted")

        # F-04 Missing audit logging
        if t == "aws_vpc" and not referenced("aws_flow_log", r, "vpc_id"):
            add("F-04", "MEDIUM", r, "VPC has no flow logs")
        # Object access is logged by S3 server access logs or by CloudTrail data events; log targets are exempt
        trail_logged = any(f'aws_s3_bucket.{r["name"]}.arn' in tr["body"] for tr in by_type.get("aws_cloudtrail", []))
        if t == "aws_s3_bucket" and not trail_logged and not referenced("aws_s3_bucket_logging", r) \
                and not referenced("aws_s3_bucket_logging", r, "target_bucket"):
            add("F-04", "MEDIUM", r, "S3 bucket access is not logged (no server access logs or CloudTrail data events)")

        # F-05 Network exposure (inline ingress blocks and standalone rule resources)
        ingress_rules = []
        if t == "aws_security_group":
            ingress_rules = list(sub_blocks(b, "ingress"))
        elif t == "aws_vpc_security_group_ingress_rule" or (t == "aws_security_group_rule" and attr(b, "type") == "ingress"):
            ingress_rules = [b]
        if ingress_rules:
            for ing in ingress_rules:
                if not any(c in ing for c in OPEN_CIDRS):
                    continue
                if any(port_range_covers(ing, p) for p in (22, 3389)):
                    add("F-05", "CRITICAL", r, "Management port (22/3389) open to the internet")
                elif port_range_covers(ing, 80):
                    add("F-05", "MEDIUM", r, "Plaintext HTTP (80) open to the internet")

        # F-06 Instance hardening
        if t == "aws_instance":
            meta = next(sub_blocks(b, "metadata_options"), "")
            if attr(meta, "http_tokens") != "required":
                add("F-06", "HIGH", r, "IMDSv1 allowed; set metadata_options.http_tokens = \"required\"")

        # F-13 Managed TLS: no plaintext or weak listeners, no instance directly on the internet
        if t == "aws_lb_listener":
            proto = attr(b, "protocol")
            if proto == "HTTP" and not re.search(r'type\s*=\s*"redirect"', b):
                add("F-13", "HIGH", r, "Plaintext HTTP listener that does not redirect to HTTPS")
            if proto == "HTTPS" and not re.match(r"ELBSecurityPolicy-(TLS13|TLS-1-2)", attr(b, "ssl_policy") or ""):
                add("F-13", "HIGH", r, "HTTPS listener allows TLS below 1.2 (set a TLS13 or TLS-1-2 ssl_policy)")
        if t == "aws_instance":
            subnet = re.match(r"aws_subnet\.([\w-]+)\.", attr(b, "subnet_id") or "")
            public_subnet = subnet and any(s["name"] == subnet.group(1) and attr(s["body"], "map_public_ip_on_launch") == "true"
                                           for s in by_type.get("aws_subnet", []))
            if attr(b, "associate_public_ip_address") == "true" or public_subnet:
                add("F-13", "MEDIUM", r, "Instance gets a public IP; serve it through a TLS load balancer instead")

        # F-08 Preventive guardrails: roles people can assume need a permissions boundary
        if t == "aws_iam_role" and re.search(r"Principal\s*=\s*\{\s*AWS", b) \
                and not re.search(r"\bpermissions_boundary\s*=", b):
            add("F-08", "HIGH", r, "Human-assumable role without a permissions boundary")

    # Project-level: controls that are missing entirely
    def missing(fid, sev, msg):
        findings.append({"id": fid, "severity": sev, "file": str(Path(directory)), "line": 0,
                         "resource": "(project)", "message": msg})

    if resources:
        if not any(attr(r["body"], "enable_log_file_validation") == "true" for r in by_type.get("aws_cloudtrail", [])):
            missing("F-04", "HIGH", "No CloudTrail with log file validation enabled")
        if not any(attr(r["body"], "enable") == "true" for r in by_type.get("aws_guardduty_detector", [])):
            missing("F-07", "HIGH", "No enabled GuardDuty detector (no runtime threat detection)")
        if not by_type.get("aws_config_configuration_recorder"):
            missing("F-07", "HIGH", "No AWS Config recorder (configuration drift is not monitored)")
        if not by_type.get("aws_backup_plan"):
            missing("F-11", "HIGH", "No AWS Backup plan (no point-in-time recovery for instance data)")
        elif not by_type.get("aws_backup_restore_testing_plan"):
            missing("F-11", "MEDIUM", "Backups are never test-restored (no restore testing plan)")
        if by_type.get("aws_s3_bucket") and not by_type.get("aws_s3_bucket_replication_configuration"):
            missing("F-12", "MEDIUM", "Data is held in a single region (no S3 replication configuration)")
        if not (Path(directory) / ".terraform.lock.hcl").is_file():
            missing("F-09", "MEDIUM", "No .terraform.lock.hcl (provider checksums are not pinned)")

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["id"], f["file"], f["line"]))
    return findings


def main(argv):
    as_json = "--json" in argv
    dirs = [a for a in argv if not a.startswith("--")] or ["."]
    findings = [f for d in dirs for f in scan(d)]
    failed = any(f["severity"] in FAIL_ON for f in findings)

    if as_json:
        print(json.dumps({"findings": findings, "failed": failed}, indent=2))
    else:
        print("=== COMPLIANCE AUDIT ===")
        for f in findings:
            loc = f'{f["file"]}:{f["line"]}' if f["line"] else f["file"]
            print(f' [{f["severity"]:<8}] {f["id"]} {loc} {f["resource"]}: {f["message"]}')
        counts = {s: sum(f["severity"] == s for f in findings) for s in SEVERITY_ORDER}
        print("=== %d findings (%s) — %s ===" % (
            len(findings), ", ".join(f"{v} {k}" for k, v in counts.items() if v) or "clean",
            "FAIL" if failed else "PASS"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
