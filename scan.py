#!/usr/bin/env python3
"""Policy-as-code scanner for this repository's Terraform.

Parses HCL structurally (comments and strings are understood, so a comment that
mentions "*" is not a finding), checks resources against NIST SP 800-53 Rev.5
controls, and fails closed so it can gate a pipeline.

Exit codes:
  0  no finding at or above --fail-on
  1  at least one finding at or above --fail-on
  2  usage error, or no .tf files found (a scan that saw nothing must not pass)
"""
import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

SEVERITIES = ["INFO", "MEDIUM", "HIGH", "CRITICAL"]
WEB_PORTS = {80, 443}
ADMIN_PORTS = {22, 3389}
WORLD_CIDRS = {"0.0.0.0/0", "::/0"}


@dataclass
class Finding:
    rule: str
    severity: str
    control: str
    message: str
    file: str
    line: int


@dataclass
class Block:
    kind: str                       # "resource", "ingress", "provider", ...
    labels: list
    file: str
    line: int
    text: str                       # full source text of the file (comments blanked)
    start: int                      # index just after "{"
    end: int                        # index of matching "}"
    attrs: dict = field(default_factory=dict)     # name -> (raw value, line)
    children: list = field(default_factory=list)  # nested Blocks

    @property
    def body(self):
        return self.text[self.start:self.end]

    @property
    def address(self):
        return ".".join(self.labels)

    def attr(self, name):
        value = self.attrs.get(name)
        return value[0].strip() if value else None

    def attr_line(self, name):
        value = self.attrs.get(name)
        return value[1] if value else self.line

    def child(self, kind):
        return next((c for c in self.children if c.kind == kind), None)


# ── Lexing helpers ──────────────────────────────────────────────────────────

def skip_string(text, i):
    """text[i] is an opening quote. Return the index just past the closing quote,
    following ${ ... } interpolations that may themselves contain quotes."""
    i += 1
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == '"':
            return i + 1
        if text.startswith("${", i) or text.startswith("%{", i):
            i = skip_balanced(text, i + 1)
            continue
        i += 1
    return i


def skip_balanced(text, i):
    """text[i] is an opening bracket. Return the index just past its match."""
    pairs = {"{": "}", "[": "]", "(": ")"}
    stack = [pairs[text[i]]]
    i += 1
    while i < len(text) and stack:
        ch = text[i]
        if ch == '"':
            i = skip_string(text, i)
            continue
        if ch in pairs:
            stack.append(pairs[ch])
        elif stack and ch == stack[-1]:
            stack.pop()
        i += 1
    return i


HEREDOC_RE = re.compile(r"<<-?([A-Za-z_]\w*)[ \t]*\n")


def blank_comments(text):
    """Replace comments with spaces (newlines kept) so offsets and line numbers survive."""
    out = list(text)
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '"':
            i = skip_string(text, i)
        elif ch == "<" and HEREDOC_RE.match(text, i):
            m = HEREDOC_RE.match(text, i)
            end = re.compile(r"^[ \t]*" + re.escape(m.group(1)) + r"[ \t]*$", re.M).search(text, m.end())
            i = end.end() if end else len(text)
        elif ch == "#" or text.startswith("//", i):
            j = text.find("\n", i)
            j = len(text) if j == -1 else j
            out[i:j] = " " * (j - i)
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = len(text) if j == -1 else j + 2
            out[i:j] = [c if c == "\n" else " " for c in text[i:j]]
            i = j
        else:
            i += 1
    return "".join(out)


BLOCK_RE = re.compile(r'([A-Za-z_][\w-]*)((?:[ \t]+"[^"\n]*")*)[ \t]*\{')
ATTR_RE = re.compile(r'"?([A-Za-z_][\w:.\-/]*)"?[ \t]*[=:](?![=])')


def parse_body(text, start, end, file, line_of):
    """Split text[start:end] into attributes and nested blocks."""
    attrs, blocks = {}, []
    i = start
    while i < end:
        while i < end and text[i] in " \t\r\n,":
            i += 1
        if i >= end:
            break
        m = BLOCK_RE.match(text, i)
        if m and m.end() <= end:
            close = skip_balanced(text, m.end() - 1) - 1
            labels = re.findall(r'"([^"]*)"', m.group(2))
            blk = Block(m.group(1), labels, file, line_of(i), text, m.end(), close)
            blk.attrs, blk.children = parse_body(text, m.end(), close, file, line_of)
            blocks.append(blk)
            i = close + 1
            continue
        a = ATTR_RE.match(text, i)
        if a:
            j = a.end()
            value_start = j
            while j < end and text[j] not in "\n,":
                if text[j] == '"':
                    j = skip_string(text, j)
                elif text[j] in "{[(":
                    j = skip_balanced(text, j)
                else:
                    j += 1
            attrs[a.group(1)] = (text[value_start:j], line_of(i))
            i = j
            continue
        # Unrecognised token: skip it (balanced if it opens a bracket)
        if text[i] == '"':
            i = skip_string(text, i)
        elif text[i] in "{[(":
            i = skip_balanced(text, i)
        else:
            i += 1
    return attrs, blocks


def parse_file(path, root):
    raw = path.read_text(encoding="utf-8")
    text = blank_comments(raw)
    newlines = [m.start() for m in re.finditer("\n", text)]

    def line_of(offset):
        lo, hi = 0, len(newlines)
        while lo < hi:
            mid = (lo + hi) // 2
            if newlines[mid] < offset:
                lo = mid + 1
            else:
                hi = mid
        return lo + 1

    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path)
    _, blocks = parse_body(text, 0, len(text), rel, line_of)
    return rel, blocks, line_of


# ── Value helpers ───────────────────────────────────────────────────────────

def strings_in(value):
    return re.findall(r'"([^"]*)"', value or "")


def literal(value):
    if value is None:
        return None
    s = value.strip()
    return s[1:-1] if len(s) >= 2 and s[0] == s[-1] == '"' else s


def referenced_name(value, rtype):
    m = re.search(re.escape(rtype) + r"\.([\w-]+)", value or "")
    return m.group(1) if m else None


def objects_in(text, start, end):
    """Yield (start, end) of every balanced {...} object inside text[start:end], at any depth."""
    i = start
    while i < end:
        ch = text[i]
        if ch == '"':
            i = skip_string(text, i)
        elif ch == "{":
            close = skip_balanced(text, i) - 1
            yield i + 1, close
            yield from objects_in(text, i + 1, close)
            i = close + 1
        else:
            i += 1


def policy_statements(block, line_of_block):
    """Yield (attrs, line) for every IAM statement object inside a resource body."""
    for s, e in objects_in(block.text, block.start, block.end):
        attrs, _ = parse_body(block.text, s, e, block.file, line_of_block)
        if "Effect" in attrs:
            yield attrs, attrs["Effect"][1]


# ── Rules ───────────────────────────────────────────────────────────────────

class Scanner:
    def __init__(self, blocks_by_file, line_lookup):
        self.findings = []
        self.blocks_by_file = blocks_by_file
        self.line_lookup = line_lookup
        self.resources = {}   # type -> list[Block]
        self.data_sources = {}
        self.providers = []
        for blocks in blocks_by_file.values():
            for b in blocks:
                if b.kind == "resource" and len(b.labels) == 2:
                    self.resources.setdefault(b.labels[0], []).append(b)
                elif b.kind == "data" and len(b.labels) == 2:
                    self.data_sources.setdefault(b.labels[0], []).append(b)
                elif b.kind == "provider":
                    self.providers.append(b)

    def add(self, rule, severity, control, message, block, line=None):
        self.findings.append(Finding(rule, severity, control, message, block.file, line or block.line))

    def of(self, rtype):
        return self.resources.get(rtype, [])

    def run(self):
        self.check_security_groups()
        self.check_policies()
        self.check_policy_documents()
        self.check_buckets()
        self.check_audit_and_detection()
        self.check_identity()
        self.check_compute()
        self.check_listeners()
        self.check_waf()
        self.check_providers()
        order = {s: i for i, s in enumerate(SEVERITIES)}
        self.findings.sort(key=lambda f: (-order[f.severity], f.file, f.line))
        return self.findings

    # SC-7: network boundary
    def check_security_groups(self):
        def ports(from_v, to_v, proto):
            if literal(proto) in ("-1", "all"):
                return None
            try:
                return int(literal(from_v)), int(literal(to_v))
            except (TypeError, ValueError):
                return None

        def judge(blk, rule_block, from_v, to_v, proto, cidrs, direction):
            rng = ports(from_v, to_v, proto)
            where = f"{blk.address} {direction}"
            world = bool(set(cidrs) & WORLD_CIDRS)
            if direction == "ingress" and cidrs and not world:
                admin = ADMIN_PORTS if rng is None else ADMIN_PORTS & set(range(rng[0], rng[1] + 1))
                if admin:
                    self.add("TF-AC17-01", "MEDIUM", "AC-17",
                             f"{where}: remote administration port {', '.join(map(str, sorted(admin)))} reachable over the network; "
                             "use SSM Session Manager", blk, rule_block.line)
            if not world:
                return
            if direction == "ingress":
                if rng is None or not set(range(rng[0], rng[1] + 1)) <= WEB_PORTS:
                    label = "all ports" if rng is None else f"port {rng[0]}" + (f"-{rng[1]}" if rng[1] != rng[0] else "")
                    self.add("TF-SC7-01", "CRITICAL", "SC-7",
                             f"{where}: {label} open to the internet", blk, rule_block.line)
            elif rng is None:
                self.add("TF-SC7-02", "MEDIUM", "SC-7(5)",
                         f"{where}: unrestricted egress to the internet on all protocols", blk, rule_block.line)

        for sg in self.of("aws_security_group"):
            for c in sg.children:
                if c.kind in ("ingress", "egress"):
                    cidrs = strings_in(c.attr("cidr_blocks")) + strings_in(c.attr("ipv6_cidr_blocks"))
                    judge(sg, c, c.attr("from_port"), c.attr("to_port"), c.attr("protocol"), cidrs, c.kind)
        for r in self.of("aws_security_group_rule"):
            cidrs = strings_in(r.attr("cidr_blocks")) + strings_in(r.attr("ipv6_cidr_blocks"))
            judge(r, r, r.attr("from_port"), r.attr("to_port"), r.attr("protocol"), cidrs, literal(r.attr("type")))
        for rtype, direction in (("aws_vpc_security_group_ingress_rule", "ingress"),
                                 ("aws_vpc_security_group_egress_rule", "egress")):
            for r in self.of(rtype):
                cidrs = [literal(r.attr("cidr_ipv4")), literal(r.attr("cidr_ipv6"))]
                judge(r, r, r.attr("from_port"), r.attr("to_port"), r.attr("ip_protocol"), [c for c in cidrs if c], direction)

    # AC-6: wildcard and public grants in any inline policy document
    def check_policies(self):
        for rtype, blocks in self.resources.items():
            for b in blocks:
                lookup = self.line_lookup[b.file]
                for attrs, line in policy_statements(b, lookup):
                    if literal(attrs["Effect"][0]) != "Allow":
                        continue
                    actions = strings_in(attrs.get("Action", ("", 0))[0])
                    wild = [a for a in actions if a == "*" or re.fullmatch(r"[\w-]+:\*", a)]
                    if wild:
                        self.add("TF-AC6-01", "HIGH", "AC-6",
                                 f"{b.address}: Allow statement grants wildcard action {', '.join(wild)}", b, line)
                    if "NotAction" in attrs:
                        self.add("TF-AC6-02", "HIGH", "AC-6",
                                 f"{b.address}: Allow statement uses NotAction (grants everything not listed)", b, line)
                    principal = attrs.get("Principal", ("", 0))[0]
                    if "Condition" not in attrs and (literal(principal) == "*" or re.search(r'AWS"?\s*[=:]\s*"\*"', principal)):
                        self.add("TF-AC3-01", "CRITICAL", "AC-3",
                                 f"{b.address}: Allow statement grants access to any principal (\"*\")", b, line)

    # AC-6 / AC-3 for policies written as aws_iam_policy_document data sources
    def check_policy_documents(self):
        for doc in self.data_sources.get("aws_iam_policy_document", []):
            for st in doc.children:
                if st.kind != "statement" or (literal(st.attr("effect")) or "Allow") != "Allow":
                    continue
                address = f"data.{doc.address}"
                wild = [a for a in strings_in(st.attr("actions")) if a == "*" or re.fullmatch(r"[\w-]+:\*", a)]
                if wild:
                    self.add("TF-AC6-01", "HIGH", "AC-6",
                             f"{address}: Allow statement grants wildcard action {', '.join(wild)}", doc, st.line)
                if st.attr("not_actions"):
                    self.add("TF-AC6-02", "HIGH", "AC-6",
                             f"{address}: Allow statement uses not_actions (grants everything not listed)", doc, st.line)
                public = any("*" in strings_in(p.attr("identifiers")) for p in st.children if p.kind == "principals")
                if public and not st.child("condition"):
                    self.add("TF-AC3-01", "CRITICAL", "AC-3",
                             f"{address}: Allow statement grants access to any principal (\"*\")", doc, st.line)

    # AC-3, CP-9, SC-8, SC-28, AU-12: S3 bucket posture
    def check_buckets(self):
        def by_bucket(rtype):
            out = {}
            for r in self.of(rtype):
                name = referenced_name(r.attr("bucket"), "aws_s3_bucket")
                if name:
                    out.setdefault(name, []).append(r)
            return out

        pab = by_bucket("aws_s3_bucket_public_access_block")
        versioning = by_bucket("aws_s3_bucket_versioning")
        policies = by_bucket("aws_s3_bucket_policy")
        sse = by_bucket("aws_s3_bucket_server_side_encryption_configuration")
        logging = by_bucket("aws_s3_bucket_logging")
        log_targets = {referenced_name(r.attr("target_bucket"), "aws_s3_bucket") for r in self.of("aws_s3_bucket_logging")}
        tls_locals = any("aws:SecureTransport" in b.body for b in self._locals())

        for bucket in self.of("aws_s3_bucket"):
            name = bucket.labels[1]
            if literal(bucket.attr("acl")) in ("public-read", "public-read-write", "authenticated-read"):
                self.add("TF-AC3-02", "CRITICAL", "AC-3", f"{bucket.address}: public canned ACL", bucket, bucket.attr_line("acl"))

            if name not in pab:
                self.add("TF-AC3-03", "HIGH", "AC-3", f"{bucket.address}: no public access block", bucket)
            for p in pab.get(name, []):
                for flag in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
                    if literal(p.attr(flag)) != "true":
                        self.add("TF-AC3-04", "CRITICAL", "AC-3",
                                 f"{p.address}: {flag} is not true", p, p.attr_line(flag))

            enabled = any(literal(v.child("versioning_configuration").attr("status")) == "Enabled"
                          for v in versioning.get(name, []) if v.child("versioning_configuration"))
            if not enabled:
                self.add("TF-CP9-01", "HIGH", "CP-9", f"{bucket.address}: versioning is not enabled", bucket)

            pols = policies.get(name, [])
            if not any("aws:SecureTransport" in p.body or ("local." in p.body and tls_locals) for p in pols):
                self.add("TF-SC8-01", "HIGH", "SC-8",
                         f"{bucket.address}: no bucket policy denies requests without TLS (aws:SecureTransport)", bucket)

            if name not in sse:
                self.add("TF-SC28-01", "MEDIUM", "SC-28",
                         f"{bucket.address}: no explicit server-side encryption configuration", bucket)
            elif re.search(r'DataClass"?\s*=\s*"[^"]*(PII|PHI)', bucket.attr("tags") or ""):
                kms = any(
                    literal(d.attr("sse_algorithm")) in ("aws:kms", "aws:kms:dsse")
                    for cfg in sse[name] for rule in cfg.children if rule.kind == "rule"
                    for d in rule.children if d.kind == "apply_server_side_encryption_by_default")
                if not kms:
                    self.add("TF-SC28-03", "MEDIUM", "SC-28(1)",
                             f"{bucket.address}: PII/PHI bucket is not encrypted with a KMS key", bucket)
            if name not in logging and name not in log_targets:
                self.add("TF-AU12-01", "MEDIUM", "AU-12", f"{bucket.address}: server access logging is not enabled", bucket)

    def _locals(self):
        return [b for blocks in self.blocks_by_file.values() for b in blocks if b.kind == "locals"]

    # AU-2, AU-9(3), AU-12, SI-4: audit plane and detection must exist
    def check_audit_and_detection(self):
        if not self.resources:
            return
        anchor = next(iter(next(iter(self.resources.values()))))
        trails = self.of("aws_cloudtrail")
        if not trails:
            self.add("TF-AU2-01", "HIGH", "AU-2", "no aws_cloudtrail: API activity is not recorded", anchor, 1)
        for t in trails:
            if literal(t.attr("enable_log_file_validation")) != "true":
                self.add("TF-AU9-01", "HIGH", "AU-9(3)", f"{t.address}: log file integrity validation is off", t)
            if literal(t.attr("is_multi_region_trail")) != "true":
                self.add("TF-AU2-02", "MEDIUM", "AU-2", f"{t.address}: trail is not multi-region", t)
        if self.of("aws_vpc") and not self.of("aws_flow_log"):
            self.add("TF-AU12-02", "HIGH", "AU-12", "no aws_flow_log: VPC traffic is not recorded", self.of("aws_vpc")[0])
        if not self.of("aws_guardduty_detector"):
            self.add("TF-SI4-01", "HIGH", "SI-4", "no aws_guardduty_detector: threat detection is off", anchor, 1)

    # IA-2(1), IA-5(1): human identities
    def check_identity(self):
        users = self.of("aws_iam_user")
        if not users:
            return
        if not self.of("aws_iam_account_password_policy"):
            self.add("TF-IA5-01", "HIGH", "IA-5(1)", "IAM users exist but no aws_iam_account_password_policy is defined", users[0])
        mfa_enforced = False
        for rtype in ("aws_iam_group_policy", "aws_iam_user_policy", "aws_iam_policy"):
            for b in self.of(rtype):
                for attrs, _ in policy_statements(b, self.line_lookup[b.file]):
                    if literal(attrs["Effect"][0]) == "Deny" and "aws:MultiFactorAuthPresent" in attrs.get("Condition", ("", 0))[0]:
                        mfa_enforced = True
        if not mfa_enforced:
            self.add("TF-IA2-01", "HIGH", "IA-2(1)",
                     "IAM users exist but no policy denies actions when aws:MultiFactorAuthPresent is false", users[0])

    # SC-7 / CM-7 (IMDSv2) and SC-28 (volume encryption)
    def check_compute(self):
        for b in self.of("aws_instance") + self.of("aws_launch_template"):
            md = b.child("metadata_options")
            if not md or literal(md.attr("http_tokens")) != "required":
                self.add("TF-CM7-01", "MEDIUM", "CM-7", f"{b.address}: IMDSv2 not enforced (metadata_options.http_tokens)", b)
            if b.labels[0] == "aws_instance":
                root = b.child("root_block_device")
                encrypted = root and literal(root.attr("encrypted")) == "true"
            else:
                encrypted = any(
                    m.child("ebs") and literal(m.child("ebs").attr("encrypted")) == "true"
                    for m in b.children if m.kind == "block_device_mappings")
            if not encrypted and not self.of("aws_ebs_encryption_by_default"):
                self.add("TF-SC28-02", "MEDIUM", "SC-28", f"{b.address}: root volume encryption is not enabled", b)

    # SC-8: plaintext listeners
    def check_listeners(self):
        for b in self.of("aws_lb_listener") + self.of("aws_alb_listener"):
            if literal(b.attr("protocol")) != "HTTP":
                continue
            action = b.child("default_action")
            if not action or literal(action.attr("type")) != "redirect":
                self.add("TF-SC8-02", "HIGH", "SC-8", f"{b.address}: HTTP listener serves traffic instead of redirecting to HTTPS", b)

    # SC-7 / SI-4: internet-facing application load balancers need a web application firewall
    def check_waf(self):
        protected = {referenced_name(a.attr("resource_arn"), "aws_lb")
                     for a in self.of("aws_wafv2_web_acl_association")}
        for lb in self.of("aws_lb") + self.of("aws_alb"):
            if literal(lb.attr("internal")) == "true":
                continue
            if (literal(lb.attr("load_balancer_type")) or "application") != "application":
                continue
            if lb.labels[1] not in protected:
                self.add("TF-SC7-03", "MEDIUM", "SC-7",
                         f"{lb.address}: internet-facing load balancer has no WAF web ACL association", lb)

    # IA-5(7): credentials embedded in configuration
    def check_providers(self):
        for p in self.providers:
            alias = literal(p.attr("alias"))
            name = ".".join(p.labels) + (f".{alias}" if alias else "")
            for key in ("access_key", "secret_key", "token"):
                value = p.attr(key)
                if value and value.startswith('"'):
                    self.add("TF-IA5-02", "MEDIUM", "IA-5(7)",
                             f"provider {name}: static {key} in configuration", p, p.attr_line(key))


# ── Output ──────────────────────────────────────────────────────────────────

def to_sarif(findings):
    level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "INFO": "note"}
    rules = {}
    for f in findings:
        rules.setdefault(f.rule, {"id": f.rule, "properties": {"nist-800-53": f.control}})
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "nist-iac-scan", "rules": list(rules.values())}},
            "results": [{
                "ruleId": f.rule,
                "level": level[f.severity],
                "message": {"text": f"[{f.severity}] [{f.control}] {f.message}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line},
                }}],
            } for f in findings],
        }],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", type=Path,
                        help="directories or .tf files to scan (default: the directory containing this script)")
    parser.add_argument("--fail-on", choices=SEVERITIES, default="HIGH",
                        help="lowest severity that makes the scan fail (default: HIGH)")
    parser.add_argument("--sarif", type=Path, help="also write results as SARIF 2.1.0 to this file")
    args = parser.parse_args(argv)

    targets = args.paths or [Path(__file__).resolve().parent]
    files = []
    for t in targets:
        if t.is_file() and t.suffix == ".tf":
            files.append(t)
        elif t.is_dir():
            files.extend(p for p in sorted(t.rglob("*.tf")) if ".terraform" not in p.parts)
    if not files:
        print(f"ERROR: no .tf files found under {', '.join(map(str, targets))}", file=sys.stderr)
        return 2

    root = (targets[0] if targets[0].is_dir() else targets[0].parent).resolve()
    blocks_by_file, line_lookup = {}, {}
    print("=== NIST SP 800-53 IaC COMPLIANCE SCAN ===")
    for f in files:
        f = f.resolve()
        print(f"Scanning {f.relative_to(root) if f.is_relative_to(root) else f}")
        rel, blocks, line_of = parse_file(f, root)
        blocks_by_file[rel], line_lookup[rel] = blocks, line_of

    findings = Scanner(blocks_by_file, line_lookup).run()

    print()
    for f in findings:
        print(f" [{f.severity:<8}] {f.rule:<10} {f.control:<8} {f.file}:{f.line}  {f.message}")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in reversed(SEVERITIES)}
    print("\n=== SCAN COMPLETE: " + ", ".join(f"{n} {s}" for s, n in counts.items()) + " ===")

    if args.sarif:
        args.sarif.write_text(json.dumps(to_sarif(findings), indent=2), encoding="utf-8")

    threshold = SEVERITIES.index(args.fail_on)
    failing = [f for f in findings if SEVERITIES.index(f.severity) >= threshold]
    if failing:
        print(f"FAIL: {len(failing)} finding(s) at or above {args.fail_on}")
        return 1
    print(f"PASS: no findings at or above {args.fail_on}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
