# OPA policy gate for the Terraform in this repository (F-08: preventive guardrails).
# Run by CI with:  conftest test --parser hcl2 --combine *.tf
# --combine gives one input: [{"path": "s3.tf", "contents": {...}}, ...], so rules can see
# every file at once and catch controls that are missing entirely.
package main

import rego.v1

# resources[type][name] = body, merged across all files
resources[t][n] := body if {
	some f in input
	some t, by_name in f.contents.resource
	some n, body in by_name
}

as_list(x) := x if is_array(x)

as_list(x) := [x] if not is_array(x)

refers_to(body, attr, t, n) if contains(sprintf("%v", [body[attr]]), sprintf("%s.%s.", [t, n]))

open_cidr(r) if {
	some c in array.concat(object.get(r, "cidr_blocks", []), object.get(r, "ipv6_cidr_blocks", []))
	c in {"0.0.0.0/0", "::/0"}
}

open_cidr(r) if r.cidr_ipv4 == "0.0.0.0/0"

open_cidr(r) if r.cidr_ipv6 == "::/0"

covers(r, port) if object.get(r, "protocol", object.get(r, "ip_protocol", "")) in {"-1", "all"}

covers(r, port) if {
	r.from_port <= port
	port <= r.to_port
}

ingress_rules contains [addr, r] if {
	some n, sg in resources.aws_security_group
	some r in as_list(object.get(sg, "ingress", []))
	addr := sprintf("aws_security_group.%s", [n])
}

ingress_rules contains [addr, r] if {
	some n, r in resources.aws_security_group_rule
	r.type == "ingress"
	addr := sprintf("aws_security_group_rule.%s", [n])
}

ingress_rules contains [addr, r] if {
	some n, r in resources.aws_vpc_security_group_ingress_rule
	addr := sprintf("aws_vpc_security_group_ingress_rule.%s", [n])
}

# ── F-01 Public data exposure ─────────────────────────────────────────
deny contains msg if {
	some n, b in resources.aws_s3_bucket_public_access_block
	some a in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
	b[a] == false
	msg := sprintf("F-01 aws_s3_bucket_public_access_block.%s: %s must be true", [n, a])
}

deny contains msg if {
	some n, b in resources.aws_s3_bucket_policy
	regex.match(`Effect\s*=\s*"Allow"[^{}]*Principal\s*=\s*"\*"|Principal\s*=\s*"\*"[^{}]*Effect\s*=\s*"Allow"`, b.policy)
	msg := sprintf("F-01 aws_s3_bucket_policy.%s: Allow statement for any principal (\"*\")", [n])
}

deny contains msg if {
	some n, _ in resources.aws_s3_bucket
	not any_refers("aws_s3_bucket_public_access_block", "bucket", "aws_s3_bucket", n)
	msg := sprintf("F-01 aws_s3_bucket.%s: no public access block", [n])
}

any_refers(rt, attr, t, n) if {
	some _, r in resources[rt]
	refers_to(r, attr, t, n)
}

# ── F-02 Excessive privilege ─────────────────────────────────────────
deny contains msg if {
	some t in ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_group_policy", "aws_iam_user_policy"]
	some n, p in resources[t]
	regex.match(`Action\s*=\s*(\[[^\]]*)?"\*"`, p.policy)
	msg := sprintf("F-02 %s.%s: policy allows all actions (\"*\")", [t, n])
}

deny contains msg if {
	some n, _ in resources.aws_iam_user
	msg := sprintf("F-02 aws_iam_user.%s: long-lived IAM user; use federated roles with MFA", [n])
}

# ── F-03 Encryption at rest ──────────────────────────────────────────
deny contains msg if {
	some n, _ in resources.aws_s3_bucket
	not any_refers("aws_s3_bucket_server_side_encryption_configuration", "bucket", "aws_s3_bucket", n)
	msg := sprintf("F-03 aws_s3_bucket.%s: no server-side encryption", [n])
}

deny contains msg if {
	some n, i in resources.aws_instance
	not object.get(object.get(i, "root_block_device", {}), "encrypted", false) == true
	msg := sprintf("F-03 aws_instance.%s: root volume not encrypted", [n])
}

# ── F-04 Audit logging ───────────────────────────────────────────────
deny contains "F-04 no aws_cloudtrail with enable_log_file_validation = true" if {
	count(input) > 0
	not validated_trail
}

validated_trail if {
	some _, t in resources.aws_cloudtrail
	t.enable_log_file_validation == true
}

deny contains msg if {
	some n, _ in resources.aws_vpc
	not any_refers("aws_flow_log", "vpc_id", "aws_vpc", n)
	msg := sprintf("F-04 aws_vpc.%s: no VPC flow logs", [n])
}

# ── F-05 Network exposure ────────────────────────────────────────────
deny contains msg if {
	some rule in ingress_rules
	[addr, r] := rule
	open_cidr(r)
	some port in [22, 3389]
	covers(r, port)
	msg := sprintf("F-05 %s: port %d open to the internet", [addr, port])
}

warn contains msg if {
	some rule in ingress_rules
	[addr, r] := rule
	open_cidr(r)
	covers(r, 80)
	msg := sprintf("F-05 %s: plaintext HTTP (80) open to the internet", [addr])
}

# ── F-06 Instance hardening ──────────────────────────────────────────
deny contains msg if {
	some n, i in resources.aws_instance
	not object.get(object.get(i, "metadata_options", {}), "http_tokens", "") == "required"
	msg := sprintf("F-06 aws_instance.%s: IMDSv2 not required", [n])
}

# ── F-07 Runtime detection ───────────────────────────────────────────
deny contains "F-07 no enabled aws_guardduty_detector" if {
	count(input) > 0
	not guardduty_on
}

guardduty_on if {
	some _, d in resources.aws_guardduty_detector
	d.enable == true
}

deny contains "F-07 no aws_config_configuration_recorder (configuration drift is not monitored)" if {
	count(input) > 0
	count(object.get(resources, "aws_config_configuration_recorder", {})) == 0
}

# ── F-08 Preventive guardrails ───────────────────────────────────────
deny contains msg if {
	some n, r in resources.aws_iam_role
	regex.match(`Principal\s*=\s*\{\s*AWS`, r.assume_role_policy)
	not r.permissions_boundary
	msg := sprintf("F-08 aws_iam_role.%s: human-assumable role without a permissions boundary", [n])
}
