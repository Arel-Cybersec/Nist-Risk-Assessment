# Run: conftest verify -p policy
package main

import rego.v1

wrap(resource) := [{"path": "t.tf", "contents": {"resource": resource}}]

# Baseline so project-level rules (CloudTrail, GuardDuty, Config) are satisfied
base := {
	"aws_cloudtrail": {"t": {"enable_log_file_validation": true}},
	"aws_guardduty_detector": {"g": {"enable": true}},
	"aws_config_configuration_recorder": {"r": {"name": "r"}},
	"aws_backup_plan": {"p": {"name": "p"}},
	"aws_backup_restore_testing_plan": {"t": {"name": "t"}},
}

test_clean_baseline_passes if {
	count(deny) == 0 with input as wrap(base)
}

test_human_role_without_boundary_denied if {
	r := object.union(base, {"aws_iam_role": {"dev": {"assume_role_policy": `${jsonencode({Statement = [{Principal = { AWS = "arn:aws:iam::1:root" }}]})}`}}})
	"F-08 aws_iam_role.dev: human-assumable role without a permissions boundary" in deny with input as wrap(r)
}

test_human_role_with_boundary_allowed if {
	r := object.union(base, {"aws_iam_role": {"dev": {
		"assume_role_policy": `${jsonencode({Statement = [{Principal = { AWS = "arn:aws:iam::1:root" }}]})}`,
		"permissions_boundary": "${aws_iam_policy.b.arn}",
	}}})
	count(deny) == 0 with input as wrap(r)
}

test_service_role_needs_no_boundary if {
	r := object.union(base, {"aws_iam_role": {"svc": {"assume_role_policy": `${jsonencode({Statement = [{Principal = { Service = "ec2.amazonaws.com" }}]})}`}}})
	count(deny) == 0 with input as wrap(r)
}

test_standalone_ssh_rule_denied if {
	r := object.union(base, {"aws_vpc_security_group_ingress_rule": {"ssh": {"from_port": 22, "to_port": 22, "ip_protocol": "tcp", "cidr_ipv4": "0.0.0.0/0"}}})
	"F-05 aws_vpc_security_group_ingress_rule.ssh: port 22 open to the internet" in deny with input as wrap(r)
}

test_all_protocols_open_denied if {
	r := object.union(base, {"aws_security_group": {"sg": {"ingress": {"from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]}}}})
	"F-05 aws_security_group.sg: port 22 open to the internet" in deny with input as wrap(r)
}

test_public_https_allowed if {
	r := object.union(base, {"aws_security_group": {"sg": {"ingress": {"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}}}})
	count(deny) == 0 with input as wrap(r)
	count(warn) == 0 with input as wrap(r)
}

test_deny_statement_with_wildcard_principal_allowed if {
	r := object.union(base, {"aws_s3_bucket_policy": {"p": {"policy": `${jsonencode({Statement = [{Effect = "Deny", Principal = "*", Action = "s3:*"}]})}`}}})
	count(deny) == 0 with input as wrap(r)
}

test_admin_wildcard_in_list_denied if {
	r := object.union(base, {"aws_iam_policy": {"p": {"policy": `${jsonencode({Statement = [{Effect = "Allow", Action = ["s3:GetObject", "*"], Resource = "*"}]})}`}}})
	"F-02 aws_iam_policy.p: policy allows all actions (\"*\")" in deny with input as wrap(r)
}

test_missing_detection_denied if {
	msgs := deny with input as wrap({"aws_vpc": {"v": {}}})
	"F-07 no enabled aws_guardduty_detector" in msgs
	"F-07 no aws_config_configuration_recorder (configuration drift is not monitored)" in msgs
	"F-04 no aws_cloudtrail with enable_log_file_validation = true" in msgs
}

test_backup_without_restore_testing_denied if {
	r := object.remove(base, ["aws_backup_restore_testing_plan"])
	"F-11 backups are never test-restored (no aws_backup_restore_testing_plan)" in deny with input as wrap(r)
}

test_weak_tls_listener_denied if {
	r := object.union(base, {"aws_lb_listener": {"l": {"protocol": "HTTPS", "ssl_policy": "ELBSecurityPolicy-2016-08"}}})
	"F-13 aws_lb_listener.l: TLS below 1.2 allowed" in deny with input as wrap(r)
}

test_http_redirect_listener_allowed if {
	r := object.union(base, {"aws_lb_listener": {"l": {"protocol": "HTTP", "default_action": {"type": "redirect"}}}})
	count(deny) == 0 with input as wrap(r)
}

test_tls13_listener_allowed if {
	r := object.union(base, {"aws_lb_listener": {"l": {"protocol": "HTTPS", "ssl_policy": "ELBSecurityPolicy-TLS13-1-3-2021-06"}}})
	count(deny) == 0 with input as wrap(r)
}
