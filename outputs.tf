output "isolation_sg_id" {
  description = "Security group used to isolate a compromised instance (incident response Playbook B)."
  value       = aws_security_group.isolation.id
}

output "security_alerts_topic_arn" {
  description = "SNS topic that receives GuardDuty, Config and tampering alerts."
  value       = aws_sns_topic.security_alerts.arn
}
