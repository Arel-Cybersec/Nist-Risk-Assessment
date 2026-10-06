output "app_url" {
  description = "HTTPS entry point for the application."
  value       = "https://${aws_lb.app.dns_name}"
}

output "acm_validation_records" {
  description = "DNS records to create so ACM can issue the load balancer certificate."
  value = [
    for o in aws_acm_certificate.app.domain_validation_options : {
      name  = o.resource_record_name
      type  = o.resource_record_type
      value = o.resource_record_value
    }
  ]
}

output "cloudtrail_arn" {
  description = "Audit trail recording management events and PII bucket data events."
  value       = aws_cloudtrail.audit.arn
}

output "security_alerts_topic_arn" {
  description = "SNS topic receiving security alarms and high-severity GuardDuty findings."
  value       = aws_sns_topic.security_alerts.arn
}
