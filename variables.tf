variable "aws_region" {
  description = "Primary AWS region for the FinTech platform."
  type        = string
  default     = "us-east-1"
}

variable "replica_region" {
  description = "Secondary region that receives the cross-region replica of the PII bucket."
  type        = string
  default     = "us-west-2"
}

variable "app_domain_name" {
  description = "Public DNS name served by the HTTPS load balancer. Create the DNS validation records from the acm_validation_records output so the certificate can be issued."
  type        = string
  default     = "app.fintech.example.com"
}

variable "audit_log_retention_days" {
  description = "Object Lock retention, in days, for CloudTrail and VPC Flow Log objects in the audit bucket."
  type        = number
  default     = 365
}

variable "audit_log_object_lock_mode" {
  description = "Object Lock mode for the audit bucket. COMPLIANCE cannot be shortened or bypassed by any user, including root, until retention expires."
  type        = string
  default     = "COMPLIANCE"

  validation {
    condition     = contains(["COMPLIANCE", "GOVERNANCE"], var.audit_log_object_lock_mode)
    error_message = "audit_log_object_lock_mode must be COMPLIANCE or GOVERNANCE."
  }
}

variable "security_alert_email" {
  description = "Optional email address subscribed to the security alerts SNS topic. Leave empty to skip the subscription."
  type        = string
  default     = ""
}
