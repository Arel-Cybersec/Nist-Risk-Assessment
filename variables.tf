variable "region" {
  description = "AWS region for all resources."
  type        = string
  default     = "us-east-1"
}

variable "dr_region" {
  description = "Second region holding replicated data and backup copies (F-12). Must differ from region."
  type        = string
  default     = "us-west-2"

  validation {
    condition     = var.dr_region != var.region
    error_message = "dr_region must be different from region."
  }
}

variable "domain_name" {
  description = "Public hostname for the application (F-13), e.g. app.example.com. Empty: no certificate or HTTPS listener is created."
  type        = string
  default     = ""
}

variable "route53_zone_id" {
  description = "Route 53 hosted zone that owns domain_name; used for DNS validation of the ACM certificate."
  type        = string
  default     = ""

  validation {
    condition     = var.domain_name == "" || var.route53_zone_id != ""
    error_message = "route53_zone_id is required when domain_name is set."
  }
}

variable "deletion_protection" {
  description = "Protect the load balancer from deletion. Set false before terraform destroy."
  type        = bool
  default     = true
}

variable "use_localstack" {
  description = "true: target LocalStack on localhost. false: deploy to the AWS account in the current credentials."
  type        = bool
  default     = true
}

variable "alert_email" {
  description = "Optional address subscribed to security alerts (GuardDuty, Config, drift). Must confirm the SNS email."
  type        = string
  default     = ""
}

variable "localstack_endpoint" {
  description = "LocalStack edge endpoint."
  type        = string
  default     = "http://localhost:4566"
}

variable "localstack_access_key" {
  description = "LocalStack access key. Set TF_VAR_localstack_access_key; LocalStack accepts any value."
  type        = string
  default     = "test"
  sensitive   = true
}

variable "localstack_secret_key" {
  description = "LocalStack secret key. Set TF_VAR_localstack_secret_key; LocalStack accepts any value."
  type        = string
  default     = "test"
  sensitive   = true
}

variable "app_ami_id" {
  description = "AMI for the application server. Use a current, hardened image in a real account."
  type        = string
  default     = "ami-0c55b159cbfafe1f0"
}

variable "log_retention_days" {
  description = "Retention for CloudWatch audit and flow logs (365 meets common audit requirements)."
  type        = number
  default     = 365
}
