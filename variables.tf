variable "region" {
  description = "AWS region for all resources."
  type        = string
  default     = "us-east-1"
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
