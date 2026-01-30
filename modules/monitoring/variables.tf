variable "project_name" {
  description = "Project name"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "alb_arn" {
  description = "ALB ARN"
  type        = string
  default     = ""
}

variable "asg_name" {
  description = "Auto Scaling Group name"
  type        = string
  default     = ""
}

variable "rds_instance_id" {
  description = "RDS instance ID"
  type        = string
  default     = ""
}

variable "enable_rds_alarm" {
  description = "Enable RDS CloudWatch alarm"
  type        = bool
  default     = true
}

variable "enable_alarms" {
  description = "Enable CloudWatch alarms"
  type        = bool
  default     = true
}

variable "enable_dashboard" {
  description = "Enable CloudWatch dashboard"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Log retention in days"
  type        = number
  default     = 30
}

variable "kms_key_arn" {
  description = "KMS key ARN for CloudWatch log group encryption"
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply"
  type        = map(string)
  default     = {}
}
