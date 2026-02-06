variable "project_name" {
  description = "Project name"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for aws:SourceVpc IAM conditions"
  type        = string
}

variable "s3_bucket_name" {
  description = "S3 bucket name for CloudTrail"
  type        = string
}

variable "cloudtrail_name" {
  description = "CloudTrail name"
  type        = string
}

variable "enable_cloudtrail" {
  description = "Enable CloudTrail"
  type        = bool
  default     = true
}

variable "enable_cloudwatch" {
  description = "Enable CloudWatch integration"
  type        = bool
  default     = true
}

variable "s3_access_logs_bucket_id" {
  description = "Centralized S3 access logs bucket ID for S3 server access logging"
  type        = string
  default     = ""
}

variable "enable_s3_access_logging" {
  description = "Enable S3 server access logging for CloudTrail bucket"
  type        = bool
  default     = true
}

variable "enable_cloudtrail_sns_notifications" {
  description = "Enable SNS notifications for CloudTrail events and security alarms"
  type        = bool
  default     = false
}

variable "alarm_notification_email" {
  description = "Email address to receive security alarm notifications. Required when enable_cloudtrail_sns_notifications is true."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply"
  type        = map(string)
  default     = {}
}
