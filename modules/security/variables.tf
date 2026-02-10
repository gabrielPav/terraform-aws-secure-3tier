variable "project_name" {
  description = "Project name"
  type        = string
}

variable "environment" {
  description = "Environment name"
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

variable "enable_object_lock_cloudtrail" {
  description = "Enable S3 Object Lock (Governance Mode) on the CloudTrail logs bucket. Recommended for compliance workloads. WARNING: flipping this on an existing bucket destroys and recreates it — all objects are lost."
  type        = bool
  default     = false
}

variable "object_lock_cloudtrail_retention_days" {
  description = "Number of days to retain CloudTrail log objects under Governance Mode Object Lock."
  type        = number
  default     = 30

  validation {
    condition     = var.object_lock_cloudtrail_retention_days >= 1
    error_message = "Object Lock retention must be at least 1 day."
  }
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

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags to apply"
  type        = map(string)
  default     = {}
}
