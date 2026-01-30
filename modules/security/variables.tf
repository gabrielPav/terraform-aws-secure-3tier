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

variable "tags" {
  description = "Tags to apply"
  type        = map(string)
  default     = {}
}
