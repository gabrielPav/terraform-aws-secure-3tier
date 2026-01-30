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

variable "public_subnet_ids" {
  description = "Public subnet IDs"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnet IDs"
  type        = list(string)
}

variable "target_group_arns" {
  description = "Target group ARNs"
  type        = list(string)
}

variable "alb_internal" {
  description = "Internal ALB"
  type        = bool
  default     = false
}

variable "enable_access_logs" {
  description = "Enable access logs"
  type        = bool
  default     = true
}

variable "s3_access_logs_bucket_id" {
  description = "Centralized S3 access logs bucket ID for S3 server access logging"
  type        = string
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection"
  type        = bool
  default     = false
}

variable "enable_drop_invalid_headers" {
  description = "Enable Drop Invalid Headers"
  type        = bool
  default     = false
}

variable "enable_http2" {
  description = "Enable HTTP/2"
  type        = bool
  default     = true
}

variable "enable_cross_zone" {
  description = "Enable cross-zone load balancing"
  type        = bool
  default     = true
}

variable "enable_https" {
  description = "Enable HTTPS"
  type        = bool
  default     = false
}

variable "certificate_arn" {
  description = "SSL certificate ARN"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply"
  type        = map(string)
  default     = {}
}
