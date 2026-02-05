variable "project_name" {
  description = "Project name"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "alb_dns_name" {
  description = "ALB DNS name"
  type        = string
}

variable "alb_zone_id" {
  description = "ALB zone ID"
  type        = string
}

variable "s3_bucket_domain_name" {
  description = "S3 bucket domain name"
  type        = string
}

variable "enable_cloudfront" {
  description = "Enable CloudFront"
  type        = bool
  default     = true
}

variable "price_class" {
  description = "CloudFront price class"
  type        = string
  default     = "PriceClass_All"
}

variable "enable_https" {
  description = "Enable HTTPS"
  type        = bool
  default     = true
}

variable "enable_compression" {
  description = "Enable compression"
  type        = bool
  default     = true
}

variable "enable_logging" {
  description = "Enable logging"
  type        = bool
  default     = true
}

variable "s3_access_logs_bucket_domain" {
  description = "S3 access logs bucket domain name for CloudFront logging"
  type        = string
}

variable "enable_waf" {
  description = "Enable WAF"
  type        = bool
  default     = false
}

variable "enable_geo_restriction" {
  description = "Enable geo restriction for CloudFront distribution"
  type        = bool
  default     = false
}

variable "geo_restriction_type" {
  description = "Type of geo restriction: whitelist or blacklist"
  type        = string
  default     = "whitelist"

  validation {
    condition     = contains(["whitelist", "blacklist"], var.geo_restriction_type)
    error_message = "geo_restriction_type must be either 'whitelist' or 'blacklist'."
  }
}

variable "geo_restriction_locations" {
  description = "List of ISO 3166-1-alpha-2 country codes for geo restriction"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags to apply"
  type        = map(string)
  default     = {}
}
