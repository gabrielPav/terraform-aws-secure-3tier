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

variable "s3_bucket_id" {
  description = "S3 bucket ID (name) for the assets bucket. Used to create a bucket policy granting CloudFront OAC read access."
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

variable "s3_access_logs_bucket_arn" {
  description = "S3 access logs bucket ARN for CloudFront standard logging v2"
  type        = string
}

variable "enable_waf" {
  description = "Enable WAF"
  type        = bool
  default     = true
}

variable "us_east_1_kms_key_arn" {
  description = "KMS key ARN in us-east-1 for encrypting CloudWatch log groups (WAF logs). Required because CloudFront WAF logs must be in us-east-1."
  type        = string
}

variable "enable_waf_logging" {
  description = "Enable WAF logging to CloudWatch Logs. Logs are stored in us-east-1 (required for CloudFront WAF)."
  type        = bool
  default     = true
}

variable "waf_log_retention_days" {
  description = "Number of days to retain WAF logs in CloudWatch"
  type        = number
  default     = 30
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

# ACM cert settings

variable "domain_name" {
  description = "Custom domain name for CloudFront distribution. Required for TLS 1.2 enforcement."
  type        = string
}

variable "aws_region" {
  description = "AWS region where the infrastructure is deployed. Used to determine if a separate CloudFront ACM certificate is needed."
  type        = string
}

variable "route53_zone_id" {
  description = "Route53 hosted zone ID for DNS validation of CloudFront ACM certificate."
  type        = string
}

variable "alb_certificate_arn" {
  description = "ARN of the ALB's ACM certificate. Reused for CloudFront when deploying to us-east-1."
  type        = string
}
