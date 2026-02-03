# ============================================================================
# Load Balancer Module - Variables
# ============================================================================
# This file defines all input variables for the ALB module including
# HTTPS/SSL configuration with ACM certificate and Route53 DNS validation.
# ============================================================================

# ============================================================================
# General Configuration Variables
# ============================================================================

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, production)"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID where the ALB will be deployed"
  type        = string
}

variable "public_subnet_ids" {
  description = "List of public subnet IDs for external ALB placement"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for internal ALB placement"
  type        = list(string)
}

variable "target_group_arns" {
  description = "List of target group ARNs to forward traffic to"
  type        = list(string)
}

# ============================================================================
# ALB Configuration Variables
# ============================================================================

variable "alb_internal" {
  description = "Whether the ALB is internal (true) or internet-facing (false)"
  type        = bool
  default     = false
}

variable "enable_access_logs" {
  description = "Enable ALB access logs to S3"
  type        = bool
  default     = true
}

variable "s3_access_logs_bucket_id" {
  description = "Centralized S3 access logs bucket ID for S3 server access logging"
  type        = string
}

variable "enable_deletion_protection" {
  description = "Enable deletion protection for the ALB"
  type        = bool
  default     = false
}

variable "enable_drop_invalid_headers" {
  description = "Enable dropping of invalid HTTP headers"
  type        = bool
  default     = false
}

variable "enable_http2" {
  description = "Enable HTTP/2 protocol support"
  type        = bool
  default     = true
}

variable "enable_cross_zone" {
  description = "Enable cross-zone load balancing"
  type        = bool
  default     = true
}

# ============================================================================
# HTTPS/SSL Configuration Variables
# ============================================================================
# These variables enable automatic SSL certificate provisioning via ACM
# with DNS validation through Route53.
# ============================================================================

variable "enable_https" {
  description = "Enable HTTPS listener on port 443"
  type        = bool
  default     = false
}

variable "certificate_arn" {
  description = <<-EOT
    Existing SSL certificate ARN to use for HTTPS listener.
    If provided along with domain_name, this takes precedence over
    creating a new ACM certificate.
  EOT
  type        = string
  default     = ""
}

variable "domain_name" {
  description = <<-EOT
    Fully Qualified Domain Name (FQDN) for the HTTPS endpoint.
    When provided (and certificate_arn is empty), Terraform will:
    1. Request an ACM certificate for this domain
    2. Look up the Route53 hosted zone for DNS validation
    3. Create DNS records for certificate validation
    4. Configure the ALB HTTPS listener with the validated certificate

    Example: "app.example.com" or "www.mysite.org"

    Note: The Route53 hosted zone for the root domain must already exist.
    For "app.example.com", the hosted zone "example.com" must exist.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.domain_name == "" || can(regex("^[a-zA-Z0-9][a-zA-Z0-9-]*(\\.[a-zA-Z0-9][a-zA-Z0-9-]*)+$", var.domain_name))
    error_message = "Domain name must be a valid FQDN (e.g., 'app.example.com')."
  }
}

variable "create_route53_zone" {
  description = <<-EOT
    Whether to create a new Route53 hosted zone or use an existing one.

    - true:  Creates a new hosted zone. You must manually update your domain
             registrar's nameservers after apply (can take up to 48 hours for
             DNS propagation before certificate validates).

    - false: Uses an existing hosted zone. The hosted zone must already exist
             and be properly configured. Certificate validation is almost
             immediate (2-5 minutes).

    Default is false (use existing zone) for faster certificate validation.
  EOT
  type        = bool
  default     = false
}

variable "ssl_policy" {
  description = <<-EOT
    SSL/TLS policy for the HTTPS listener.
    Recommended policies:
    - ELBSecurityPolicy-TLS13-1-2-2021-06: TLS 1.2 and 1.3 (recommended)
    - ELBSecurityPolicy-TLS13-1-2-Res-2021-06: TLS 1.2 and 1.3 with restricted ciphers
    See: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html
  EOT
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

variable "redirect_http_to_https" {
  description = <<-EOT
    When HTTPS is enabled, redirect all HTTP (port 80) traffic to HTTPS (port 443).
    If false, HTTP listener will forward traffic to target group instead of redirecting.
  EOT
  type        = bool
  default     = true
}

# ============================================================================
# Tagging Variables
# ============================================================================

variable "tags" {
  description = "Tags to apply to all resources created by this module"
  type        = map(string)
  default     = {}
}
