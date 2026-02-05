# ============================================================================
# Production Infrastructure - Variables
# ============================================================================

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "web-app"
}

variable "environment" {
  description = "Environment name (dev, staging, production)"
  type        = string
  default     = "production"
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be one of: dev, staging, production."
  }
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    ManagedBy = "Terraform"
  }
}

# ============================================================================
# Networking Variables
# ============================================================================

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "number_of_availability_zones" {
  description = "Number of availability zones to use"
  type        = number
  default     = 3
}

variable "enable_vpc_endpoints" {
  description = "Map of interface VPC endpoints to enable"
  type        = map(bool)
  default = {
    logs = true
  }
}

variable "enable_eic_endpoint" {
  description = "Enable EC2 Instance Connect Endpoint for secure SSH access to private instances"
  type        = bool
  default     = true
}

# ============================================================================
# Compute Variables
# ============================================================================

variable "ec2_instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.medium"
}

variable "asg_min_size" {
  description = "Minimum number of instances in ASG"
  type        = number
  default     = 2
}

variable "asg_max_size" {
  description = "Maximum number of instances in ASG"
  type        = number
  default     = 10
}

variable "asg_desired_capacity" {
  description = "Desired number of instances in ASG"
  type        = number
  default     = 2
}

variable "ebs_volume_size" {
  description = "Size of EBS volume in GB"
  type        = number
  default     = 50
}

# ============================================================================
# Database Variables
# ============================================================================

variable "rds_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "rds_engine" {
  description = "RDS engine type"
  type        = string
  default     = "mysql"
  validation {
    condition     = contains(["mysql", "postgres", "mariadb", "oracle-ee", "sqlserver-ee"], var.rds_engine)
    error_message = "RDS engine must be one of: mysql, postgres, mariadb, oracle-ee, sqlserver-ee."
  }
}

variable "rds_engine_version" {
  description = "RDS engine version"
  type        = string
  default     = "8.0"
}

variable "rds_database_name" {
  description = "Name of the RDS database"
  type        = string
  default     = "appdb"
}

variable "rds_username" {
  description = "RDS master username"
  type        = string
  default     = "dbmaster"
  sensitive   = true
}

variable "rds_allocated_storage" {
  description = "RDS allocated storage in GB"
  type        = number
  default     = 50
}

variable "rds_backup_retention_period" {
  description = "RDS backup retention period in days"
  type        = number
  default     = 7
}

# ============================================================================
# Load Balancer Variables
# ============================================================================

variable "alb_certificate_arn" {
  description = <<-EOT
    ARN of an existing SSL certificate for ALB (optional).
    If provided, this certificate will be used instead of creating a new one.
    Takes precedence over domain_name for certificate selection.
  EOT
  type        = string
  default     = ""
}

variable "domain_name" {
  description = <<-EOT
    Fully Qualified Domain Name (FQDN) for the HTTPS endpoint.
    When provided (and alb_certificate_arn is empty), Terraform will:
    1. Request an ACM certificate for this domain
    2. Look up the Route53 hosted zone for DNS validation
    3. Create DNS records for certificate validation
    4. Configure the ALB HTTPS listener with the validated certificate
    5. Create a Route53 A record pointing to the ALB

    Example: "app.example.com" or "www.webapp.io"

    Requirements:
    - The Route53 hosted zone for the root domain must already exist
    - For "app.example.com", the hosted zone "example.com" must exist
    - DNS propagation and certificate validation typically take 2-5 minutes
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.domain_name == "" || can(regex("^[a-zA-Z0-9][a-zA-Z0-9-]*(\\.[a-zA-Z0-9][a-zA-Z0-9-]*)+$", var.domain_name))
    error_message = "Domain name must be a valid FQDN (e.g., 'app.example.com')."
  }
}

variable "redirect_http_to_https" {
  description = <<-EOT
    When HTTPS is enabled, redirect all HTTP (port 80) traffic to HTTPS (port 443).
    Uses HTTP 301 permanent redirect. Set to false to keep HTTP forwarding to targets.
  EOT
  type        = bool
  default     = true
}

variable "create_route53_zone" {
  description = <<-EOT
    Whether to create a new Route53 hosted zone or use an existing one.

    - false (default): Uses an existing hosted zone. The zone must already exist
                       and be configured. Certificate validates in 2-5 minutes.

    - true: Creates a new hosted zone. You must manually update your domain
            registrar's nameservers after apply. DNS propagation can take up to
            48 hours before the certificate validates.

    Recommendation: Use false (existing zone) for faster setup if you already
    have a Route53 hosted zone for your domain.
  EOT
  type        = bool
  default     = false
}

# ============================================================================
# CDN Variables
# ============================================================================

variable "enable_cloudfront" {
  description = "Enable CloudFront CDN"
  type        = bool
  default     = true
}

variable "enable_waf" {
  description = "Enable WAF for CloudFront"
  type        = bool
  default     = false
}

variable "enable_geo_restriction" {
  description = "Enable geo restriction for CloudFront distribution"
  type        = bool
  default     = false
}

variable "geo_restriction_type" {
  description = "Type of geo restriction: whitelist (allow only listed countries) or blacklist (block listed countries)"
  type        = string
  default     = "whitelist"

  validation {
    condition     = contains(["whitelist", "blacklist"], var.geo_restriction_type)
    error_message = "geo_restriction_type must be either 'whitelist' or 'blacklist'."
  }
}

variable "geo_restriction_locations" {
  description = "List of ISO 3166-1-alpha-2 country codes for geo restriction (e.g., [\"US\", \"CA\", \"GB\"])"
  type        = list(string)
  default     = []
}

# ============================================================================
# Monitoring Variables
# ============================================================================

variable "cloudwatch_log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}
