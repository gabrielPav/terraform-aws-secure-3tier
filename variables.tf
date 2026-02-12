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
  description = "Common tags to apply to all resources. Note: ManagedBy, Environment, and Project are set automatically via provider default_tags."
  type        = map(string)
  default     = {}
}

# Networking

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid CIDR block (e.g., 10.0.0.0/16)."
  }
}

variable "number_of_availability_zones" {
  description = "Number of availability zones to use"
  type        = number
  default     = 3

  validation {
    condition     = var.number_of_availability_zones >= 2 && var.number_of_availability_zones <= 6
    error_message = "number_of_availability_zones must be between 2 and 6 for high availability."
  }
}

variable "enable_vpc_endpoints" {
  description = "Map of interface VPC endpoints to enable"
  type        = map(bool)
  default = {
    logs           = true
    secretsmanager = true
  }
}

variable "enable_eic_endpoint" {
  description = "Enable EC2 Instance Connect Endpoint for secure SSH access to private instances"
  type        = bool
  default     = true
}

# Storage

variable "enable_s3_object_lock" {
  description = "Enable S3 Object Lock (Governance Mode) on the assets bucket. Recommended for compliance workloads."
  type        = bool
  default     = false
}

variable "s3_object_lock_retention_days" {
  description = "Number of days to retain assets bucket objects under Governance Mode Object Lock."
  type        = number
  default     = 30

  validation {
    condition     = var.s3_object_lock_retention_days >= 1
    error_message = "Object Lock retention must be at least 1 day."
  }
}

variable "enable_s3_object_lock_access_logs" {
  description = "Enable S3 Object Lock (Governance Mode) on the S3 access logs bucket. Recommended for compliance workloads. WARNING: flipping this on an existing bucket destroys and recreates it — all objects are lost."
  type        = bool
  default     = false
}

variable "s3_object_lock_access_logs_retention_days" {
  description = "Number of days to retain S3 access log objects under Governance Mode Object Lock."
  type        = number
  default     = 30

  validation {
    condition     = var.s3_object_lock_access_logs_retention_days >= 1
    error_message = "Object Lock retention must be at least 1 day."
  }
}

variable "enable_object_lock_alb_logs" {
  description = "Enable S3 Object Lock (Governance Mode) on the ALB access logs bucket. Recommended for compliance workloads. WARNING: flipping this on an existing bucket destroys and recreates it — all objects are lost."
  type        = bool
  default     = false
}

variable "object_lock_alb_logs_retention_days" {
  description = "Number of days to retain ALB access log objects under Governance Mode Object Lock."
  type        = number
  default     = 30

  validation {
    condition     = var.object_lock_alb_logs_retention_days >= 1
    error_message = "Object Lock retention must be at least 1 day."
  }
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

# Compute

variable "ec2_instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.medium"
}

variable "asg_min_size" {
  description = "Minimum number of instances in ASG"
  type        = number
  default     = 3
}

variable "asg_max_size" {
  description = "Maximum number of instances in ASG"
  type        = number
  default     = 10
}

variable "asg_desired_capacity" {
  description = "Desired number of instances in ASG"
  type        = number
  default     = 3
}

variable "ebs_volume_size" {
  description = "Size of EBS volume in GB"
  type        = number
  default     = 50
}

# Database

variable "rds_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "rds_engine" {
  description = "RDS engine type. Only MySQL-compatible engines are supported (application uses mysqli PHP driver)."
  type        = string
  default     = "mysql"
  validation {
    condition     = contains(["mysql", "mariadb"], var.rds_engine)
    error_message = "RDS engine must be mysql or mariadb. Other engines are incompatible with the application's mysqli PHP driver."
  }
}

variable "rds_engine_version" {
  description = "RDS engine version. Use major.minor only (e.g., '8.0')."
  type        = string
  default     = "8.0"
}

variable "rds_database_name" {
  description = "Name of the RDS database"
  type        = string
  default     = "webappdb"
}

variable "rds_username" {
  description = "RDS master username"
  type        = string
  default     = "dbopsadmin"
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

  validation {
    condition     = var.rds_backup_retention_period >= 1 && var.rds_backup_retention_period <= 35
    error_message = "rds_backup_retention_period must be between 1 and 35 days."
  }
}

# Load Balancer

variable "domain_name" {
  description = <<-EOT
    Fully Qualified Domain Name (FQDN) for the application (REQUIRED).

    This is required for production workloads because:
    - CloudFront is enabled by default for CDN, DDoS protection, and edge caching
    - CloudFront requires an ACM certificate for SSL/TLS enforcement
    - ACM certificates require a custom domain for DNS validation

    Terraform will:
    1. Request ACM certificate(s) for this domain
    2. Look up the Route53 hosted zone for DNS validation
    3. Create DNS records for certificate validation
    4. Configure the ALB HTTPS listener with the validated certificate
    5. Configure CloudFront with SSL/TLS enforcement
    6. Create Route53 A record pointing to CloudFront

    Example: "app.example.com" or "webapp.com"

    Requirements:
    - The Route53 hosted zone for the root domain must already exist
    - For "app.example.com", the hosted zone "example.com" must exist
    - DNS propagation and certificate validation typically take 2-5 minutes
  EOT
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9][a-zA-Z0-9-]*(\\.[a-zA-Z0-9][a-zA-Z0-9-]*)+$", var.domain_name))
    error_message = "domain_name is required and must be a valid FQDN (e.g., 'app.example.com')."
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

    Prefer false (existing zone) if you already have one — much faster setup.
  EOT
  type        = bool
  default     = false
}

# CDN

variable "enable_cloudfront" {
  description = <<-EOT
    Enable CloudFront CDN distribution in front of the ALB

    Strongly recommended to keep enabled (default: true). CloudFront provides:
    - HTTPS between users and edge locations (end-to-end encryption with ALB)
    - HTTP to HTTPS redirect handled at the edge (ALB only receives HTTPS)
    - ALB security group restricted to CloudFront IPs only (not open to the internet)
    - WAF, DDoS protection, and edge caching

    Disabling CloudFront removes WAF and DDoS protection and exposes the ALB
    directly to the internet. Only disable for testing or non-production use.
  EOT
  type        = bool
  default     = true
}

variable "enable_waf" {
  description = "Enable WAF for CloudFront"
  type        = bool
  default     = true
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

# Monitoring

variable "cloudwatch_log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

variable "alarm_notification_email" {
  description = "Email address to receive CloudWatch alarm and security alert notifications. Leave empty to disable SNS notifications."
  type        = string
  default     = ""
}

# Disabled by default, notifications are an optional secondary layer
variable "enable_cloudtrail_sns_notifications" {
  description = "Enable SNS notifications for CloudTrail events and security monitoring alarms. Requires alarm_notification_email to be set."
  type        = bool
  default     = false
}

# Cross-Region Replication

variable "enable_s3_crr" {
  description = "Enable S3 cross-region replication for the assets bucket. Asynchronously copies objects to a replica bucket in a second region for disaster recovery."
  type        = bool
  default     = false
}

variable "s3_replica_region" {
  description = "AWS region for the S3 cross-region replica bucket (e.g., us-west-2). Must differ from the primary aws_region."
  type        = string
  default     = "us-west-2"
}
