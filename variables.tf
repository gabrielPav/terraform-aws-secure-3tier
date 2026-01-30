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
    ssm         = true
    ssmmessages = true
    ec2messages = true
    logs        = true
  }
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
  default     = 100
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
  description = "ARN of SSL certificate for ALB (optional)"
  type        = string
  default     = ""
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

# ============================================================================
# Monitoring Variables
# ============================================================================

variable "cloudwatch_log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}
