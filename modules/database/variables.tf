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

variable "private_subnet_ids" {
  description = "Private subnet IDs"
  type        = list(string)
}

variable "allowed_security_group_id" {
  description = "Security group ID allowed to access RDS"
  type        = string
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
}

variable "db_engine" {
  description = "RDS engine"
  type        = string
}

variable "db_engine_version" {
  description = "RDS engine version"
  type        = string
}

variable "db_name" {
  description = "Database name"
  type        = string
}

variable "db_username" {
  description = "Database username"
  type        = string
  sensitive   = true
}

variable "db_allocated_storage" {
  description = "Allocated storage in GB"
  type        = number
}

variable "db_max_allocated_storage" {
  description = "Max allocated storage in GB"
  type        = number
  default     = 1000
}

variable "db_port" {
  description = "Database port"
  type        = number
  default     = 3306
}

variable "db_parameter_group_family" {
  description = "Parameter group family"
  type        = string
  default     = "mysql8.0"
}

variable "multi_az" {
  description = "Enable Multi-AZ"
  type        = bool
  default     = false
}

variable "backup_retention_period" {
  description = "Backup retention period in days"
  type        = number
  default     = 7
}

variable "kms_key_id" {
  description = "KMS key ID"
  type        = string
  default     = null
}

variable "deletion_protection" {
  description = "Enable deletion protection for the RDS instance"
  type        = bool
  default     = true
}

variable "enhanced_monitoring_interval" {
  description = "Enhanced monitoring interval in seconds (0 to disable, 1, 5, 10, 15, 30, or 60)"
  type        = number
  default     = 0
}

variable "performance_insights_enabled" {
  description = "Enable Performance Insights for RDS"
  type        = bool
  default     = false
}

variable "performance_insights_retention_period" {
  description = "Performance Insights retention period in days (7 for free tier, 31-731 for paid)"
  type        = number
  default     = 7
}

variable "tags" {
  description = "Tags to apply"
  type        = map(string)
  default     = {}
}
