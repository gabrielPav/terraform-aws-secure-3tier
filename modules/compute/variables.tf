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

variable "efs_file_system_id" {
  description = "EFS file system ID"
  type        = string
  default     = null
}

variable "efs_access_point_id" {
  description = "EFS access point ID"
  type        = string
  default     = null
}

variable "s3_bucket_name" {
  description = "S3 bucket name"
  type        = string
}

variable "rds_endpoint" {
  description = "RDS endpoint"
  type        = string
  sensitive   = true
}

variable "rds_port" {
  description = "RDS port"
  type        = number
}

variable "db_secret_arn" {
  description = "ARN of the Secrets Manager secret containing database credentials"
  type        = string
  sensitive   = true
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
}

variable "min_size" {
  description = "Minimum ASG size"
  type        = number
}

variable "max_size" {
  description = "Maximum ASG size"
  type        = number
}

variable "desired_capacity" {
  description = "Desired ASG capacity"
  type        = number
}

variable "ebs_volume_size" {
  description = "EBS volume size"
  type        = number
}

variable "ebs_volume_type" {
  description = "EBS volume type"
  type        = string
  default     = "gp3"
}

variable "enable_ebs_encryption" {
  description = "Enable EBS encryption"
  type        = bool
  default     = true
}

variable "iam_instance_profile" {
  description = "IAM instance profile name"
  type        = string
}

variable "enable_detailed_monitoring" {
  description = "Enable EC2 detailed monitoring"
  type        = bool
  default     = true
}

variable "enable_ec2_termination_protection" {
  description = "Enable EC2 instance termination protection"
  type        = bool
  default     = true
}

variable "instance_tenancy" {
  description = "EC2 Instance tenancy: default, dedicated, or host"
  type        = string
  default     = "default"
  validation {
    condition     = contains(["default", "dedicated", "host"], var.instance_tenancy)
    error_message = "Instance tenancy must be one of: default, dedicated, host."
  }
}

variable "alb_security_group_ids" {
  description = "ALB security group IDs"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags to apply"
  type        = map(string)
  default     = {}
}
