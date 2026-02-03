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

variable "db_name" {
  description = "Database name"
  type        = string
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

variable "kms_key_arn" {
  description = "KMS key ARN for EBS encryption"
  type        = string
}

variable "allowed_security_group_id" {
  description = "List of security group IDs that EC2 instances are allowed to send traffic to (e.g., RDS security group)"
  type        = list(string)
  default     = []
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

variable "eic_security_group_id" {
  description = "EC2 Instance Connect Endpoint security group ID for SSH access"
  type        = string
  default     = null
}

variable "enable_eic_ssh_access" {
  description = "Enable SSH access from EC2 Instance Connect Endpoint"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags to apply"
  type        = map(string)
  default     = {}
}
