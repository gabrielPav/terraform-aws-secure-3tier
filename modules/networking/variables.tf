variable "vpc_name" {
  description = "Name of the VPC"
  type        = string
}

variable "project_name" {
  description = "Project name for resource naming and S3 bucket restrictions"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
}

variable "number_of_availability_zones" {
  description = "Number of availability zones"
  type        = number
  default     = 3
}

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Use single NAT Gateway"
  type        = bool
  default     = false
}

variable "enable_flow_logs" {
  description = "Enable VPC Flow Logs"
  type        = bool
  default     = true
}

variable "enable_s3_endpoint" {
  description = "Enable S3 VPC endpoint"
  type        = bool
  default     = true
}

variable "enable_interface_endpoints" {
  description = "Map of interface endpoints to enable"
  type        = map(bool)
  default     = {}
}

variable "flow_log_retention_days" {
  description = "Number of days to retain VPC Flow Log data in CloudWatch"
  type        = number
  default     = 365
}

variable "kms_key_arn" {
  description = "KMS key ARN for CloudWatch log group encryption (observability layer)"
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply"
  type        = map(string)
  default     = {}
}
