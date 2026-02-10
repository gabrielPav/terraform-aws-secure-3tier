variable "project_name" {
  description = "Project name"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "s3_bucket_name" {
  description = "S3 bucket name"
  type        = string
}

variable "enable_s3_versioning" {
  description = "Enable S3 versioning"
  type        = bool
  default     = true
}

variable "kms_key_id" {
  description = "KMS key ID for encryption"
  type        = string
  default     = null
}

variable "enable_s3_object_lock" {
  description = "Enable S3 Object Lock (Governance Mode) on the assets bucket. Recommended for compliance workloads. WARNING: flipping this on an existing bucket destroys and recreates it — all objects are lost."
  type        = bool
  default     = false
}

variable "s3_object_lock_retention_days" {
  description = "Number of days to retain objects under Governance Mode Object Lock."
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

variable "skip_bucket_policy" {
  description = "Skip creating the assets bucket policy. Set to true when an external module (e.g., CDN) manages the policy instead."
  type        = bool
  default     = false
}

variable "enable_s3_crr" {
  description = "Enable S3 cross-region replication for the assets bucket. Requires versioning to be enabled."
  type        = bool
  default     = false
}

variable "kms_key_arn" {
  description = "KMS key ARN for the source bucket. Used in the replication IAM policy to allow decryption of source objects."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply"
  type        = map(string)
  default     = {}
}
