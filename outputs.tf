# ============================================================================
# Production Infrastructure - Outputs
# ============================================================================

# Networking Outputs
output "vpc_id" {
  description = "VPC ID"
  value       = module.networking.vpc_id
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = module.networking.public_subnet_ids
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = module.networking.private_subnet_ids
}

# Compute Outputs
output "asg_name" {
  description = "Auto Scaling Group name"
  value       = module.compute.asg_name
}

output "ec2_security_group_id" {
  description = "EC2 security group ID"
  value       = module.compute.ec2_security_group_id
}

# Load Balancer Outputs
output "alb_dns_name" {
  description = "ALB DNS name"
  value       = module.load_balancer.alb_dns_name
}

output "alb_arn" {
  description = "ALB ARN"
  value       = module.load_balancer.alb_arn
}

# CDN Outputs
output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID"
  value       = module.cdn.cloudfront_distribution_id
}

output "cloudfront_domain_name" {
  description = "CloudFront domain name"
  value       = module.cdn.cloudfront_domain_name
}

# Database Outputs
output "rds_endpoint" {
  description = "RDS endpoint"
  value       = module.database.rds_endpoint
  sensitive   = true
}

output "rds_port" {
  description = "RDS port"
  value       = module.database.rds_port
}

# Storage Outputs
output "s3_bucket_name" {
  description = "S3 bucket name"
  value       = module.storage.s3_bucket_name
}

output "efs_file_system_id" {
  description = "EFS file system ID"
  value       = module.storage.efs_file_system_id
}

# Security Outputs
output "cloudtrail_name" {
  description = "CloudTrail name"
  value       = module.security.cloudtrail_name
}

output "kms_key_id" {
  description = "KMS key ID"
  value       = module.security.kms_key_id
}
