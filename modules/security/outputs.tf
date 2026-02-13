# Data layer (RDS, Secrets Manager)
output "kms_data_key_id" {
  description = "KMS key ID for the data layer (RDS, Secrets Manager)"
  value       = aws_kms_key.data.key_id
}

output "kms_data_key_arn" {
  description = "KMS key ARN for the data layer (RDS, Secrets Manager)"
  value       = aws_kms_key.data.arn
}

# Compute layer (EBS, Auto Scaling)
output "kms_compute_key_id" {
  description = "KMS key ID for the compute layer (EBS, Auto Scaling)"
  value       = aws_kms_key.compute.key_id
}

output "kms_compute_key_arn" {
  description = "KMS key ARN for the compute layer (EBS, Auto Scaling)"
  value       = aws_kms_key.compute.arn
}

# Storage layer (S3, CloudFront)
output "kms_storage_key_id" {
  description = "KMS key ID for the storage layer (S3, CloudFront)"
  value       = aws_kms_key.storage.key_id
}

output "kms_storage_key_arn" {
  description = "KMS key ARN for the storage layer (S3, CloudFront)"
  value       = aws_kms_key.storage.arn
}

# Observability layer (CloudTrail, CloudWatch, SNS)
output "kms_observability_key_id" {
  description = "KMS key ID for the observability layer (CloudTrail, CloudWatch, SNS)"
  value       = aws_kms_key.observability.key_id
}

output "kms_observability_key_arn" {
  description = "KMS key ARN for the observability layer (CloudTrail, CloudWatch, SNS)"
  value       = aws_kms_key.observability.arn
}

output "ec2_instance_profile_name" {
  description = "EC2 instance profile name"
  value       = aws_iam_instance_profile.ec2.name
}

output "ec2_instance_profile_arn" {
  description = "EC2 instance profile ARN"
  value       = aws_iam_instance_profile.ec2.arn
}

output "cloudtrail_name" {
  description = "CloudTrail name"
  value       = var.enable_cloudtrail ? aws_cloudtrail.main[0].name : null
}

output "cloudtrail_arn" {
  description = "CloudTrail ARN"
  value       = var.enable_cloudtrail ? aws_cloudtrail.main[0].arn : null
}

output "us_east_1_kms_key_arn" {
  description = "KMS key ARN for us-east-1 resources (WAF logs, Route53 query logs). Returns the observability key when deployed to us-east-1, otherwise a dedicated us-east-1 key."
  value       = var.aws_region == "us-east-1" ? aws_kms_key.observability.arn : aws_kms_key.us_east_1[0].arn
}
