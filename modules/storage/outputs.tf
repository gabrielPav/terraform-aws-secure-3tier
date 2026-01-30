output "s3_bucket_name" {
  description = "S3 bucket name"
  value       = aws_s3_bucket.main.id
}

output "s3_bucket_arn" {
  description = "S3 bucket ARN"
  value       = aws_s3_bucket.main.arn
}

output "s3_bucket_domain_name" {
  description = "S3 bucket domain name"
  value       = aws_s3_bucket.main.bucket_domain_name
}

output "efs_file_system_id" {
  description = "EFS file system ID"
  value       = var.enable_efs ? aws_efs_file_system.main[0].id : null
}

output "efs_file_system_arn" {
  description = "EFS file system ARN"
  value       = var.enable_efs ? aws_efs_file_system.main[0].arn : null
}

output "efs_access_point_id" {
  description = "EFS access point ID"
  value       = var.enable_efs ? aws_efs_access_point.main[0].id : null
}

output "efs_dns_name" {
  description = "EFS DNS name"
  value       = var.enable_efs ? "${aws_efs_file_system.main[0].id}.efs.${data.aws_region.current.name}.amazonaws.com" : null
}

output "s3_access_logs_bucket_id" {
  description = "Centralized S3 access logs bucket ID"
  value       = aws_s3_bucket.s3_access_logs.id
}

output "s3_access_logs_bucket_arn" {
  description = "Centralized S3 access logs bucket ARN"
  value       = aws_s3_bucket.s3_access_logs.arn
}

output "s3_access_logs_bucket_domain" {
  description = "Centralized S3 access logs bucket domain name"
  value       = aws_s3_bucket.s3_access_logs.bucket_domain_name
}
