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
