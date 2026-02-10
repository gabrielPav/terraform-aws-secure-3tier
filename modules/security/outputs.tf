output "kms_key_id" {
  description = "KMS key ID"
  value       = aws_kms_key.main.key_id
}

output "kms_key_arn" {
  description = "KMS key ARN"
  value       = aws_kms_key.main.arn
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
  description = "KMS key ARN for us-east-1 resources (WAF logs, Route53 query logs). Returns the main key when deployed to us-east-1, otherwise a dedicated us-east-1 key."
  value       = var.aws_region == "us-east-1" ? aws_kms_key.main.arn : aws_kms_key.us_east_1[0].arn
}
