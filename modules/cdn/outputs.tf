output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID"
  value       = var.enable_cloudfront ? aws_cloudfront_distribution.main[0].id : null
}

output "cloudfront_domain_name" {
  description = "CloudFront domain name"
  value       = var.enable_cloudfront ? aws_cloudfront_distribution.main[0].domain_name : null
}

output "cloudfront_arn" {
  description = "CloudFront distribution ARN"
  value       = var.enable_cloudfront ? aws_cloudfront_distribution.main[0].arn : null
}

output "cloudfront_hosted_zone_id" {
  description = "CloudFront distribution hosted zone ID"
  value       = var.enable_cloudfront ? aws_cloudfront_distribution.main[0].hosted_zone_id : null
}

output "cloudfront_certificate_arn" {
  description = "ARN of the ACM certificate used by CloudFront"
  value       = var.enable_cloudfront && var.domain_name != "" ? local.cloudfront_certificate_arn : null
}

output "cloudfront_certificate_created" {
  description = "Whether a new ACM certificate was created for CloudFront (true if not us-east-1)"
  value       = local.create_cloudfront_certificate
}

output "cloudfront_custom_domain_url" {
  description = "Custom domain URL for CloudFront (HTTPS)"
  value       = var.enable_cloudfront && var.domain_name != "" ? "https://${var.domain_name}" : null
}
