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

# ============================================================================
# Load Balancer Outputs
# ============================================================================

output "alb_dns_name" {
  description = <<-EOT
    The DNS name of the Application Load Balancer.
    Use this to access the ALB directly or configure external DNS records.
    Example: my-alb-123456789.us-east-1.elb.amazonaws.com
  EOT
  value       = module.load_balancer.alb_dns_name
}

output "alb_arn" {
  description = "The ARN of the Application Load Balancer"
  value       = module.load_balancer.alb_arn
}

output "https_endpoint_url" {
  description = <<-EOT
    The HTTPS endpoint URL for the application.
    - If domain_name is configured: https://<domain_name>
    - If only certificate_arn is provided: https://<alb_dns_name>
    - If HTTPS is not enabled: Empty string

    Use this URL to access the application securely over HTTPS.
  EOT
  value       = module.load_balancer.https_endpoint_url
}

output "http_endpoint_url" {
  description = <<-EOT
    The HTTP endpoint URL for the application.
    Note: If HTTPS is enabled with redirect_http_to_https=true,
    HTTP requests will be automatically redirected to HTTPS.
  EOT
  value       = module.load_balancer.http_endpoint_url
}

output "https_enabled" {
  description = "Whether HTTPS is enabled on the ALB"
  value       = module.load_balancer.https_enabled
}

output "acm_certificate_arn" {
  description = <<-EOT
    The ARN of the ACM certificate used for HTTPS.
    Empty string if HTTPS is not enabled.
  EOT
  value       = module.load_balancer.acm_certificate_arn
}

output "route53_name_servers" {
  description = <<-EOT
    The nameservers for the Route53 hosted zone.
    Only populated if create_route53_zone = true (new zone created).
    If populated, configure your domain registrar to use these nameservers.
  EOT
  value       = module.load_balancer.route53_zone_name_servers
}

output "route53_zone_created" {
  description = <<-EOT
    Whether a new Route53 zone was created.
    - true: You must update your domain registrar's nameservers (see route53_name_servers)
    - false: Using existing zone, certificate validates in 2-5 minutes
  EOT
  value       = module.load_balancer.route53_zone_created
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
output "rds_port" {
  description = "RDS port"
  value       = module.database.rds_port
}

# Storage Outputs
output "s3_bucket_name" {
  description = "S3 bucket name"
  value       = module.storage.s3_bucket_name
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

# EC2 Instance Connect Endpoint
output "eic_endpoint_id" {
  description = <<-EOT
    EC2 Instance Connect Endpoint ID for SSH access to private instances.
    Connect using: aws ec2-instance-connect ssh --instance-id <instance-id> --connection-type eice
  EOT
  value       = module.networking.eic_endpoint_id
}
