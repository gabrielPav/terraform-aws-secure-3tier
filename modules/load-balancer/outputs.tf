output "alb_id" {
  description = "The ID of the Application Load Balancer"
  value       = aws_lb.main.id
}

output "alb_arn" {
  description = "The ARN of the Application Load Balancer"
  value       = aws_lb.main.arn
}

output "alb_arn_suffix" {
  description = "The ARN suffix of the ALB for use in CloudWatch metric dimensions"
  value       = aws_lb.main.arn_suffix
}

output "alb_dns_name" {
  description = <<-EOT
    The DNS name of the Application Load Balancer.
    Use this to access the ALB directly or configure DNS records.
    Example: my-alb-123456789.us-east-1.elb.amazonaws.com
  EOT
  value       = aws_lb.main.dns_name
}

output "alb_zone_id" {
  description = <<-EOT
    The hosted zone ID of the ALB.
    Use this when creating Route53 alias records pointing to the ALB.
  EOT
  value       = aws_lb.main.zone_id
}

output "alb_security_group_id" {
  description = <<-EOT
    The ID of the ALB security group.
    Use this to allow traffic from the ALB to backend instances.
  EOT
  value       = aws_security_group.alb.id
}

output "https_endpoint_url" {
  description = <<-EOT
    The HTTPS endpoint URL for the application.
    - If domain_name is configured: https://<domain_name>
    - Otherwise: https://<alb_dns_name>
    Returns empty string if HTTPS is not enabled.
  EOT
  value = local.enable_https ? (
    var.domain_name != "" ? "https://${var.domain_name}" : "https://${aws_lb.main.dns_name}"
  ) : ""
}

output "http_endpoint_url" {
  description = <<-EOT
    The HTTP endpoint URL for the application.
    - If domain_name is configured: http://<domain_name>
    - Otherwise: http://<alb_dns_name>
    Note: If HTTPS is enabled with redirect, HTTP requests will be redirected to HTTPS.
  EOT
  value       = var.domain_name != "" ? "http://${var.domain_name}" : "http://${aws_lb.main.dns_name}"
}

output "https_enabled" {
  description = "Whether HTTPS is enabled on the ALB"
  value       = local.enable_https
}

output "acm_certificate_arn" {
  description = <<-EOT
    The ARN of the ACM certificate used for HTTPS.
    - If a new certificate was created: ARN of the new certificate
    - If an existing certificate was provided: The provided certificate_arn
    - If HTTPS is not enabled: Empty string
  EOT
  value       = local.enable_https ? local.certificate_arn : ""
}

output "acm_certificate_domain_validation_options" {
  description = <<-EOT
    The domain validation options for the ACM certificate.
    Useful for debugging certificate validation issues.
    Only populated when a new certificate is created.
  EOT
  value       = local.create_acm_certificate ? aws_acm_certificate.main[0].domain_validation_options : []
}

output "acm_certificate_status" {
  description = <<-EOT
    The status of the ACM certificate (e.g., PENDING_VALIDATION, ISSUED, FAILED).
    Only populated when a new certificate is created.
  EOT
  value       = local.create_acm_certificate ? aws_acm_certificate.main[0].status : ""
}

output "route53_zone_id" {
  description = <<-EOT
    The Route53 hosted zone ID used for DNS validation and ALB alias record.
    Only populated when domain_name is provided.
  EOT
  value       = var.domain_name != "" ? local.route53_zone_id : ""
}

output "route53_zone_name_servers" {
  description = <<-EOT
    The nameservers for the Route53 hosted zone.
    Only populated when create_route53_zone = true (new zone created).

    IMPORTANT: If a new zone was created, you must configure your domain
    registrar to use these nameservers. This is a one-time manual step.

    If using an existing zone (create_route53_zone = false), this will be
    empty because the nameservers are already configured.
  EOT
  value       = local.create_acm_certificate && var.create_route53_zone ? aws_route53_zone.created[0].name_servers : []
}

output "route53_zone_created" {
  description = <<-EOT
    Whether a new Route53 hosted zone was created (true) or an existing one was used (false).
    If true, you need to update your domain registrar's nameservers.
    If false, certificate validation should complete within 2-5 minutes.
  EOT
  value       = local.create_acm_certificate && var.create_route53_zone
}

output "route53_alb_record_fqdn" {
  description = <<-EOT
    The FQDN of the Route53 A record pointing to the ALB.
    Only populated when domain_name is provided.
  EOT
  value       = var.domain_name != "" && var.create_dns_record ? aws_route53_record.alb_alias[0].fqdn : ""
}

output "http_listener_arn" {
  description = "The ARN of the HTTP listener (port 80)"
  value       = aws_lb_listener.http.arn
}

output "https_listener_arn" {
  description = <<-EOT
    The ARN of the HTTPS listener (port 443).
    Returns empty string if HTTPS is not enabled.
  EOT
  value       = local.enable_https ? aws_lb_listener.https[0].arn : ""
}

output "alb_logs_bucket_id" {
  description = <<-EOT
    The ID of the S3 bucket storing ALB access logs.
    Returns empty string if access logs are disabled.
  EOT
  value       = var.enable_access_logs ? aws_s3_bucket.alb_logs[0].id : ""
}

output "alb_logs_bucket_arn" {
  description = <<-EOT
    The ARN of the S3 bucket storing ALB access logs.
    Returns empty string if access logs are disabled.
  EOT
  value       = var.enable_access_logs ? aws_s3_bucket.alb_logs[0].arn : ""
}
