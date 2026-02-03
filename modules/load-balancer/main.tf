# ============================================================================
# Load Balancer Module - ALB with HTTPS/SSL Support
# ============================================================================
# This module creates an Application Load Balancer (ALB) with:
# - HTTP listener on port 80 (with optional redirect to HTTPS)
# - HTTPS listener on port 443 (optional, with ACM certificate)
# - Automatic ACM certificate provisioning with DNS validation
# - Route53 DNS records for certificate validation
# - Security group with HTTP/HTTPS ingress rules
# - S3 bucket for access logging
# ============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ============================================================================
# Local Variables
# ============================================================================
# Define computed values used throughout the module for cleaner code.
# ============================================================================

locals {
  # Determine if we should create a new ACM certificate
  # Only create if domain_name is provided AND no existing certificate_arn is given
  create_acm_certificate = var.domain_name != "" && var.certificate_arn == ""

  # Determine if HTTPS should be enabled
  # HTTPS is enabled if explicitly set OR if domain_name/certificate_arn is provided
  enable_https = var.enable_https || var.domain_name != "" || var.certificate_arn != ""

  # Determine which certificate ARN to use for the HTTPS listener
  # Priority: 1. Existing certificate_arn, 2. Newly created ACM certificate
  certificate_arn = var.certificate_arn != "" ? var.certificate_arn : (
    local.create_acm_certificate ? aws_acm_certificate.main[0].arn : ""
  )

  # Extract the root domain from the FQDN for Route53 hosted zone lookup
  # Example: "app.example.com" -> "example.com"
  # Example: "www.sub.example.co.uk" -> "sub.example.co.uk" (takes last 2 parts)
  # This handles most common domain structures
  domain_parts = var.domain_name != "" ? split(".", var.domain_name) : []
  root_domain = var.domain_name != "" ? join(".", slice(
    local.domain_parts,
    length(local.domain_parts) > 2 ? length(local.domain_parts) - 2 : 0,
    length(local.domain_parts)
  )) : ""

  # Get the Route53 zone ID from either the created zone or existing zone
  # This abstracts away the source so other resources can reference it uniformly
  route53_zone_id = local.create_acm_certificate ? (
    var.create_route53_zone ? aws_route53_zone.created[0].zone_id : data.aws_route53_zone.existing[0].zone_id
  ) : ""
}

# ============================================================================
# S3 Bucket for ALB Access Logs
# ============================================================================
# This bucket stores ALB access logs for security analysis and troubleshooting.
# Access logs are enabled by default but can be disabled via variable.
# ============================================================================

resource "aws_s3_bucket" "alb_logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = "${var.project_name}-${var.environment}-alb-logs"

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-alb-logs"
  })
}

# Enable versioning on the ALB logs bucket with MFA Delete protection
resource "aws_s3_bucket_versioning" "alb_logs_versioning" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.alb_logs[0].id

  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Enabled"
  }
}

# Configure S3 server access logging for the ALB logs bucket itself
resource "aws_s3_bucket_logging" "alb_logs_logging" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.alb_logs[0].id

  target_bucket = var.s3_access_logs_bucket_id
  target_prefix = "alb-logs-bucket/"
}

# Block all public access to the ALB logs bucket
resource "aws_s3_bucket_public_access_block" "alb_logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.alb_logs[0].id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# Bucket policy allowing AWS load balancer service to write access logs
resource "aws_s3_bucket_policy" "alb_logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.alb_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "delivery.logs.amazonaws.com"
      }
      Action   = "s3:PutObject"
      Resource = "${aws_s3_bucket.alb_logs[0].arn}/*"
    }]
  })
}

# ============================================================================
# Security Group for ALB
# ============================================================================
# This security group controls inbound traffic to the ALB.
# By default, it allows HTTP (80) and HTTPS (443) from anywhere.
# ============================================================================

resource "aws_security_group" "alb" {
  name        = "${var.project_name}-${var.environment}-alb-sg"
  description = "Security group for Application Load Balancer - allows HTTP/HTTPS traffic"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-alb-sg"
  })
}

# Ingress Rule: Allow HTTP traffic from anywhere (port 80)
resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow HTTP from anywhere"

  from_port   = 80
  to_port     = 80
  ip_protocol = "tcp"
  cidr_ipv4   = "0.0.0.0/0"
}

# Ingress Rule: Allow HTTPS traffic from anywhere (port 443)
resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow HTTPS from anywhere"

  from_port   = 443
  to_port     = 443
  ip_protocol = "tcp"
  cidr_ipv4   = "0.0.0.0/0"
}

# Egress Rule: Allow all outbound traffic (required for health checks)
resource "aws_vpc_security_group_egress_rule" "alb_all_egress" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow all outbound traffic"

  ip_protocol = "-1"
  cidr_ipv4   = "0.0.0.0/0"
}

# ============================================================================
# ACM Certificate Request
# ============================================================================
# This section requests an SSL/TLS certificate from AWS Certificate Manager.
# The certificate uses DNS validation, which is fully automated with Route53.
# Only created when domain_name is provided and no existing certificate_arn.
# ============================================================================

resource "aws_acm_certificate" "main" {
  count = local.create_acm_certificate ? 1 : 0

  # The domain name for which the certificate will be issued
  domain_name = var.domain_name

  # DNS validation is preferred over email validation because it can be
  # fully automated and doesn't require manual intervention
  validation_method = "DNS"

  # Lifecycle rule ensures new certificate is created before old one is destroyed
  # This prevents downtime during certificate renewal or changes
  lifecycle {
    create_before_destroy = true
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-acm-cert"
  })
}

# ============================================================================
# Route53 Hosted Zone - Create New (Optional)
# ============================================================================
# Creates a NEW public Route53 hosted zone for the root domain.
# Only used when create_route53_zone = true.
#
# IMPORTANT: After terraform apply, you must update your domain registrar
# to use the nameservers provided in the outputs. This is a one-time manual
# step required for DNS resolution to work.
# ============================================================================

resource "aws_route53_zone" "created" {
  count = local.create_acm_certificate && var.create_route53_zone ? 1 : 0

  # Create hosted zone for the root domain
  # Example: For "app.example.com", creates zone for "example.com"
  name = local.root_domain

  # Optional comment describing the zone's purpose
  comment = "Hosted zone for ${var.project_name}-${var.environment} managed by Terraform"

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-hosted-zone"
  })
}

# ============================================================================
# Route53 Hosted Zone - Use Existing (Default)
# ============================================================================
# Looks up an EXISTING Route53 hosted zone for the root domain.
# Used when create_route53_zone = false (default).
# This is faster because DNS is already configured - certificate validates
# in 2-5 minutes instead of waiting for DNS propagation (up to 48 hours).
# ============================================================================

data "aws_route53_zone" "existing" {
  count = local.create_acm_certificate && !var.create_route53_zone ? 1 : 0

  # Look up the hosted zone by the root domain name
  name = "${local.root_domain}."

  # Only look for public hosted zones (not private)
  private_zone = false
}

# ============================================================================
# Route53 DNS Records for ACM Certificate Validation
# ============================================================================
# These DNS records prove domain ownership to AWS Certificate Manager.
# ACM provides the record details; we just need to create them in Route53.
# The for_each handles multiple validation records (e.g., for SANs).
# ============================================================================

resource "aws_route53_record" "acm_validation" {
  # Create a record for each domain validation option provided by ACM
  for_each = local.create_acm_certificate ? {
    for dvo in aws_acm_certificate.main[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  # Use the hosted zone ID from the data source lookup
  zone_id = local.route53_zone_id

  # ACM provides these values - we just need to create the records
  name    = each.value.name
  type    = each.value.type
  records = [each.value.record]

  # Short TTL for validation records (60 seconds)
  ttl = 60

  # Allow overwriting if the record already exists
  allow_overwrite = true
}

# ============================================================================
# ACM Certificate Validation
# ============================================================================
# This resource waits for the certificate validation to complete.
# It depends on the Route53 DNS records being created first.
# Once validation is complete, the certificate is ready for use.
# ============================================================================

resource "aws_acm_certificate_validation" "main" {
  count = local.create_acm_certificate ? 1 : 0

  # Reference the certificate to be validated
  certificate_arn = aws_acm_certificate.main[0].arn

  # Wait for all DNS validation records to be created and propagated
  validation_record_fqdns = [for record in aws_route53_record.acm_validation : record.fqdn]

  # This resource will wait until the certificate status is ISSUED
  # Typically takes 2-5 minutes for DNS validation
}

# ============================================================================
# Application Load Balancer
# ============================================================================
# The main ALB resource that handles incoming HTTP/HTTPS traffic.
# Can be internet-facing (default) or internal based on configuration.
# ============================================================================

resource "aws_lb" "main" {
  name               = "${var.project_name}-${var.environment}-alb"
  internal           = var.alb_internal
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]

  # Place ALB in public subnets for internet-facing, private for internal
  subnets = var.alb_internal ? var.private_subnet_ids : var.public_subnet_ids

  # Security and performance settings
  enable_deletion_protection       = var.enable_deletion_protection
  enable_http2                     = var.enable_http2
  enable_cross_zone_load_balancing = var.enable_cross_zone
  drop_invalid_header_fields       = true

  # Access logging configuration
  access_logs {
    bucket  = var.enable_access_logs ? aws_s3_bucket.alb_logs[0].id : null
    prefix  = var.enable_access_logs ? "alb" : null
    enabled = var.enable_access_logs
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-alb"
  })
}

# ============================================================================
# HTTP Listener (Port 80)
# ============================================================================
# This listener handles HTTP traffic on port 80.
# When HTTPS is enabled and redirect_http_to_https is true, it redirects
# all HTTP traffic to HTTPS (HTTP 301 permanent redirect).
# Otherwise, it forwards traffic directly to the target group.
# ============================================================================

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  # Default action depends on whether HTTPS redirect is enabled
  default_action {
    # Use redirect when HTTPS is enabled and redirect is desired
    type = local.enable_https && var.redirect_http_to_https ? "redirect" : "forward"

    # Redirect configuration (only used when type is "redirect")
    dynamic "redirect" {
      for_each = local.enable_https && var.redirect_http_to_https ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301" # Permanent redirect
      }
    }

    # Forward configuration (only used when type is "forward")
    dynamic "forward" {
      for_each = local.enable_https && var.redirect_http_to_https ? [] : [1]
      content {
        target_group {
          arn = var.target_group_arns[0]
        }
      }
    }
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-http-listener"
  })
}

# ============================================================================
# HTTPS Listener (Port 443)
# ============================================================================
# This listener handles HTTPS traffic on port 443.
# It terminates SSL/TLS and forwards decrypted traffic to the target group.
# Only created when HTTPS is enabled (via domain_name or certificate_arn).
#
# IMPORTANT: This resource depends on ACM certificate validation completing
# first. The depends_on ensures proper ordering of resource creation.
# ============================================================================

resource "aws_lb_listener" "https" {
  # Only create the HTTPS listener when HTTPS is enabled
  count = local.enable_https ? 1 : 0

  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "HTTPS"

  # SSL/TLS policy - controls which protocols and ciphers are supported
  # Using a modern policy that supports TLS 1.2 and 1.3 only
  ssl_policy = var.ssl_policy

  # Certificate ARN - either from existing certificate or newly created ACM cert
  certificate_arn = local.certificate_arn

  # Forward all HTTPS traffic to the target group
  default_action {
    type             = "forward"
    target_group_arn = var.target_group_arns[0]
  }

  # CRITICAL DEPENDENCY: Wait for certificate validation before creating listener
  # This ensures the certificate is in ISSUED state before attaching to ALB
  depends_on = [aws_acm_certificate_validation.main]

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-https-listener"
  })
}

# ============================================================================
# Route53 Alias Record for ALB (Optional)
# ============================================================================
# Creates a Route53 A record (alias) pointing the domain name to the ALB.
# This allows users to access the application using the custom domain name
# instead of the ALB's default DNS name.
# Only created when a domain_name is provided.
# ============================================================================

resource "aws_route53_record" "alb_alias" {
  count = var.domain_name != "" ? 1 : 0

  zone_id = local.route53_zone_id
  name    = var.domain_name
  type    = "A"

  # Alias records are special - they don't have TTL, they point to AWS resources
  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}
