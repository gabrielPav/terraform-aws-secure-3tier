terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.0"
      configuration_aliases = [aws.us_east_1]
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  create_acm_certificate = var.domain_name != ""

  enable_https = var.enable_https || var.domain_name != ""

  certificate_arn = local.create_acm_certificate ? aws_acm_certificate.main[0].arn : ""

  # Extract root domain from FQDN for Route53 lookup (e.g. "app.example.com" -> "example.com")
  domain_parts = var.domain_name != "" ? split(".", var.domain_name) : []
  root_domain = var.domain_name != "" ? join(".", slice(
    local.domain_parts,
    length(local.domain_parts) > 2 ? length(local.domain_parts) - 2 : 0,
    length(local.domain_parts)
  )) : ""

  route53_zone_id = var.domain_name != "" ? (
    var.create_route53_zone && local.create_acm_certificate ? aws_route53_zone.created[0].zone_id : data.aws_route53_zone.existing[0].zone_id
  ) : ""
}

# ALB access logs bucket

resource "aws_s3_bucket" "alb_logs" {
  count               = var.enable_access_logs ? 1 : 0
  bucket              = "${var.project_name}-${var.environment}-alb-logs-${data.aws_caller_identity.current.account_id}"
  object_lock_enabled = var.enable_object_lock_alb_logs

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-alb-logs"
  })
}

resource "aws_s3_bucket_versioning" "alb_logs_versioning" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.alb_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "alb_logs" {
  count  = var.enable_access_logs && var.enable_object_lock_alb_logs ? 1 : 0
  bucket = aws_s3_bucket.alb_logs[0].id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.object_lock_alb_logs_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.alb_logs_versioning]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.alb_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      # ALB access logs only support SSE-S3, not SSE-KMS
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_logging" "alb_logs_logging" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.alb_logs[0].id

  target_bucket = var.s3_access_logs_bucket_id
  target_prefix = "alb-logs-bucket/"
}

resource "aws_s3_bucket_ownership_controls" "alb_logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.alb_logs[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.alb_logs[0].id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

data "aws_elb_service_account" "main" {}

resource "aws_s3_bucket_policy" "alb_logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.alb_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = data.aws_elb_service_account.main.arn
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs[0].arn}/alb/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "logdelivery.elasticloadbalancing.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs[0].arn}/alb/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.alb_logs[0].arn,
          "${aws_s3_bucket.alb_logs[0].arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  count  = var.enable_access_logs ? 1 : 0
  bucket = aws_s3_bucket.alb_logs[0].id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }

  rule {
    id     = "transition-to-glacier"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 365
    }
  }

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# ALB security group
# When CloudFront is in front, ingress is restricted to CloudFront IPs via
# the AWS managed prefix list to prevent direct ALB access.

data "aws_ec2_managed_prefix_list" "cloudfront" {
  count = var.restrict_ingress_to_cloudfront ? 1 : 0
  name  = "com.amazonaws.global.cloudfront.origin-facing"
}

resource "aws_security_group" "alb" {
  name        = "${var.project_name}-${var.environment}-alb-sg"
  description = "Security group for Application Load Balancer - allows HTTP/HTTPS traffic"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-alb-sg"
  })
}

# When CloudFront is enabled, only allow HTTPS from CloudFront to prevent bypassing it
resource "aws_vpc_security_group_ingress_rule" "alb_https_cloudfront" {
  count = var.restrict_ingress_to_cloudfront ? 1 : 0

  security_group_id = aws_security_group.alb.id
  description       = "Allow HTTPS from CloudFront only"

  from_port      = 443
  to_port        = 443
  ip_protocol    = "tcp"
  prefix_list_id = data.aws_ec2_managed_prefix_list.cloudfront[0].id
}

resource "aws_vpc_security_group_ingress_rule" "alb_https_public" {
  count = var.restrict_ingress_to_cloudfront ? 0 : 1

  security_group_id = aws_security_group.alb.id
  description       = "Allow HTTPS from anywhere"

  from_port   = 443
  to_port     = 443
  ip_protocol = "tcp"
  cidr_ipv4   = "0.0.0.0/0"
}

# Allows HTTP traffic to reach the ALB so it can redirect users to HTTPS.
# No unencrypted traffic is ever forwarded to backend targets.
# This rule is only created when CloudFront is disabled. When CloudFront
# is enabled (the default), it handles the redirect at the edge and this
# rule will not be created.
resource "aws_vpc_security_group_ingress_rule" "alb_http_redirect" {
  count = var.restrict_ingress_to_cloudfront ? 0 : 1

  security_group_id = aws_security_group.alb.id
  description       = "HTTP to HTTPS redirect only — traffic is never forwarded unencrypted to targets"

  from_port   = 80
  to_port     = 80
  ip_protocol = "tcp"
  cidr_ipv4   = "0.0.0.0/0"
}

# Broad egress is the standard pattern for ALBs. The ALB is a managed service
# that only forwards traffic to registered targets. It cannot be compromised
# to initiate arbitrary outbound connections like an EC2 instance could.
resource "aws_vpc_security_group_egress_rule" "alb_all_egress" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow all outbound traffic"

  ip_protocol = "-1"
  cidr_ipv4   = "0.0.0.0/0"
}

# ACM certificate (only when domain_name is provided without an existing cert)

resource "aws_acm_certificate" "main" {
  count = local.create_acm_certificate ? 1 : 0

  domain_name       = var.domain_name
  validation_method = "DNS"

  # Create new cert before destroying old one to avoid downtime
  lifecycle {
    create_before_destroy = true
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-acm-cert"
  })
}

# New Route53 zone (optional, requires manual nameserver update at registrar)
resource "aws_route53_zone" "created" {
  count = local.create_acm_certificate && var.create_route53_zone ? 1 : 0

  name    = local.root_domain
  comment = "Hosted zone for ${var.project_name}-${var.environment} managed by Terraform"

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-hosted-zone"
  })
}

# Look up existing Route53 zone (default path — no NS delegation needed)
data "aws_route53_zone" "existing" {
  count = var.domain_name != "" && !var.create_route53_zone ? 1 : 0

  name         = "${local.root_domain}."
  private_zone = false
}

# Route53 DNS query logging (only for newly created zones)

resource "aws_cloudwatch_log_group" "route53_query_logs" {
  count    = var.enable_dns_query_logging && var.create_route53_zone ? 1 : 0
  provider = aws.us_east_1

  name              = "/aws/route53/${var.project_name}-${var.environment}"
  retention_in_days = var.dns_query_log_retention_days

  tags = var.tags
}

resource "aws_cloudwatch_log_resource_policy" "route53_query_logging" {
  count    = var.enable_dns_query_logging && var.create_route53_zone ? 1 : 0
  provider = aws.us_east_1

  policy_name = "${var.project_name}-${var.environment}-route53-query-logging"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "Route53LogsToCloudWatchLogs"
      Effect = "Allow"
      Principal = {
        Service = "route53.amazonaws.com"
      }
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.route53_query_logs[0].arn}:*"
    }]
  })
}

resource "aws_route53_query_log" "main" {
  count = var.enable_dns_query_logging && var.create_route53_zone ? 1 : 0

  cloudwatch_log_group_arn = aws_cloudwatch_log_group.route53_query_logs[0].arn
  zone_id                  = aws_route53_zone.created[0].zone_id

  depends_on = [aws_cloudwatch_log_resource_policy.route53_query_logging]
}

# DNS records for ACM certificate validation

resource "aws_route53_record" "acm_validation" {
  for_each = local.create_acm_certificate ? {
    for dvo in aws_acm_certificate.main[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  zone_id = local.route53_zone_id
  name    = each.value.name
  type    = each.value.type
  records = [each.value.record]
  ttl     = 60

  allow_overwrite = true
}

# Waits for certificate to reach ISSUED status (typically 2-5 minutes)
resource "aws_acm_certificate_validation" "main" {
  count = local.create_acm_certificate ? 1 : 0

  certificate_arn         = aws_acm_certificate.main[0].arn
  validation_record_fqdns = [for record in aws_route53_record.acm_validation : record.fqdn]
}

# Application Load Balancer

resource "aws_lb" "main" {
  name               = "${var.project_name}-${var.environment}-alb"
  internal           = var.alb_internal
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.alb_internal ? var.private_subnet_ids : var.public_subnet_ids

  enable_deletion_protection       = var.enable_deletion_protection
  enable_http2                     = var.enable_http2
  enable_cross_zone_load_balancing = var.enable_cross_zone
  drop_invalid_header_fields       = var.enable_drop_invalid_headers

  access_logs {
    bucket  = var.enable_access_logs ? aws_s3_bucket.alb_logs[0].id : null
    prefix  = var.enable_access_logs ? "alb" : null
    enabled = var.enable_access_logs
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-alb"
  })
}

# HTTP listener - redirects to HTTPS when enabled, otherwise forwards to targets
# Skipped when CloudFront is enabled since CloudFront connects on HTTPS only
# and no security group ingress exists for port 80 in that configuration.
resource "aws_lb_listener" "http" {
  count = var.restrict_ingress_to_cloudfront ? 0 : 1

  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = local.enable_https && var.redirect_http_to_https ? "redirect" : "forward"

    dynamic "redirect" {
      for_each = local.enable_https && var.redirect_http_to_https ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }

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

# HTTPS listener - terminates TLS and forwards to targets
resource "aws_lb_listener" "https" {
  count = local.enable_https ? 1 : 0

  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = var.ssl_policy
  certificate_arn   = local.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = var.target_group_arns[0]
  }

  # Certificate must be validated before attaching to listener
  depends_on = [aws_acm_certificate_validation.main]

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-https-listener"
  })
}

# Route53 A record pointing domain to ALB (skipped when CloudFront handles DNS)
resource "aws_route53_record" "alb_alias" {
  count = var.domain_name != "" && var.create_dns_record ? 1 : 0

  zone_id = local.route53_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}
