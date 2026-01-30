# ============================================================================
# CDN Module - CloudFront
# ============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# CloudFront Origin Access Control (for S3)
resource "aws_cloudfront_origin_access_control" "s3" {
  name                              = "${var.project_name}-${var.environment}-s3-oac"
  description                       = "OAC for S3 bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "main" {
  count = var.enable_cloudfront ? 1 : 0

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "${var.project_name} ${var.environment} CloudFront Distribution"
  default_root_object = "index.html"
  price_class         = var.price_class

  # ALB Origin
  origin {
    domain_name = var.alb_dns_name
    origin_id   = "${var.project_name}-${var.environment}-alb"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  # S3 Origin
  origin {
    domain_name              = var.s3_bucket_domain_name
    origin_id                = "${var.project_name}-${var.environment}-s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.s3.id
  }

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${var.project_name}-${var.environment}-alb"

    forwarded_values {
      query_string = true
      headers      = ["Host", "Authorization"]
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = var.enable_https ? "redirect-to-https" : "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = var.enable_compression
  }

  # S3 Cache Behavior
  ordered_cache_behavior {
    path_pattern     = "/assets/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${var.project_name}-${var.environment}-s3"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = var.enable_https ? "redirect-to-https" : "allow-all"
    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  # Logging
  dynamic "logging_config" {
    for_each = var.enable_logging ? [1] : []
    content {
      bucket          = var.s3_access_logs_bucket_domain
      include_cookies = false
      prefix          = "cloudfront/"
    }
  }

  # WAF
  web_acl_id = var.enable_waf ? aws_wafv2_web_acl.main[0].id : null

  tags = var.tags
}

# WAF Web ACL
resource "aws_wafv2_web_acl" "main" {
  count = var.enable_cloudfront && var.enable_waf ? 1 : 0

  name  = "${var.project_name}-${var.environment}-waf"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    override_action {
      none {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-${var.environment}-waf-common"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-${var.environment}-waf"
    sampled_requests_enabled   = true
  }

  tags = var.tags
}
