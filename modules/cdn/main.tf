# CDN — CloudFront distribution, WAF, security headers, OAC for S3

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.0"
      configuration_aliases = [aws.us_east_1]
    }
  }
}

locals {
  # Reuse the ALB cert when we're already in us-east-1
  is_us_east_1 = var.aws_region == "us-east-1"

  # Need a separate cert only when CF is on + domain set + not in us-east-1
  create_cloudfront_certificate = var.enable_cloudfront && var.domain_name != "" && !local.is_us_east_1

  # Pick the right cert ARN
  cloudfront_certificate_arn = var.domain_name != "" ? (
    local.is_us_east_1 ? var.alb_certificate_arn : aws_acm_certificate.cloudfront[0].arn
  ) : ""
}

# ACM cert for CloudFront — must be in us-east-1 (reuses ALB cert if already there)

resource "aws_acm_certificate" "cloudfront" {
  count    = local.create_cloudfront_certificate ? 1 : 0
  provider = aws.us_east_1

  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-cloudfront-cert"
  })
}

# DNS validation for the CloudFront cert
resource "aws_route53_record" "cloudfront_cert_validation" {
  for_each = local.create_cloudfront_certificate ? {
    for dvo in aws_acm_certificate.cloudfront[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  zone_id         = var.route53_zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  ttl             = 60
  allow_overwrite = true
}

# Wait for cert to reach ISSUED
resource "aws_acm_certificate_validation" "cloudfront" {
  count    = local.create_cloudfront_certificate ? 1 : 0
  provider = aws.us_east_1

  certificate_arn         = aws_acm_certificate.cloudfront[0].arn
  validation_record_fqdns = [for record in aws_route53_record.cloudfront_cert_validation : record.fqdn]
}

# Security headers — HSTS, clickjacking protection, MIME sniffing, etc.
resource "aws_cloudfront_response_headers_policy" "security_headers" {
  count = var.enable_cloudfront ? 1 : 0

  name    = "${var.project_name}-${var.environment}-security-headers"
  comment = "Security headers policy for ${var.project_name} ${var.environment}"

  security_headers_config {
    # HSTS — browsers must use HTTPS, no exceptions
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    # Prevent MIME sniffing
    content_type_options {
      override = true
    }

    # Block framing — clickjacking protection
    frame_options {
      frame_option = "DENY"
      override     = true
    }

    # XSS filter for legacy browsers
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }

    # Don't leak full URLs on cross-origin navigation
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
  }
}

# OAC — S3 origin gets SigV4-signed requests from CloudFront
resource "aws_cloudfront_origin_access_control" "s3" {
  count = var.enable_cloudfront ? 1 : 0

  name                              = "${var.project_name}-${var.environment}-s3-oac"
  description                       = "OAC for S3 bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Bucket policy for OAC — without this, S3 returns 403 on every request
resource "aws_s3_bucket_policy" "cloudfront_oac" {
  count  = var.enable_cloudfront ? 1 : 0
  bucket = var.s3_bucket_id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontOACReadOnly"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::${var.s3_bucket_id}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.main[0].arn
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "arn:aws:s3:::${var.s3_bucket_id}",
          "arn:aws:s3:::${var.s3_bucket_id}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid       = "DenyNonKMSEncryptedUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "arn:aws:s3:::${var.s3_bucket_id}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid       = "DenyIncorrectKMSKey"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "arn:aws:s3:::${var.s3_bucket_id}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = var.s3_kms_key_arn
          }
        }
      }
    ]
  })
}

# Cache policy for ALB — forward cookies + auth headers (dynamic content)
resource "aws_cloudfront_cache_policy" "alb" {
  count = var.enable_cloudfront ? 1 : 0

  name        = "${var.project_name}-${var.environment}-alb-cache-policy"
  comment     = "Cache policy for ALB origin - forwards cookies and auth headers for dynamic content"
  default_ttl = 0
  max_ttl     = 86400
  min_ttl     = 0

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "all"
    }

    headers_config {
      header_behavior = "whitelist"
      headers {
        items = ["Host", "Authorization"]
      }
    }

    query_strings_config {
      query_string_behavior = "all"
    }

    enable_accept_encoding_brotli = true
    enable_accept_encoding_gzip   = true
  }
}

# Cache policy for S3 — cache everything aggressively
resource "aws_cloudfront_cache_policy" "s3_assets" {
  count = var.enable_cloudfront ? 1 : 0

  name        = "${var.project_name}-${var.environment}-s3-cache-policy"
  comment     = "Cache policy for S3 static assets - aggressive caching"
  default_ttl = 86400
  max_ttl     = 31536000
  min_ttl     = 0

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }

    headers_config {
      header_behavior = "none"
    }

    query_strings_config {
      query_string_behavior = "none"
    }

    enable_accept_encoding_brotli = true
    enable_accept_encoding_gzip   = true
  }
}

# The distribution
resource "aws_cloudfront_distribution" "main" {
  count = var.enable_cloudfront ? 1 : 0

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "${var.project_name} ${var.environment} CloudFront Distribution"
  default_root_object = "index.php"
  price_class         = var.price_class
  aliases             = var.domain_name != "" ? [var.domain_name] : []

  # ALB origin — HTTPS only to the backend
  origin {
    domain_name = var.alb_dns_name
    origin_id   = "${var.project_name}-${var.environment}-alb"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }

    origin_shield {
      enabled              = true
      origin_shield_region = var.aws_region
    }
  }

  # S3 origin — static assets via OAC
  origin {
    domain_name              = var.s3_bucket_domain_name
    origin_id                = "${var.project_name}-${var.environment}-s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.s3[0].id
  }

  # Failover: ALB 5xx → fall back to S3
  origin_group {
    origin_id = "${var.project_name}-${var.environment}-origin-group"

    failover_criteria {
      status_codes = [500, 502, 503, 504]
    }

    member {
      origin_id = "${var.project_name}-${var.environment}-alb"
    }

    member {
      origin_id = "${var.project_name}-${var.environment}-s3"
    }
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${var.project_name}-${var.environment}-origin-group"

    cache_policy_id = aws_cloudfront_cache_policy.alb[0].id

    viewer_protocol_policy     = var.enable_https ? "redirect-to-https" : "allow-all"
    compress                   = var.enable_compression
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers[0].id
  }

  # /assets/* → S3 with aggressive caching
  ordered_cache_behavior {
    path_pattern     = "/assets/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${var.project_name}-${var.environment}-s3"

    cache_policy_id = aws_cloudfront_cache_policy.s3_assets[0].id

    viewer_protocol_policy     = var.enable_https ? "redirect-to-https" : "allow-all"
    compress                   = true
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers[0].id
  }

  restrictions {
    geo_restriction {
      restriction_type = var.enable_geo_restriction ? var.geo_restriction_type : "none"
      locations        = var.enable_geo_restriction ? var.geo_restriction_locations : []
    }
  }

  viewer_certificate {
    # Fall back to *.cloudfront.net cert when no custom domain
    cloudfront_default_certificate = var.domain_name == ""
    acm_certificate_arn            = var.domain_name != "" ? local.cloudfront_certificate_arn : null
    ssl_support_method             = var.domain_name != "" ? "sni-only" : null
    minimum_protocol_version       = var.domain_name != "" ? "TLSv1.2_2021" : null
  }

  # Can't deploy until the cert is validated
  depends_on = [aws_acm_certificate_validation.cloudfront]

  # Logging via Standard Logging v2 (below)

  # WAF
  web_acl_id = var.enable_waf ? aws_wafv2_web_acl.main[0].arn : null

  tags = var.tags
}

# WAF — rate limiting + AWS managed rule sets
resource "aws_wafv2_web_acl" "main" {
  count    = var.enable_cloudfront && var.enable_waf ? 1 : 0
  provider = aws.us_east_1

  name  = "${var.project_name}-${var.environment}-waf"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # Rate limit — 500 req/5min per IP before we block
  rule {
    name     = "RateLimitRule"
    priority = 0

    statement {
      rate_based_statement {
        limit              = 500
        aggregate_key_type = "IP"
      }
    }

    action {
      block {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-${var.environment}-waf-rate-limit"
      sampled_requests_enabled   = true
    }
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

  # Known bad inputs — covers Log4Shell (CVE-2021-44228) and friends
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    override_action {
      none {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-${var.environment}-waf-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # IP reputation — blocks IPs known for bots, botnets, and other threats
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 3

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    override_action {
      none {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-${var.environment}-waf-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  # SQLi protection — inspects query strings, body, cookies, URI
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 4

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    override_action {
      none {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-${var.environment}-waf-sqli"
      sampled_requests_enabled   = true
    }
  }

  # PHP-specific — blocks function injection, deserialization, stream wrapper abuse
  rule {
    name     = "AWSManagedRulesPHPRuleSet"
    priority = 5

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesPHPRuleSet"
        vendor_name = "AWS"
      }
    }

    override_action {
      none {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-${var.environment}-waf-php"
      sampled_requests_enabled   = true
    }
  }

  # Linux-specific — blocks LFI, /etc/passwd traversal, /proc access
  rule {
    name     = "AWSManagedRulesLinuxRuleSet"
    priority = 6

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesLinuxRuleSet"
        vendor_name = "AWS"
      }
    }

    override_action {
      none {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.project_name}-${var.environment}-waf-linux"
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

# WAF logging — name MUST start with "aws-waf-logs-" or AWS rejects it
# Must be in us-east-1 for CloudFront-scoped WAFs

resource "aws_cloudwatch_log_group" "waf_logs" {
  count    = var.enable_cloudfront && var.enable_waf && var.enable_waf_logging ? 1 : 0
  provider = aws.us_east_1

  name              = "aws-waf-logs-${var.project_name}-${var.environment}"
  retention_in_days = var.waf_log_retention_days
  kms_key_id        = var.us_east_1_kms_key_arn

  tags = var.tags
}

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  count    = var.enable_cloudfront && var.enable_waf && var.enable_waf_logging ? 1 : 0
  provider = aws.us_east_1

  log_destination_configs = [aws_cloudwatch_log_group.waf_logs[0].arn]
  resource_arn            = aws_wafv2_web_acl.main[0].arn

  # Don't log tokens or session cookies — they're forwarded but shouldn't be stored
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }

  # Only log blocks and counts — allowed requests are just noise here
  logging_filter {
    default_behavior = "DROP"

    filter {
      behavior    = "KEEP"
      requirement = "MEETS_ANY"

      condition {
        action_condition {
          action = "BLOCK"
        }
      }

      condition {
        action_condition {
          action = "COUNT"
        }
      }
    }
  }
}

# DNS — point the domain at CloudFront instead of the ALB

resource "aws_route53_record" "cloudfront_alias" {
  count = var.enable_cloudfront && var.domain_name != "" ? 1 : 0

  zone_id = var.route53_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.main[0].domain_name
    zone_id                = aws_cloudfront_distribution.main[0].hosted_zone_id
    evaluate_target_health = false
  }
}

# CloudFront access logs — Standard Logging v2 → S3
# Legacy logging_config needs ACLs which we don't allow (BucketOwnerEnforced)
# V2 uses Vended Logs + bucket policies instead. Must be in us-east-1.

resource "aws_cloudwatch_log_delivery_source" "cloudfront" {
  count    = var.enable_cloudfront && var.enable_logging ? 1 : 0
  provider = aws.us_east_1

  name         = "${var.project_name}-${var.environment}-cloudfront"
  log_type     = "ACCESS_LOGS"
  resource_arn = aws_cloudfront_distribution.main[0].arn

  tags = var.tags
}

resource "aws_cloudwatch_log_delivery_destination" "s3" {
  count    = var.enable_cloudfront && var.enable_logging ? 1 : 0
  provider = aws.us_east_1
  name     = "${var.project_name}-${var.environment}-cloudfront-logs-s3"

  delivery_destination_configuration {
    destination_resource_arn = var.s3_access_logs_bucket_arn
  }

  tags = var.tags
}

resource "aws_cloudwatch_log_delivery" "cloudfront_to_s3" {
  count    = var.enable_cloudfront && var.enable_logging ? 1 : 0
  provider = aws.us_east_1

  delivery_source_name     = aws_cloudwatch_log_delivery_source.cloudfront[0].name
  delivery_destination_arn = aws_cloudwatch_log_delivery_destination.s3[0].arn

  s3_delivery_configuration {
    suffix_path                 = "cloudfront/"
    enable_hive_compatible_path = false
  }

  tags = var.tags
}
