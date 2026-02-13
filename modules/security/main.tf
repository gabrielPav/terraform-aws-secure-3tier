# Security — KMS keys, IAM roles, CloudTrail, CIS alarms

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
data "aws_region" "current" {}

locals {
  is_us_east_1 = var.aws_region == "us-east-1"
}

# Add lifecycle { prevent_destroy = true } in prod

# KMS key — data layer (RDS, Secrets Manager)

resource "aws_kms_key" "data" {
  description             = "KMS key for ${var.project_name} data layer - RDS and Secrets Manager"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = 90

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowRDSToUseTheKey"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-kms-data"
  })
}

resource "aws_kms_alias" "data" {
  name          = "alias/${var.project_name}-${var.environment}-data"
  target_key_id = aws_kms_key.data.key_id
}

# KMS key — compute layer (EBS, Auto Scaling)

resource "aws_kms_key" "compute" {
  description             = "KMS key for ${var.project_name} compute layer - EBS and Auto Scaling"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = 90

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowEC2ToUseTheKey"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowAutoScalingToUseTheKey"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowAutoScalingToCreateGrants"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        }
        Action   = "kms:CreateGrant"
        Resource = "*"
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource" = "true"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-kms-compute"
  })
}

resource "aws_kms_alias" "compute" {
  name          = "alias/${var.project_name}-${var.environment}-compute"
  target_key_id = aws_kms_key.compute.key_id
}

# KMS key — storage layer (S3, CloudFront, ELB log delivery)

resource "aws_kms_key" "storage" {
  description             = "KMS key for ${var.project_name} storage layer - S3 and CloudFront"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = 90

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowS3ToUseTheKey"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        # CloudFront OAC decrypts KMS-encrypted S3 objects
        Sid    = "AllowCloudFrontToDecryptS3Objects"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowELBLogDeliveryToUseTheKey"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-kms-storage"
  })
}

resource "aws_kms_alias" "storage" {
  name          = "alias/${var.project_name}-${var.environment}-storage"
  target_key_id = aws_kms_key.storage.key_id
}

# KMS key — observability layer (CloudTrail, CloudWatch, SNS)

resource "aws_kms_key" "observability" {
  description             = "KMS key for ${var.project_name} observability layer - CloudTrail, CloudWatch, SNS"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = 90

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogsToUseTheKey"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      },
      {
        Sid    = "AllowCloudTrailToUseTheKey"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      },
      {
        Sid    = "AllowSNSToUseTheKey"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        # S3 needs this key for CloudTrail bucket SSE-KMS + bucket key
        Sid    = "AllowS3ForCloudTrailBucketEncryption"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-kms-observability"
  })
}

resource "aws_kms_alias" "observability" {
  name          = "alias/${var.project_name}-${var.environment}-observability"
  target_key_id = aws_kms_key.observability.key_id
}

# Force EBS encryption account-wide — catches anything created outside Terraform

resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

# IAM role for EC2 instances

resource "aws_iam_role" "ec2" {
  name_prefix = "${var.project_name}-${var.environment}-ec2-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowEC2AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "ec2_s3" {
  name = "${var.project_name}-${var.environment}-ec2-s3-policy"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListAssetsBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.project_name}-${var.environment}-assets-${data.aws_caller_identity.current.account_id}"
        ]
      },
      {
        Sid    = "ReadWriteAssets"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          "arn:aws:s3:::${var.project_name}-${var.environment}-assets-${data.aws_caller_identity.current.account_id}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "ec2_secrets_manager" {
  name = "${var.project_name}-${var.environment}-ec2-secrets-policy"
  role = aws_iam_role.ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GetSecretValue"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:rds!*"
      },
      {
        Sid    = "DecryptSecret"
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.data.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2" {
  name_prefix = "${var.project_name}-${var.environment}-ec2-profile-"
  role        = aws_iam_role.ec2.name

  tags = var.tags
}

# CloudTrail — audit log everything

resource "aws_s3_bucket" "cloudtrail" {
  count               = var.enable_cloudtrail ? 1 : 0
  bucket              = var.s3_bucket_name
  object_lock_enabled = var.enable_object_lock_cloudtrail

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-cloudtrail"
  })
}

resource "aws_s3_bucket_ownership_controls" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "cloudtrail" {
  count  = var.enable_cloudtrail && var.enable_object_lock_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.object_lock_cloudtrail_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.cloudtrail]
}

# S3 access logs for the CloudTrail bucket itself
resource "aws_s3_bucket_logging" "cloudtrail_logging" {
  count  = var.enable_cloudtrail && var.enable_s3_access_logging ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  target_bucket = var.s3_access_logs_bucket_id
  target_prefix = "cloudtrail-bucket/"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.observability.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail[0].arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.cloudtrail_name}"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.cloudtrail_name}"
          }
        }
      },
      {
        Sid       = "EnforceTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail[0].arn,
          "${aws_s3_bucket.cloudtrail[0].arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

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

resource "aws_cloudwatch_log_group" "cloudtrail" {
  count             = var.enable_cloudtrail && var.enable_cloudwatch ? 1 : 0
  name              = "/aws/cloudtrail/${var.cloudtrail_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.observability.arn

  tags = var.tags
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  count       = var.enable_cloudtrail && var.enable_cloudwatch ? 1 : 0
  name_prefix = "${var.cloudtrail_name}-cw-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowCloudTrailAssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  count = var.enable_cloudtrail && var.enable_cloudwatch ? 1 : 0
  name  = "${var.cloudtrail_name}-cloudwatch-policy"
  role  = aws_iam_role.cloudtrail_cloudwatch[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowCloudTrailWriteToCloudWatch"
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "main" {
  count                         = var.enable_cloudtrail ? 1 : 0
  name                          = var.cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail[0].id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.observability.arn

  cloud_watch_logs_group_arn = var.enable_cloudwatch ? "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*" : null
  cloud_watch_logs_role_arn  = var.enable_cloudwatch ? aws_iam_role.cloudtrail_cloudwatch[0].arn : null

  sns_topic_name = var.enable_cloudtrail_sns_notifications ? aws_sns_topic.cloudtrail_notifications[0].arn : null

  # Management events always on; S3 data events scoped to project buckets to control costs
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type = "AWS::S3::Object"
      values = [
        "${aws_s3_bucket.cloudtrail[0].arn}/",
        "arn:aws:s3:::${var.project_name}-${var.environment}-assets-${data.aws_caller_identity.current.account_id}/"
      ]
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]

  tags = var.tags
}

# SNS topic — CloudTrail notifications + security alarm delivery

resource "aws_sns_topic" "cloudtrail_notifications" {
  count = var.enable_cloudtrail && var.enable_cloudtrail_sns_notifications ? 1 : 0

  name              = "${var.project_name}-${var.environment}-cloudtrail-notifications"
  kms_master_key_id = aws_kms_key.observability.id

  tags = var.tags

  lifecycle {
    precondition {
      condition     = var.alarm_notification_email != ""
      error_message = "alarm_notification_email is required when enable_cloudtrail_sns_notifications is true."
    }
  }
}

resource "aws_sns_topic_policy" "cloudtrail_notifications" {
  count = var.enable_cloudtrail && var.enable_cloudtrail_sns_notifications ? 1 : 0

  arn = aws_sns_topic.cloudtrail_notifications[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudTrailPublish"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.cloudtrail_notifications[0].arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudtrail.main[0].arn
          }
        }
      },
      {
        Sid    = "AllowCloudWatchAlarmsPublish"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.cloudtrail_notifications[0].arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "email" {
  count = var.enable_cloudtrail && var.enable_cloudtrail_sns_notifications ? 1 : 0

  topic_arn = aws_sns_topic.cloudtrail_notifications[0].arn
  protocol  = "email"
  endpoint  = var.alarm_notification_email
}

# CIS 3.4 — IAM policy changes

resource "aws_cloudwatch_log_metric_filter" "iam_policy_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  name           = "${var.project_name}-${var.environment}-iam-policy-changes"
  pattern        = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  metric_transformation {
    name      = "IAMPolicyChanges"
    namespace = "${var.project_name}/${var.environment}/CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_policy_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  alarm_name          = "${var.project_name}-${var.environment}-iam-policy-changes"
  alarm_description   = "Alerts when IAM policies are created, modified, attached, or deleted"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "IAMPolicyChanges"
  namespace           = "${var.project_name}/${var.environment}/CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.cloudtrail_notifications[0].arn]
  ok_actions    = [aws_sns_topic.cloudtrail_notifications[0].arn]

  tags = var.tags
}

# CIS 3.1 — unauthorized API calls (AccessDenied / UnauthorizedAccess)

resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  name           = "${var.project_name}-${var.environment}-unauthorized-api-calls"
  pattern        = "{($.errorCode=\"*UnauthorizedAccess\")||($.errorCode=\"AccessDenied*\")}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = "${var.project_name}/${var.environment}/CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  alarm_name          = "${var.project_name}-${var.environment}-unauthorized-api-calls"
  alarm_description   = "Alerts when unauthorized API calls are detected (AccessDenied or UnauthorizedAccess)"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedAPICalls"
  namespace           = "${var.project_name}/${var.environment}/CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.cloudtrail_notifications[0].arn]
  ok_actions    = [aws_sns_topic.cloudtrail_notifications[0].arn]

  tags = var.tags
}

# CIS 3.5 — someone touching CloudTrail config

resource "aws_cloudwatch_log_metric_filter" "cloudtrail_config_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  name           = "${var.project_name}-${var.environment}-cloudtrail-config-changes"
  pattern        = "{($.eventName=CreateTrail)||($.eventName=UpdateTrail)||($.eventName=DeleteTrail)||($.eventName=StartLogging)||($.eventName=StopLogging)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  metric_transformation {
    name      = "CloudTrailConfigChanges"
    namespace = "${var.project_name}/${var.environment}/CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_config_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  alarm_name          = "${var.project_name}-${var.environment}-cloudtrail-config-changes"
  alarm_description   = "Alerts when CloudTrail configuration is created, updated, deleted, or logging is started/stopped"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "CloudTrailConfigChanges"
  namespace           = "${var.project_name}/${var.environment}/CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.cloudtrail_notifications[0].arn]
  ok_actions    = [aws_sns_topic.cloudtrail_notifications[0].arn]

  tags = var.tags
}

# CIS 3.8 — S3 bucket policy or ACL changes

resource "aws_cloudwatch_log_metric_filter" "s3_bucket_policy_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  name           = "${var.project_name}-${var.environment}-s3-bucket-policy-changes"
  pattern        = "{($.eventSource=s3.amazonaws.com)&&(($.eventName=PutBucketAcl)||($.eventName=PutBucketPolicy)||($.eventName=PutBucketCors)||($.eventName=PutBucketLifecycle)||($.eventName=PutBucketReplication)||($.eventName=DeleteBucketPolicy)||($.eventName=DeleteBucketCors)||($.eventName=DeleteBucketLifecycle)||($.eventName=DeleteBucketReplication))}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  metric_transformation {
    name      = "S3BucketPolicyChanges"
    namespace = "${var.project_name}/${var.environment}/CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_bucket_policy_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  alarm_name          = "${var.project_name}-${var.environment}-s3-bucket-policy-changes"
  alarm_description   = "Alerts when S3 bucket policies, ACLs, CORS, lifecycle, or replication configurations are changed"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "S3BucketPolicyChanges"
  namespace           = "${var.project_name}/${var.environment}/CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.cloudtrail_notifications[0].arn]
  ok_actions    = [aws_sns_topic.cloudtrail_notifications[0].arn]

  tags = var.tags
}

# CIS 3.9 — AWS Config recorder tampered with

resource "aws_cloudwatch_log_metric_filter" "aws_config_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  name           = "${var.project_name}-${var.environment}-aws-config-changes"
  pattern        = "{($.eventSource=config.amazonaws.com)&&(($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder))}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  metric_transformation {
    name      = "AWSConfigChanges"
    namespace = "${var.project_name}/${var.environment}/CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "aws_config_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  alarm_name          = "${var.project_name}-${var.environment}-aws-config-changes"
  alarm_description   = "Alerts when AWS Config configuration recorder or delivery channel is modified"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "AWSConfigChanges"
  namespace           = "${var.project_name}/${var.environment}/CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.cloudtrail_notifications[0].arn]
  ok_actions    = [aws_sns_topic.cloudtrail_notifications[0].arn]

  tags = var.tags
}

# CIS 3.10 — security group changes

resource "aws_cloudwatch_log_metric_filter" "security_group_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  name           = "${var.project_name}-${var.environment}-security-group-changes"
  pattern        = "{($.eventName=AuthorizeSecurityGroupIngress)||($.eventName=AuthorizeSecurityGroupEgress)||($.eventName=RevokeSecurityGroupIngress)||($.eventName=RevokeSecurityGroupEgress)||($.eventName=CreateSecurityGroup)||($.eventName=DeleteSecurityGroup)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  metric_transformation {
    name      = "SecurityGroupChanges"
    namespace = "${var.project_name}/${var.environment}/CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_group_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  alarm_name          = "${var.project_name}-${var.environment}-security-group-changes"
  alarm_description   = "Alerts when security groups or their ingress/egress rules are created, modified, or deleted"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "SecurityGroupChanges"
  namespace           = "${var.project_name}/${var.environment}/CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.cloudtrail_notifications[0].arn]
  ok_actions    = [aws_sns_topic.cloudtrail_notifications[0].arn]

  tags = var.tags
}

# CIS 3.13 — route table changes

resource "aws_cloudwatch_log_metric_filter" "route_table_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  name           = "${var.project_name}-${var.environment}-route-table-changes"
  pattern        = "{($.eventName=CreateRoute)||($.eventName=CreateRouteTable)||($.eventName=ReplaceRoute)||($.eventName=ReplaceRouteTableAssociation)||($.eventName=DeleteRouteTable)||($.eventName=DeleteRoute)||($.eventName=DisassociateRouteTable)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  metric_transformation {
    name      = "RouteTableChanges"
    namespace = "${var.project_name}/${var.environment}/CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "route_table_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  alarm_name          = "${var.project_name}-${var.environment}-route-table-changes"
  alarm_description   = "Alerts when route tables or routes are created, replaced, deleted, or disassociated"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RouteTableChanges"
  namespace           = "${var.project_name}/${var.environment}/CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.cloudtrail_notifications[0].arn]
  ok_actions    = [aws_sns_topic.cloudtrail_notifications[0].arn]

  tags = var.tags
}

# CIS 3.14 — VPC/peering/gateway changes

resource "aws_cloudwatch_log_metric_filter" "vpc_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  name           = "${var.project_name}-${var.environment}-vpc-changes"
  pattern        = "{($.eventName=CreateVpc)||($.eventName=DeleteVpc)||($.eventName=ModifyVpcAttribute)||($.eventName=AcceptVpcPeeringConnection)||($.eventName=CreateVpcPeeringConnection)||($.eventName=DeleteVpcPeeringConnection)||($.eventName=RejectVpcPeeringConnection)||($.eventName=AttachClassicLinkVpc)||($.eventName=DetachClassicLinkVpc)||($.eventName=DisableVpcClassicLink)||($.eventName=EnableVpcClassicLink)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  metric_transformation {
    name      = "VPCChanges"
    namespace = "${var.project_name}/${var.environment}/CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "vpc_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  alarm_name          = "${var.project_name}-${var.environment}-vpc-changes"
  alarm_description   = "Alerts when VPCs, subnets, route tables, gateways, or peering connections are modified"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "VPCChanges"
  namespace           = "${var.project_name}/${var.environment}/CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.cloudtrail_notifications[0].arn]
  ok_actions    = [aws_sns_topic.cloudtrail_notifications[0].arn]

  tags = var.tags
}

# CIS 3.12 — internet gateway or NAT gateway changes

resource "aws_cloudwatch_log_metric_filter" "network_gateway_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  name           = "${var.project_name}-${var.environment}-network-gateway-changes"
  pattern        = "{($.eventName=CreateCustomerGateway)||($.eventName=DeleteCustomerGateway)||($.eventName=AttachInternetGateway)||($.eventName=CreateInternetGateway)||($.eventName=DeleteInternetGateway)||($.eventName=DetachInternetGateway)||($.eventName=CreateNatGateway)||($.eventName=DeleteNatGateway)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  metric_transformation {
    name      = "NetworkGatewayChanges"
    namespace = "${var.project_name}/${var.environment}/CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "network_gateway_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  alarm_name          = "${var.project_name}-${var.environment}-network-gateway-changes"
  alarm_description   = "Alerts when internet gateways, NAT gateways, or customer gateways are created, deleted, or modified"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "NetworkGatewayChanges"
  namespace           = "${var.project_name}/${var.environment}/CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.cloudtrail_notifications[0].arn]
  ok_actions    = [aws_sns_topic.cloudtrail_notifications[0].arn]

  tags = var.tags
}

# CIS 3.7 — KMS key disabled or scheduled for deletion

resource "aws_cloudwatch_log_metric_filter" "kms_cmk_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  name           = "${var.project_name}-${var.environment}-kms-cmk-changes"
  pattern        = "{($.eventSource=kms.amazonaws.com)&&(($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion))}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  metric_transformation {
    name      = "KMSCMKChanges"
    namespace = "${var.project_name}/${var.environment}/CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "kms_cmk_changes" {
  count = var.enable_cloudtrail && var.enable_cloudwatch && var.enable_cloudtrail_sns_notifications ? 1 : 0

  alarm_name          = "${var.project_name}-${var.environment}-kms-cmk-changes"
  alarm_description   = "Alerts when KMS customer-managed keys are disabled or scheduled for deletion"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "KMSCMKChanges"
  namespace           = "${var.project_name}/${var.environment}/CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.cloudtrail_notifications[0].arn]
  ok_actions    = [aws_sns_topic.cloudtrail_notifications[0].arn]

  tags = var.tags
}

# KMS key in us-east-1 for WAF logs and Route53 query logs
# Skipped when we're already in us-east-1 — the observability key covers it

resource "aws_kms_key" "us_east_1" {
  count    = local.is_us_east_1 ? 0 : 1
  provider = aws.us_east_1

  description             = "KMS key for ${var.project_name} us-east-1 resources (WAF logs, Route53 query logs)"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = 90

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudWatchLogsEncryption"
        Effect = "Allow"
        Principal = {
          Service = "logs.us-east-1.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:us-east-1:${data.aws_caller_identity.current.account_id}:log-group:*"
          }
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-us-east-1-kms-key"
  })
}

resource "aws_kms_alias" "us_east_1" {
  count    = local.is_us_east_1 ? 0 : 1
  provider = aws.us_east_1

  name          = "alias/${var.project_name}-${var.environment}-us-east-1"
  target_key_id = aws_kms_key.us_east_1[0].key_id
}
