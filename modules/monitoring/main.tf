# ============================================================================
# Monitoring Module - CloudWatch
# ============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "main" {
  count = var.enable_dashboard ? 1 : 0

  dashboard_name = "${var.project_name}-${var.environment}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", var.alb_arn_suffix, { "stat" = "Sum" }],
            [".", "TargetResponseTime", ".", ".", { "stat" = "Average" }],
            [".", "HTTPCode_Target_2XX_Count", ".", ".", { "stat" = "Sum" }],
            [".", "HTTPCode_Target_4XX_Count", ".", ".", { "stat" = "Sum" }],
            [".", "HTTPCode_Target_5XX_Count", ".", ".", { "stat" = "Sum" }]
          ]
          period = 300
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "ALB Metrics"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/AutoScaling", "GroupDesiredCapacity", "AutoScalingGroupName", var.asg_name, { "stat" = "Average" }],
            [".", "GroupInServiceInstances", ".", ".", { "stat" = "Average" }],
            [".", "GroupTotalInstances", ".", ".", { "stat" = "Average" }]
          ]
          period = 300
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "Auto Scaling Metrics"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", var.rds_instance_id, { "stat" = "Average" }],
            [".", "DatabaseConnections", ".", ".", { "stat" = "Average" }],
            [".", "FreeableMemory", ".", ".", { "stat" = "Average" }]
          ]
          period = 300
          stat   = "Average"
          region = data.aws_region.current.name
          title  = "RDS Metrics"
        }
      }
    ]
  })
}

# ============================================================================
# SNS Topic for Alarm Notifications
# ============================================================================
# Only created when alarm_notification_email is provided.
# Email subscription requires manual confirmation via email link.
# ============================================================================

resource "aws_sns_topic" "alarms" {
  count = var.alarm_notification_email != "" ? 1 : 0

  name              = "${var.project_name}-${var.environment}-alarm-notifications"
  kms_master_key_id = var.kms_key_arn

  tags = var.tags
}

resource "aws_sns_topic_policy" "alarms" {
  count = var.alarm_notification_email != "" ? 1 : 0

  arn = aws_sns_topic.alarms[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudWatchAlarmsPublish"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alarms[0].arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AllowRDSEventsPublish"
        Effect = "Allow"
        Principal = {
          Service = "events.rds.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alarms[0].arn
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
  count = var.alarm_notification_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.alarms[0].arn
  protocol  = "email"
  endpoint  = var.alarm_notification_email
}

# ============================================================================
# RDS Event Subscription (Instance-Level)
# ============================================================================
# Notifies on failover, failure, maintenance, and other critical RDS events.
# Only created when an alarm notification email is provided (SNS topic exists).
# ============================================================================

resource "aws_db_event_subscription" "instance" {
  count = var.alarm_notification_email != "" ? 1 : 0

  name      = "${var.project_name}-${var.environment}-rds-instance-events"
  sns_topic = aws_sns_topic.alarms[0].arn

  source_type = "db-instance"
  source_ids  = [var.rds_instance_id]

  event_categories = [
    "availability",
    "deletion",
    "failover",
    "failure",
    "low storage",
    "maintenance",
    "notification",
    "recovery",
  ]

  tags = var.tags
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "alb_high_5xx" {
  count = var.enable_alarms ? 1 : 0

  alarm_name          = "${var.project_name}-${var.environment}-alb-high-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "ALB 5xx error rate exceeded threshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_notification_email != "" ? [aws_sns_topic.alarms[0].arn] : []
  ok_actions          = var.alarm_notification_email != "" ? [aws_sns_topic.alarms[0].arn] : []

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "asg_cpu_high" {
  count = var.enable_alarms && var.asg_name != "" ? 1 : 0

  alarm_name          = "${var.project_name}-${var.environment}-asg-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "EC2 CPU above 80%"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_notification_email != "" ? [aws_sns_topic.alarms[0].arn] : []
  ok_actions          = var.alarm_notification_email != "" ? [aws_sns_topic.alarms[0].arn] : []

  dimensions = {
    AutoScalingGroupName = var.asg_name
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "rds_cpu_high" {
  count = var.enable_alarms && var.enable_rds_alarm ? 1 : 0

  alarm_name          = "${var.project_name}-${var.environment}-rds-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "RDS CPU above 80%"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_notification_email != "" ? [aws_sns_topic.alarms[0].arn] : []
  ok_actions          = var.alarm_notification_email != "" ? [aws_sns_topic.alarms[0].arn] : []

  dimensions = {
    DBInstanceIdentifier = var.rds_instance_id
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "rds_low_storage" {
  count = var.enable_alarms && var.enable_rds_alarm ? 1 : 0

  alarm_name          = "${var.project_name}-${var.environment}-rds-low-storage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 5368709120 # 5 GB in bytes
  alarm_description   = "RDS free storage space below 5 GB"
  treat_missing_data  = "notBreaching"
  alarm_actions       = var.alarm_notification_email != "" ? [aws_sns_topic.alarms[0].arn] : []
  ok_actions          = var.alarm_notification_email != "" ? [aws_sns_topic.alarms[0].arn] : []

  dimensions = {
    DBInstanceIdentifier = var.rds_instance_id
  }

  tags = var.tags
}
