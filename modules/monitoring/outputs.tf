output "cloudwatch_log_group_name" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.app.name
}

output "cloudwatch_dashboard_url" {
  description = "CloudWatch dashboard URL"
  value       = var.enable_dashboard ? "https://console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.main[0].dashboard_name}" : null
}

output "sns_topic_arn" {
  description = "SNS topic ARN for alarm notifications. Empty if no email was provided."
  value       = var.alarm_notification_email != "" ? aws_sns_topic.alarms[0].arn : null
}
