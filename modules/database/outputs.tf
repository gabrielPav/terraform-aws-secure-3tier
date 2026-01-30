output "rds_instance_id" {
  description = "RDS instance ID"
  value       = aws_db_instance.main.id
}

output "rds_endpoint" {
  description = "RDS endpoint"
  value       = aws_db_instance.main.endpoint
  sensitive   = true
}

output "rds_address" {
  description = "RDS address"
  value       = aws_db_instance.main.address
  sensitive   = true
}

output "rds_port" {
  description = "RDS port"
  value       = aws_db_instance.main.port
}

output "rds_arn" {
  description = "RDS ARN"
  value       = aws_db_instance.main.arn
}

output "rds_master_user_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the master user password"
  value       = aws_db_instance.main.master_user_secret[0].secret_arn
  sensitive   = true
}
