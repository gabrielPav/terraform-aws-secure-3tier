# Database — RDS with encryption, TLS, and Secrets Manager credentials

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  db_parameter_group_family = "${var.db_engine}${var.db_engine_version}"
}

# Subnet group — private subnets only
resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-${var.environment}-db-subnet-group"
  subnet_ids = var.private_subnet_ids

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-db-subnet-group"
  })
}

# RDS security group
resource "aws_security_group" "rds" {
  name        = "${var.project_name}-${var.environment}-rds-sg"
  description = "Security group for RDS"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-rds-sg"
  })
}

# Only EC2 instances can talk to the database
resource "aws_vpc_security_group_ingress_rule" "rds_mysql_from_ec2" {
  security_group_id = aws_security_group.rds.id

  description = "MySQL/Aurora from EC2"
  from_port   = var.db_port
  to_port     = var.db_port
  ip_protocol = "tcp"

  referenced_security_group_id = var.allowed_security_group_id
}

# No egress rules — SGs are stateful, responses flow back on their own

# Enhanced Monitoring IAM role
resource "aws_iam_role" "rds_enhanced_monitoring" {
  count = var.enhanced_monitoring_interval > 0 ? 1 : 0

  name_prefix = "${var.project_name}-${var.environment}-rds-mon-role-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowRDSMonitoringAssumeRole"
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "monitoring.rds.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  count = var.enhanced_monitoring_interval > 0 ? 1 : 0

  role       = aws_iam_role.rds_enhanced_monitoring[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# Parameter group — UTF-8 + forced TLS
resource "aws_db_parameter_group" "main" {
  name   = "${var.project_name}-${var.environment}-db-params"
  family = local.db_parameter_group_family

  # utf8mb4 with general_ci for broad PHP mysqli compatibility
  parameter {
    name  = "character_set_server"
    value = "utf8mb4"
  }

  parameter {
    name  = "collation_server"
    value = "utf8mb4_general_ci"
  }

  # No plaintext connections — TLS or nothing
  parameter {
    name  = "require_secure_transport"
    value = "1"
  }

  tags = var.tags
}

# The database — add lifecycle { prevent_destroy = true } in prod
resource "aws_db_instance" "main" {
  identifier = "${var.project_name}-${var.environment}-db"

  engine         = var.db_engine
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = var.db_name
  username = var.db_username

  manage_master_user_password   = true
  master_user_secret_kms_key_id = var.kms_key_id

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  parameter_group_name   = aws_db_parameter_group.main.name

  multi_az                = var.multi_az
  publicly_accessible     = false
  backup_retention_period = var.backup_retention_period
  backup_window           = "03:00-04:00"
  maintenance_window      = "mon:04:00-mon:05:00"

  # Skipping "general" log — it captures every query, including sensitive data
  enabled_cloudwatch_logs_exports = ["error", "slowquery"]

  # Enhanced monitoring — OS-level metrics every 60s
  monitoring_interval = var.enhanced_monitoring_interval
  monitoring_role_arn = var.enhanced_monitoring_interval > 0 ? aws_iam_role.rds_enhanced_monitoring[0].arn : null

  # Performance Insights — free tier gives 7 days of history
  performance_insights_enabled          = var.performance_insights_enabled
  performance_insights_retention_period = var.performance_insights_enabled ? var.performance_insights_retention_period : null
  performance_insights_kms_key_id       = var.performance_insights_enabled ? var.kms_key_id : null

  deletion_protection        = var.deletion_protection
  skip_final_snapshot        = var.environment == "production" ? false : true
  final_snapshot_identifier  = var.environment == "production" ? "${var.project_name}-${var.environment}-db-final-snapshot" : null
  copy_tags_to_snapshot      = true
  auto_minor_version_upgrade = true

  kms_key_id = var.kms_key_id

  tags = var.tags
}
