# ============================================================================
# Database Module - RDS Multi-AZ
# ============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# DB Subnet Group
resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-${var.environment}-db-subnet-group"
  subnet_ids = var.private_subnet_ids

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-db-subnet-group"
  })
}

# Security Group for RDS
resource "aws_security_group" "rds" {
  name        = "${var.project_name}-${var.environment}-rds-sg"
  description = "Security group for RDS"
  vpc_id      = var.vpc_id

  tags = var.tags
}

# Ingress rule: MySQL/Aurora from EC2 SG
resource "aws_vpc_security_group_ingress_rule" "rds_mysql_from_ec2" {
  security_group_id = aws_security_group.rds.id

  description = "MySQL/Aurora from EC2"
  from_port   = var.db_port
  to_port     = var.db_port
  ip_protocol = "tcp"

  referenced_security_group_id = var.allowed_security_group_id
}

# Egress rule: Allow all outbound
resource "aws_vpc_security_group_egress_rule" "rds_allow_all_outbound" {
  security_group_id = aws_security_group.rds.id

  description = "Allow all outbound"
  ip_protocol = "-1"
  cidr_ipv4   = "0.0.0.0/0"
}

# DB Parameter Group
resource "aws_db_parameter_group" "main" {
  name   = "${var.project_name}-${var.environment}-db-params"
  family = var.db_parameter_group_family

  # Use utf8mb4_general_ci collation for compatibility with older PHP mysqli clients
  parameter {
    name  = "character_set_server"
    value = "utf8mb4"
  }

  parameter {
    name  = "collation_server"
    value = "utf8mb4_general_ci"
  }

  # Enforce SSL/TLS for all connections (encryption in transit)
  parameter {
    name  = "require_secure_transport"
    value = "1"
  }

  tags = var.tags
}

# RDS Instance
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

  # Enabling AWS Secrets Manager integration
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

  enabled_cloudwatch_logs_exports = ["error", "general", "slowquery"]

  deletion_protection        = var.deletion_protection
  skip_final_snapshot        = var.environment == "production" ? false : true
  copy_tags_to_snapshot      = true
  auto_minor_version_upgrade = true

  kms_key_id = var.kms_key_id

  tags = var.tags
}
