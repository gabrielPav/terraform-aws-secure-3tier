# ============================================================================
# Storage Module - S3 and EFS
# ============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# This is used in outputs
data "aws_region" "current_for_output" {
  count = var.enable_efs ? 1 : 0
}

# ============================================================================
# S3 Bucket
# ============================================================================

resource "aws_s3_bucket" "main" {
  bucket = var.s3_bucket_name

  tags = merge(var.tags, {
    Name = var.s3_bucket_name
  })
}

resource "aws_s3_bucket_public_access_block" "main" {
  bucket = aws_s3_bucket.main.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "main" {
  count  = var.enable_s3_versioning ? 1 : 0
  bucket = aws_s3_bucket.main.id

  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Enabled"
  }
}

# ============================================================================
# Centralized S3 Access Logs Bucket
# ============================================================================
# This bucket stores S3 server access logs for all S3 buckets in the project

resource "aws_s3_bucket" "s3_access_logs" {
  bucket = "${var.project_name}-${var.environment}-s3-access-logs"

  tags = merge(var.tags, {
    Name    = "${var.project_name}-${var.environment}-s3-access-logs"
    Purpose = "Centralized S3 server access logs"
  })
}

resource "aws_s3_bucket_public_access_block" "s3_access_logs" {
  bucket = aws_s3_bucket.s3_access_logs.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "s3_access_logs" {
  bucket = aws_s3_bucket.s3_access_logs.id

  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_access_logs" {
  bucket = aws_s3_bucket.s3_access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "s3_access_logs" {
  bucket = aws_s3_bucket.s3_access_logs.id

  rule {
    id     = "transition-logs-to-ia"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }

  rule {
    id     = "transition-logs-to-glacier"
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
}

# Bucket policy to allow S3 logging service to write logs
resource "aws_s3_bucket_policy" "s3_access_logs" {
  bucket = aws_s3_bucket.s3_access_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ServerAccessLogsPolicy"
        Effect = "Allow"
        Principal = {
          Service = "logging.s3.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.s3_access_logs.arn}/*"
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:aws:s3:::${var.project_name}-${var.environment}-*"
          }
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# Main bucket S3 server access logging configuration
resource "aws_s3_bucket_logging" "main" {
  bucket = aws_s3_bucket.main.id

  target_bucket = aws_s3_bucket.s3_access_logs.id
  target_prefix = "main-bucket/"
}

# S3 access logs bucket - self logging configuration
resource "aws_s3_bucket_logging" "s3_access_logs" {
  bucket = aws_s3_bucket.s3_access_logs.id

  target_bucket = aws_s3_bucket.s3_access_logs.id
  target_prefix = "self-access-logs/"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "main" {
  count  = var.enable_s3_encryption ? 1 : 0
  bucket = aws_s3_bucket.main.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "main" {
  bucket = aws_s3_bucket.main.id

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
}

# ============================================================================
# EFS File System
# ============================================================================

resource "aws_efs_file_system" "main" {
  count = var.enable_efs ? 1 : 0

  creation_token   = "${var.project_name}-${var.environment}-efs"
  performance_mode = var.efs_performance_mode
  throughput_mode  = var.efs_throughput_mode
  encrypted        = true
  kms_key_id       = var.kms_key_id

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-efs"
  })
}

resource "aws_efs_backup_policy" "main" {
  count          = var.enable_efs && var.enable_efs_backups ? 1 : 0
  file_system_id = aws_efs_file_system.main[0].id

  backup_policy {
    status = "ENABLED"
  }
}

resource "aws_efs_file_system_policy" "main" {
  count = var.enable_efs ? 1 : 0

  file_system_id = aws_efs_file_system.main[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = [
          "elasticfilesystem:ClientMount",
          "elasticfilesystem:ClientWrite"
        ]
        Condition = {
          Bool = {
            "elasticfilesystem:AccessedViaMountTarget" = "true"
            "aws:SecureTransport"                      = "true"
          }
        }
      },
      {
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action = [
          "elasticfilesystem:ClientRootAccess"
        ]
      }
    ]
  })
}

resource "aws_efs_mount_target" "main" {
  count = var.enable_efs ? length(var.private_subnet_ids) : 0

  file_system_id  = aws_efs_file_system.main[0].id
  subnet_id       = var.private_subnet_ids[count.index]
  security_groups = [aws_security_group.efs[0].id]
}

resource "aws_security_group" "efs" {
  count = var.enable_efs ? 1 : 0

  name        = "${var.project_name}-${var.environment}-efs-sg"
  description = "Security group for EFS"
  vpc_id      = var.vpc_id

  tags = var.tags
}

# Ingress rules: NFS from allowed security groups
resource "aws_vpc_security_group_ingress_rule" "efs_nfs_from_sg" {
  count = var.enable_efs ? length(var.allowed_security_groups) : 0

  security_group_id            = aws_security_group.efs[0].id
  referenced_security_group_id = var.allowed_security_groups[count.index]

  description = "NFS from allowed security groups"
  from_port   = 2049
  to_port     = 2049
  ip_protocol = "tcp"
}

# Egress rule: allow all outbound
resource "aws_vpc_security_group_egress_rule" "efs_allow_all_outbound" {
  count = var.enable_efs ? 1 : 0

  security_group_id = aws_security_group.efs[0].id

  description = "Allow all outbound"
  ip_protocol = "-1"
  cidr_ipv4   = "0.0.0.0/0"
}

resource "aws_efs_access_point" "main" {
  count = var.enable_efs ? 1 : 0

  file_system_id = aws_efs_file_system.main[0].id

  posix_user {
    gid = 1000
    uid = 1000
  }

  root_directory {
    path = "/app"
    creation_info {
      owner_gid   = 1000
      owner_uid   = 1000
      permissions = "755"
    }
  }

  tags = var.tags
}
