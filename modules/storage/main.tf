# Storage — S3 buckets, access logging, cross-region replication

terraform {
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 5.0"
      configuration_aliases = [aws.replica]
    }
  }
}

data "aws_caller_identity" "current" {}

# Main bucket — add lifecycle { prevent_destroy = true } in prod
resource "aws_s3_bucket" "main" {
  bucket              = var.s3_bucket_name
  object_lock_enabled = var.enable_s3_object_lock

  tags = merge(var.tags, {
    Name = var.s3_bucket_name
  })
}

resource "aws_s3_bucket_ownership_controls" "main" {
  bucket = aws_s3_bucket.main.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "main" {
  bucket = aws_s3_bucket.main.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "main" {
  count  = var.enable_s3_versioning || var.enable_s3_object_lock ? 1 : 0
  bucket = aws_s3_bucket.main.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "main" {
  count  = var.enable_s3_object_lock ? 1 : 0
  bucket = aws_s3_bucket.main.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.s3_object_lock_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.main]
}

# Centralized access logs bucket — collects logs from all project S3 buckets

resource "aws_s3_bucket" "s3_access_logs" {
  bucket              = "${var.project_name}-${var.environment}-s3-access-logs-${data.aws_caller_identity.current.account_id}"
  object_lock_enabled = var.enable_s3_object_lock_access_logs

  tags = merge(var.tags, {
    Name    = "${var.project_name}-${var.environment}-s3-access-logs"
    Purpose = "Centralized S3 server access logs"
  })
}

resource "aws_s3_bucket_ownership_controls" "s3_access_logs" {
  bucket = aws_s3_bucket.s3_access_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
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
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "s3_access_logs" {
  count  = var.enable_s3_object_lock_access_logs ? 1 : 0
  bucket = aws_s3_bucket.s3_access_logs.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.s3_object_lock_access_logs_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.s3_access_logs]
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

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Allow S3 and CloudFront logging services to write here
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
      },
      {
        Sid    = "CloudFrontLogsPolicy"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action = [
          "s3:PutObject",
          "s3:GetBucketAcl"
        ]
        Resource = [
          "${aws_s3_bucket.s3_access_logs.arn}/*",
          aws_s3_bucket.s3_access_logs.arn
        ]
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid       = "EnforceTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.s3_access_logs.arn,
          "${aws_s3_bucket.s3_access_logs.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

# HTTPS-only — skipped when the CDN module manages its own bucket policy
resource "aws_s3_bucket_policy" "main" {
  count  = var.skip_bucket_policy ? 0 : 1
  bucket = aws_s3_bucket.main.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.main.arn,
          "${aws_s3_bucket.main.arn}/*"
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
        Resource  = "${aws_s3_bucket.main.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

# Ship access logs to the centralized logging bucket
resource "aws_s3_bucket_logging" "main" {
  bucket = aws_s3_bucket.main.id

  target_bucket = aws_s3_bucket.s3_access_logs.id
  target_prefix = "assets-bucket/"
}

# SSE-KMS with bucket key — cheaper than per-object KMS calls
resource "aws_s3_bucket_server_side_encryption_configuration" "main" {
  bucket = aws_s3_bucket.main.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_id
    }
    bucket_key_enabled = true
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
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Cross-region replication — async copy to a second region for DR.
# Delete marker replication is off so malicious deletes don't propagate.

# KMS key in the replica region — replicated objects get re-encrypted here
resource "aws_kms_key" "replica" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  description             = "KMS key for ${var.project_name} S3 replica encryption"
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
        Sid    = "AllowS3ReplicationRoleToUseTheKey"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.s3_replication[0].arn
        }
        Action = [
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowS3ServiceToUseTheKey"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:GenerateDataKey*"
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
    Name = "${var.project_name}-${var.environment}-replica-kms-key"
  })
}

resource "aws_kms_alias" "replica" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  name          = "alias/${var.project_name}-${var.environment}-s3-replica"
  target_key_id = aws_kms_key.replica[0].key_id
}

# Replica bucket in the secondary region
resource "aws_s3_bucket" "replica" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  bucket = "${var.s3_bucket_name}-replica"

  tags = merge(var.tags, {
    Name = "${var.s3_bucket_name}-replica"
  })
}

resource "aws_s3_bucket_versioning" "replica" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.replica[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "replica" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.replica[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.replica[0].arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "replica" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.replica[0].id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "replica" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.replica[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_policy" "replica" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.replica[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.replica[0].arn,
          "${aws_s3_bucket.replica[0].arn}/*"
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
        Resource  = "${aws_s3_bucket.replica[0].arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "replica" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.replica[0].id

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
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Access logs for the replica bucket — same pattern, different region
resource "aws_s3_bucket" "replica_access_logs" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  bucket = "${var.s3_bucket_name}-replica-access-logs"

  tags = merge(var.tags, {
    Name    = "${var.s3_bucket_name}-replica-access-logs"
    Purpose = "S3 server access logs for replica bucket"
  })
}

resource "aws_s3_bucket_ownership_controls" "replica_access_logs" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.replica_access_logs[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "replica_access_logs" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.replica_access_logs[0].id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "replica_access_logs" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.replica_access_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "replica_access_logs" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.replica_access_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "replica_access_logs" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.replica_access_logs[0].id

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

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "replica_access_logs" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.replica_access_logs[0].id

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
        Resource = "${aws_s3_bucket.replica_access_logs[0].arn}/*"
        Condition = {
          ArnLike = {
            "aws:SourceArn" = aws_s3_bucket.replica[0].arn
          }
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid       = "EnforceTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.replica_access_logs[0].arn,
          "${aws_s3_bucket.replica_access_logs[0].arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

# Point replica bucket logs to its own logging bucket
resource "aws_s3_bucket_logging" "replica" {
  count    = var.enable_s3_crr ? 1 : 0
  provider = aws.replica

  bucket = aws_s3_bucket.replica[0].id

  target_bucket = aws_s3_bucket.replica_access_logs[0].id
  target_prefix = "replica-bucket/"
}

# IAM role — S3 assumes this to read source and write to the replica
resource "aws_iam_role" "s3_replication" {
  count       = var.enable_s3_crr ? 1 : 0
  name_prefix = "${var.project_name}-${var.environment}-s3-repl-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowS3AssumeReplicationRole"
      Effect = "Allow"
      Principal = {
        Service = "s3.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "s3_replication" {
  count = var.enable_s3_crr ? 1 : 0
  name  = "${var.project_name}-${var.environment}-s3-replication"
  role  = aws_iam_role.s3_replication[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SourceBucketAccess"
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket",
          "s3:GetBucketVersioning"
        ]
        Resource = aws_s3_bucket.main.arn
      },
      {
        Sid    = "SourceObjectAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging"
        ]
        Resource = "${aws_s3_bucket.main.arn}/*"
      },
      {
        Sid    = "DestinationReplication"
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateTags"
        ]
        Resource = "${aws_s3_bucket.replica[0].arn}/*"
      },
      {
        Sid    = "SourceKMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = var.kms_key_arn
      },
      {
        Sid    = "DestinationKMSEncrypt"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.replica[0].arn
      }
    ]
  })
}

# Replication rule — replicate everything, re-encrypt with replica KMS key
resource "aws_s3_bucket_replication_configuration" "main" {
  count  = var.enable_s3_crr ? 1 : 0
  bucket = aws_s3_bucket.main.id
  role   = aws_iam_role.s3_replication[0].arn

  rule {
    id     = "replicate-all"
    status = "Enabled"

    filter {}

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket        = aws_s3_bucket.replica[0].arn
      storage_class = "STANDARD_IA"

      encryption_configuration {
        replica_kms_key_id = aws_kms_key.replica[0].arn
      }
    }

    delete_marker_replication {
      status = "Disabled"
    }
  }

  depends_on = [
    aws_s3_bucket_versioning.main,
    aws_s3_bucket_versioning.replica
  ]
}
