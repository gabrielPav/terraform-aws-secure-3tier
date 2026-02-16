# Root module — wires everything together

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = merge(
      var.common_tags,
      {
        ManagedBy   = "Terraform"
        Environment = var.environment
        Project     = var.project_name
      }
    )
  }
}

# CloudFront needs certs in us-east-1
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  default_tags {
    tags = merge(
      var.common_tags,
      {
        ManagedBy   = "Terraform"
        Environment = var.environment
        Project     = var.project_name
      }
    )
  }
}

# Replica region for S3 cross-region replication
provider "aws" {
  alias  = "replica"
  region = var.s3_replica_region
  default_tags {
    tags = merge(
      var.common_tags,
      {
        ManagedBy   = "Terraform"
        Environment = var.environment
        Project     = var.project_name
      }
    )
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

# Networking

module "networking" {
  source = "./modules/networking"

  project_name                 = var.project_name
  vpc_name                     = "${var.project_name}-${var.environment}-vpc"
  vpc_cidr                     = var.vpc_cidr
  number_of_availability_zones = var.number_of_availability_zones
  enable_nat_gateway           = var.enable_nat_gateway
  single_nat_gateway           = var.environment == "production" ? false : true
  enable_flow_logs             = true
  enable_s3_endpoint           = true
  enable_interface_endpoints   = var.enable_vpc_endpoints
  kms_key_arn                  = module.security.kms_observability_key_arn
  tags                         = var.common_tags
}

# Security (IAM, KMS, CloudTrail)

module "security" {
  source = "./modules/security"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  aws_region               = var.aws_region
  project_name             = var.project_name
  environment              = var.environment
  s3_bucket_name           = "${var.project_name}-${var.environment}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  cloudtrail_name          = "${var.project_name}-${var.environment}-cloudtrail"
  log_retention_days       = var.cloudwatch_log_retention_days
  enable_cloudtrail        = true
  enable_cloudwatch        = true
  s3_access_logs_bucket_id = module.storage.s3_access_logs_bucket_id
  enable_s3_access_logging = true

  # Object Lock for CloudTrail bucket
  enable_object_lock_cloudtrail         = var.enable_object_lock_cloudtrail
  object_lock_cloudtrail_retention_days = var.object_lock_cloudtrail_retention_days

  # SNS alerts for security events
  enable_cloudtrail_sns_notifications = var.enable_cloudtrail_sns_notifications
  alarm_notification_email            = var.alarm_notification_email

  # SSM agent needs outbound internet to reach AWS endpoints — no NAT, no SSM
  enable_ssm = var.enable_nat_gateway && var.enable_ssm

  tags = var.common_tags
}

# Storage (S3)

module "storage" {
  source = "./modules/storage"

  providers = {
    aws         = aws
    aws.replica = aws.replica
  }

  project_name = var.project_name
  environment  = var.environment
  kms_key_id   = module.security.kms_storage_key_id
  kms_key_arn  = module.security.kms_storage_key_arn

  # S3 Configuration
  s3_bucket_name       = "${var.project_name}-${var.environment}-assets-${data.aws_caller_identity.current.account_id}"
  enable_s3_versioning = true

  # Object Lock (Governance Mode)
  enable_s3_object_lock         = var.enable_s3_object_lock
  s3_object_lock_retention_days = var.s3_object_lock_retention_days

  # Object Lock for S3 access logs bucket
  enable_s3_object_lock_access_logs         = var.enable_s3_object_lock_access_logs
  s3_object_lock_access_logs_retention_days = var.s3_object_lock_access_logs_retention_days

  # CDN module manages the assets bucket policy when CloudFront is on
  skip_bucket_policy = var.enable_cloudfront

  # Cross-region replication for disaster recovery
  enable_s3_crr = var.enable_s3_crr

  tags = var.common_tags
}

# Database (RDS)

module "database" {
  source = "./modules/database"

  project_name              = var.project_name
  environment               = var.environment
  vpc_id                    = module.networking.vpc_id
  private_subnet_ids        = module.networking.private_subnet_ids
  allowed_security_group_id = module.compute.ec2_security_group_id
  kms_key_id                = module.security.kms_data_key_arn
  kms_key_observability_arn = module.security.kms_observability_key_arn

  # RDS Configuration
  db_instance_class       = var.rds_instance_class
  db_engine               = var.rds_engine
  db_engine_version       = var.rds_engine_version
  db_name                 = var.rds_database_name
  db_username             = var.rds_username
  db_allocated_storage    = var.rds_allocated_storage
  multi_az                = var.rds_multi_az
  backup_retention_period = var.rds_backup_retention_period

  tags = var.common_tags
}

# Compute (EC2, Auto Scaling, EBS)

module "compute" {
  source = "./modules/compute"

  project_name       = var.project_name
  environment        = var.environment
  vpc_id             = module.networking.vpc_id
  private_subnet_ids = module.networking.private_subnet_ids
  s3_bucket_name     = module.storage.s3_bucket_name
  rds_endpoint       = module.database.rds_address
  rds_port           = module.database.rds_port
  db_name            = var.rds_database_name
  db_secret_arn      = module.database.rds_master_user_secret_arn

  # EC2 Configuration
  instance_type    = var.ec2_instance_type
  min_size         = var.asg_min_size
  max_size         = var.asg_max_size
  desired_capacity = var.asg_desired_capacity
  ebs_volume_size  = var.ebs_volume_size
  ebs_volume_type  = "gp3"
  kms_key_arn      = module.security.kms_compute_key_arn

  # IAM
  iam_instance_profile   = module.security.ec2_instance_profile_name
  alb_security_group_ids = [module.load_balancer.alb_security_group_id]

  # Security group for RDS egress
  allowed_security_group_id = [module.database.rds_security_group_id]

  tags = var.common_tags
}

# Load Balancer (ALB)

module "load_balancer" {
  source = "./modules/load-balancer"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  project_name       = var.project_name
  environment        = var.environment
  vpc_id             = module.networking.vpc_id
  vpc_cidr           = var.vpc_cidr
  public_subnet_ids  = module.networking.public_subnet_ids
  private_subnet_ids = module.networking.private_subnet_ids
  target_group_arns  = [module.compute.target_group_arn]

  # ALB Configuration
  alb_internal               = false
  enable_access_logs         = true
  s3_access_logs_bucket_id   = module.storage.s3_access_logs_bucket_id
  enable_deletion_protection = var.environment == "production" ? true : false

  # Object Lock for ALB logs bucket
  enable_object_lock_alb_logs         = var.enable_object_lock_alb_logs
  object_lock_alb_logs_retention_days = var.object_lock_alb_logs_retention_days
  enable_http2                        = true
  enable_cross_zone                   = true

  # KMS for Route53 query logs (must live in us-east-1)
  us_east_1_kms_key_arn = module.security.us_east_1_kms_key_arn

  # TLS — ACM cert auto-created and DNS-validated via Route53
  domain_name            = var.domain_name
  redirect_http_to_https = var.redirect_http_to_https
  create_route53_zone    = var.create_route53_zone

  enable_https = true

  # Lock ALB ingress to CloudFront IPs when CDN is on
  restrict_ingress_to_cloudfront = var.enable_cloudfront

  # Skip Route53 A record when CloudFront handles DNS
  create_dns_record = !var.enable_cloudfront

  tags = var.common_tags
}

# CDN (CloudFront)

module "cdn" {
  source = "./modules/cdn"

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  project_name              = var.project_name
  environment               = var.environment
  alb_dns_name              = module.load_balancer.alb_dns_name
  alb_zone_id               = module.load_balancer.alb_zone_id
  s3_bucket_id              = module.storage.s3_bucket_name
  s3_bucket_domain_name     = module.storage.s3_bucket_domain_name
  s3_access_logs_bucket_arn = module.storage.s3_access_logs_bucket_arn

  # CloudFront Configuration
  enable_cloudfront  = var.enable_cloudfront
  price_class        = "PriceClass_All"
  enable_https       = true
  enable_compression = true
  enable_logging     = true

  # ACM — reuses ALB cert in us-east-1, creates a separate one otherwise
  domain_name         = var.domain_name
  aws_region          = var.aws_region
  route53_zone_id     = module.load_balancer.route53_zone_id
  alb_certificate_arn = module.load_balancer.acm_certificate_arn

  # KMS for WAF logs (must live in us-east-1)
  us_east_1_kms_key_arn = module.security.us_east_1_kms_key_arn

  # WAF (optional)
  enable_waf = var.enable_waf

  # Geo Restriction (optional)
  enable_geo_restriction    = var.enable_geo_restriction
  geo_restriction_type      = var.geo_restriction_type
  geo_restriction_locations = var.geo_restriction_locations

  tags = var.common_tags
}

# Monitoring (CloudWatch)

module "monitoring" {
  source = "./modules/monitoring"

  project_name    = var.project_name
  environment     = var.environment
  vpc_id          = module.networking.vpc_id
  alb_arn_suffix  = module.load_balancer.alb_arn_suffix
  asg_name        = module.compute.asg_name
  rds_instance_id = module.database.rds_instance_id

  # CloudWatch Configuration
  enable_alarms      = true
  enable_dashboard   = true
  enable_rds_alarm   = true
  log_retention_days = var.cloudwatch_log_retention_days
  kms_key_arn        = module.security.kms_observability_key_arn

  # SNS notifications for CloudWatch alarms
  alarm_notification_email = var.alarm_notification_email

  tags = var.common_tags
}
