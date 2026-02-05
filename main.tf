# ============================================================================
# Production AWS Infrastructure - Main Configuration
# ============================================================================
# This is the root module that orchestrates all infrastructure components
# ============================================================================

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

# ============================================================================
# Data Sources
# ============================================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

# ============================================================================
# Networking Module
# ============================================================================

module "networking" {
  source = "./modules/networking"

  vpc_name                     = "${var.project_name}-${var.environment}-vpc"
  vpc_cidr                     = var.vpc_cidr
  number_of_availability_zones = var.number_of_availability_zones
  enable_nat_gateway           = true
  single_nat_gateway           = var.environment == "production" ? false : true
  enable_flow_logs             = true
  enable_s3_endpoint           = true
  enable_dynamodb_endpoint     = false  # Not used - project uses RDS
  enable_interface_endpoints   = var.enable_vpc_endpoints
  enable_eic_endpoint          = var.enable_eic_endpoint
  kms_key_arn                  = module.security.kms_key_arn
  tags                         = var.common_tags
}

# ============================================================================
# Security Module (IAM, KMS, CloudTrail)
# ============================================================================

module "security" {
  source = "./modules/security"

  project_name             = var.project_name
  environment              = var.environment
  vpc_id                   = module.networking.vpc_id
  s3_bucket_name           = "${var.project_name}-${var.environment}-cloudtrail-logs"
  cloudtrail_name          = "${var.project_name}-${var.environment}-cloudtrail"
  enable_cloudtrail        = true
  enable_cloudwatch        = true
  s3_access_logs_bucket_id = module.storage.s3_access_logs_bucket_id
  enable_s3_access_logging = true
  tags                     = var.common_tags
}

# ============================================================================
# Storage Module (S3)
# ============================================================================

module "storage" {
  source = "./modules/storage"

  project_name       = var.project_name
  environment        = var.environment
  kms_key_id         = module.security.kms_key_id

  # S3 Configuration
  s3_bucket_name       = "${var.project_name}-${var.environment}-assets"
  enable_s3_versioning = true
  enable_s3_encryption = true

  tags = var.common_tags
}

# ============================================================================
# Database Module (RDS)
# ============================================================================

module "database" {
  source = "./modules/database"

  project_name              = var.project_name
  environment               = var.environment
  vpc_id                    = module.networking.vpc_id
  private_subnet_ids        = module.networking.private_subnet_ids
  allowed_security_group_id = module.compute.ec2_security_group_id
  kms_key_id                = module.security.kms_key_id

  # RDS Configuration
  db_instance_class       = var.rds_instance_class
  db_engine               = var.rds_engine
  db_engine_version       = var.rds_engine_version
  db_name                 = var.rds_database_name
  db_username             = var.rds_username
  db_allocated_storage    = var.rds_allocated_storage
  multi_az                = var.environment == "production" ? true : false
  backup_retention_period = var.rds_backup_retention_period
  enable_encryption       = true

  tags = var.common_tags
}

# ============================================================================
# Compute Module (EC2, Auto Scaling, EBS)
# ============================================================================

module "compute" {
  source = "./modules/compute"

  project_name       = var.project_name
  environment        = var.environment
  vpc_id             = module.networking.vpc_id
  public_subnet_ids  = module.networking.public_subnet_ids
  private_subnet_ids = module.networking.private_subnet_ids
  s3_bucket_name     = module.storage.s3_bucket_name
  rds_endpoint       = module.database.rds_address
  rds_port           = module.database.rds_port
  db_name            = var.rds_database_name
  db_secret_arn      = module.database.rds_master_user_secret_arn

  # EC2 Configuration
  instance_type         = var.ec2_instance_type
  min_size              = var.asg_min_size
  max_size              = var.asg_max_size
  desired_capacity      = var.asg_desired_capacity
  enable_ebs_encryption = true
  ebs_volume_size       = var.ebs_volume_size
  ebs_volume_type       = "gp3"
  kms_key_arn           = module.security.kms_key_arn

  # IAM
  iam_instance_profile   = module.security.ec2_instance_profile_name
  alb_security_group_ids = [module.load_balancer.alb_security_group_id]

  # EC2 Instance Connect Endpoint for SSH access
  eic_security_group_id = module.networking.eic_endpoint_security_group_id
  enable_eic_ssh_access = var.enable_eic_endpoint

  # Security group for RDS egress
  allowed_security_group_id = [module.database.rds_security_group_id]

  tags = var.common_tags
}

# ============================================================================
# Load Balancer Module (ALB)
# ============================================================================

module "load_balancer" {
  source = "./modules/load-balancer"

  project_name       = var.project_name
  environment        = var.environment
  vpc_id             = module.networking.vpc_id
  public_subnet_ids  = module.networking.public_subnet_ids
  private_subnet_ids = module.networking.private_subnet_ids
  target_group_arns  = [module.compute.target_group_arn]

  # ALB Configuration
  alb_internal               = false
  enable_access_logs         = true
  s3_access_logs_bucket_id   = module.storage.s3_access_logs_bucket_id
  kms_key_arn                = module.security.kms_key_arn
  enable_deletion_protection = var.environment == "production" ? true : false
  enable_http2               = true
  enable_cross_zone          = true

  # ============================================================================
  # SSL/TLS Configuration
  # ============================================================================
  # HTTPS can be enabled in two ways:
  # 1. Provide domain_name - Creates ACM certificate with DNS validation
  # 2. Provide alb_certificate_arn - Uses existing certificate
  #
  # If both are provided, alb_certificate_arn takes precedence.
  # If neither is provided, only HTTP listener is created.
  #
  # Route53 Zone Options:
  # - create_route53_zone = false (default): Use existing zone, fast validation
  # - create_route53_zone = true: Create new zone, requires nameserver update
  # ============================================================================
  domain_name            = var.domain_name
  certificate_arn        = var.alb_certificate_arn
  redirect_http_to_https = var.redirect_http_to_https
  create_route53_zone    = var.create_route53_zone

  # HTTPS is enabled if either domain_name or certificate_arn is provided
  enable_https = var.domain_name != "" || var.alb_certificate_arn != ""

  tags = var.common_tags
}

# ============================================================================
# CDN Module (CloudFront)
# ============================================================================

module "cdn" {
  source = "./modules/cdn"

  project_name                 = var.project_name
  environment                  = var.environment
  alb_dns_name                 = module.load_balancer.alb_dns_name
  alb_zone_id                  = module.load_balancer.alb_zone_id
  s3_bucket_domain_name        = module.storage.s3_bucket_domain_name
  s3_access_logs_bucket_domain = module.storage.s3_access_logs_bucket_domain

  # CloudFront Configuration
  enable_cloudfront  = var.enable_cloudfront
  price_class        = "PriceClass_All"
  enable_https       = true
  enable_compression = true
  enable_logging     = true

  # WAF (optional)
  enable_waf = var.enable_waf

  # Geo Restriction (optional)
  enable_geo_restriction    = var.enable_geo_restriction
  geo_restriction_type      = var.geo_restriction_type
  geo_restriction_locations = var.geo_restriction_locations

  tags = var.common_tags
}

# ============================================================================
# Monitoring Module (CloudWatch)
# ============================================================================

module "monitoring" {
  source = "./modules/monitoring"

  project_name    = var.project_name
  environment     = var.environment
  vpc_id          = module.networking.vpc_id
  alb_arn         = module.load_balancer.alb_arn
  asg_name        = module.compute.asg_name
  rds_instance_id = module.database.rds_instance_id

  # CloudWatch Configuration
  enable_alarms      = true
  enable_dashboard   = true
  enable_rds_alarm   = true
  log_retention_days = var.cloudwatch_log_retention_days
  kms_key_arn        = module.security.kms_key_arn

  tags = var.common_tags
}
