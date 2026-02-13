# Compute — launch template, ASG, target group, scaling policy

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Latest Amazon Linux 2023 (LTS until 2028)
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# Launch template — IMDSv2 enforced, EBS encrypted, no public IP
resource "aws_launch_template" "main" {
  name_prefix   = "${var.project_name}-${var.environment}-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type

  iam_instance_profile {
    name = var.iam_instance_profile
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = var.ebs_volume_size
      volume_type           = var.ebs_volume_type
      encrypted             = true
      kms_key_id            = var.kms_key_arn
      delete_on_termination = true
    }
  }

  ebs_optimized = true

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    s3_bucket_name = var.s3_bucket_name
    rds_endpoint   = var.rds_endpoint
    rds_port       = var.rds_port
    db_name        = var.db_name
    db_secret_arn  = var.db_secret_arn
  }))

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  network_interfaces {
    associate_public_ip_address = false
    delete_on_termination       = true
    security_groups             = [aws_security_group.ec2.id]
  }

  monitoring {
    enabled = var.enable_detailed_monitoring
  }

  placement {
    tenancy = var.instance_tenancy
  }

  disable_api_termination = var.enable_ec2_termination_protection

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      Name = "${var.project_name}-${var.environment}-ec2"
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags = merge(var.tags, {
      Name = "${var.project_name}-${var.environment}-ebs"
    })
  }
}

# EC2 security group
resource "aws_security_group" "ec2" {
  name        = "${var.project_name}-${var.environment}-ec2-sg"
  description = "Security group for EC2 instances"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-ec2-sg"
  })
}

# HTTP from ALB — TLS terminates at the ALB, plain HTTP over the private network
# (re-encryption to targets only needed for PCI-DSS / HIPAA)
resource "aws_vpc_security_group_ingress_rule" "ec2_http_from_alb" {
  count = length(var.alb_security_group_ids)

  security_group_id            = aws_security_group.ec2.id
  referenced_security_group_id = var.alb_security_group_ids[count.index]

  from_port   = 80
  to_port     = 80
  ip_protocol = "tcp"
  description = "HTTP from ALB"
}

# SSH from EIC endpoint
resource "aws_vpc_security_group_ingress_rule" "ec2_ssh_from_eic" {
  count = var.enable_eic_ssh_access ? 1 : 0

  security_group_id            = aws_security_group.ec2.id
  referenced_security_group_id = var.eic_security_group_id

  from_port   = 22
  to_port     = 22
  ip_protocol = "tcp"
  description = "SSH from EC2 Instance Connect Endpoint"
}

# Outbound HTTP (yum updates, APIs)
resource "aws_vpc_security_group_egress_rule" "ec2_http_egress" {
  security_group_id = aws_security_group.ec2.id

  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 80
  to_port     = 80
  ip_protocol = "tcp"
  description = "Allow HTTP for updates and API calls via NAT Gateway"
}


# Outbound HTTPS (AWS APIs, package repos)
resource "aws_vpc_security_group_egress_rule" "ec2_https_egress" {
  security_group_id = aws_security_group.ec2.id

  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 443
  to_port     = 443
  ip_protocol = "tcp"
  description = "Allow HTTPS for updates and API calls via NAT Gateway"
}

# Outbound to RDS
resource "aws_vpc_security_group_egress_rule" "ec2_egress_rds" {
  count = length(var.allowed_security_group_id)

  security_group_id            = aws_security_group.ec2.id
  referenced_security_group_id = var.allowed_security_group_id[count.index]

  from_port   = var.rds_port
  to_port     = var.rds_port
  ip_protocol = "tcp"
  description = "Allow traffic to RDS"
}

# ASG — ELB health checks, rolling instance refresh
resource "aws_autoscaling_group" "main" {
  name                      = "${var.project_name}-${var.environment}-asg"
  vpc_zone_identifier       = var.private_subnet_ids
  target_group_arns         = [aws_lb_target_group.main.arn]
  health_check_type         = "ELB"
  health_check_grace_period = 300
  capacity_rebalance        = true

  min_size         = var.min_size
  max_size         = var.max_size
  desired_capacity = var.desired_capacity

  launch_template {
    id      = aws_launch_template.main.id
    version = aws_launch_template.main.latest_version
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-${var.environment}-asg"
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = var.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
      instance_warmup        = 300
    }
  }

  lifecycle {
    ignore_changes = [desired_capacity]
  }
}

# ALB target group
resource "aws_lb_target_group" "main" {
  name     = "${var.project_name}-${var.environment}-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  # Stateless PHP — 30s is plenty to drain in-flight requests and keeps deploys fast
  deregistration_delay = 30

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = var.health_check_path
    matcher             = "200"
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-tg"
  })
}

# Scale on CPU — target 60%
resource "aws_autoscaling_policy" "target_tracking_cpu" {
  name                   = "${var.project_name}-${var.environment}-target-tracking-cpu"
  autoscaling_group_name = aws_autoscaling_group.main.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 60.0
  }
}
