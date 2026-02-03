# ============================================================================
# Compute Module - EC2, Auto Scaling, EBS
# ============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Launch Template
resource "aws_launch_template" "main" {
  name_prefix   = "${var.project_name}-${var.environment}-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = var.instance_type

  vpc_security_group_ids = [aws_security_group.ec2.id]

  iam_instance_profile {
    name = var.iam_instance_profile
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = var.ebs_volume_size
      volume_type           = var.ebs_volume_type
      encrypted             = var.enable_ebs_encryption
      kms_key_id            = var.kms_key_id
      delete_on_termination = true
    }
  }

  ebs_optimized = true

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    efs_file_system_id  = var.efs_file_system_id
    efs_access_point_id = var.efs_access_point_id
    s3_bucket_name      = var.s3_bucket_name
    rds_endpoint        = var.rds_endpoint
    rds_port            = var.rds_port
    db_secret_arn       = var.db_secret_arn
  }))

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
    instance_metadata_tags      = "enabled"
  }

  network_interfaces {
    associate_public_ip_address = false
    delete_on_termination       = true
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

# Security Group
resource "aws_security_group" "ec2" {
  name        = "${var.project_name}-${var.environment}-ec2-sg"
  description = "Security group for EC2 instances"
  vpc_id      = var.vpc_id

  tags = var.tags
}

# Ingress: HTTP from ALB
resource "aws_vpc_security_group_ingress_rule" "ec2_http_from_alb" {
  count = length(var.alb_security_group_ids)

  security_group_id            = aws_security_group.ec2.id
  referenced_security_group_id = var.alb_security_group_ids[count.index]

  from_port   = 80
  to_port     = 80
  ip_protocol = "tcp"
  description = "HTTP from ALB"
}

# Ingress: HTTPS from ALB
resource "aws_vpc_security_group_ingress_rule" "ec2_https_from_alb" {
  count = length(var.alb_security_group_ids)

  security_group_id            = aws_security_group.ec2.id
  referenced_security_group_id = var.alb_security_group_ids[count.index]

  from_port   = 443
  to_port     = 443
  ip_protocol = "tcp"
  description = "HTTPS from ALB"
}


# Egress: Allow HTTP
resource "aws_vpc_security_group_egress_rule" "ec2_http_egress" {
  security_group_id = aws_security_group.ec2.id

  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 80
  to_port     = 80
  ip_protocol = "tcp"
  description = "Allow HTTP for updates and API calls"
}


# Egress: Allow HTTPS
resource "aws_vpc_security_group_egress_rule" "ec2_https_egress" {
  security_group_id = aws_security_group.ec2.id

  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 443
  to_port     = 443
  ip_protocol = "tcp"
  description = "Allow HTTPS for updates and API calls"
}

# Egress: Allow MySQL
resource "aws_vpc_security_group_egress_rule" "ec2_egress_rds" {
  count = length(var.allowed_security_group_id)

  security_group_id = aws_security_group.ec2.id
  referenced_security_group_id = var.allowed_security_group_id[count.index]

  from_port   = 3306
  to_port     = 3306
  ip_protocol = "tcp"
  description = "Allow traffic to RDS (MySQL)"
}

# Auto Scaling Group
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
    version = "$Latest"
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
}

# Target Group
resource "aws_lb_target_group" "main" {
  name     = "${var.project_name}-${var.environment}-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/"
    matcher             = "200"
  }

  tags = var.tags
}

# Auto Scaling Policies
resource "aws_autoscaling_policy" "scale_up" {
  name                   = "${var.project_name}-${var.environment}-scale-up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.main.name
}

resource "aws_autoscaling_policy" "scale_down" {
  name                   = "${var.project_name}-${var.environment}-scale-down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.main.name
}
