# AWS Secure 3-Tier Architecture

Secure, scalable infrastructure via Terraform. Features VPC, ASG, RDS, and CloudFront with built-in security best practices.

Production-ready, multi-AZ AWS cloud infrastructure with a focus on modularity and security-first principles.

## Architecture

- **Networking**: VPC, public/private subnets across 3 AZs, NAT Gateways, VPC Endpoints
- **Compute**: EC2 Auto Scaling Group, Application Load Balancer
- **Database**: RDS MySQL (Multi-AZ), password managed by AWS Secrets Manager
- **Storage**: S3, EFS
- **Security**: KMS encryption, CloudTrail, VPC Flow Logs, IAM least-privilege
- **CDN**: CloudFront distribution with optional WAF

## Prerequisites

- Terraform >= 1.3.0
- AWS CLI configured

```bash
terraform version
aws sts get-caller-identity
```

## Deploy

```bash
# 1. Clone the repo
git clone https://github.com/gabrielPav/terraform-aws-secure-3tier.git
cd terraform-aws-secure-3tier

# 2. Initialize and deploy
terraform init
terraform plan
terraform apply
```

## Default Configuration

┌──────────────────────┬────────────────┐
│       Setting        │ Default Value  │
├──────────────────────┼────────────────┤
│ AWS Region           │ us-east-1      │
├──────────────────────┼────────────────┤
│ Project Name         │ web-app        │
├──────────────────────┼────────────────┤
│ Environment          │ production     │
├──────────────────────┼────────────────┤
│ VPC CIDR             │ 10.0.0.0/16    │
├──────────────────────┼────────────────┤
│ Availability Zones   │ 3              │
├──────────────────────┼────────────────┤
│ EC2 Instance Type    │ t3.medium      │
├──────────────────────┼────────────────┤
│ ASG Min/Max/Desired  │ 2 / 10 / 2     │
├──────────────────────┼────────────────┤
│ EBS Volume Size      │ 50 GB          │
├──────────────────────┼────────────────┤
│ RDS Instance Class   │ db.t3.medium   │
├──────────────────────┼────────────────┤
│ RDS Engine           │ MySQL 8.0      │
├──────────────────────┼────────────────┤
│ RDS Storage          │ 100 GB         │
├──────────────────────┼────────────────┤
│ RDS Backup Retention │ 7 days         │
├──────────────────────┼────────────────┤
│ CloudFront           │ Enabled        │
├──────────────────────┼────────────────┤
│ WAF                  │ Disabled       │
├──────────────────────┼────────────────┤
│ Log Retention        │ 30 days        │
└──────────────────────┴────────────────┘

To customize, create a `terraform.tfvars` file (see `variables.tf` for all options).

## Test

```bash
curl http://$(terraform output -raw alb_dns_name)
```

## Destroy

```bash
terraform destroy
```

## License

MIT
