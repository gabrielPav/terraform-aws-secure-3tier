# Terraform AWS Secure 3-Tier Infrastructure

![AWS Badge](https://img.shields.io/badge/AWS-Deployed-4EAA25.svg?style=flat&logo=amazon-aws&logoColor=white)
![Terraform Badge](https://img.shields.io/badge/Terraform-IaC-5c4ee5.svg?style=flat&logo=terraform&logoColor=white)
![Bash Badge](https://img.shields.io/badge/Bash-Script-232F3E.svg?style=flat&logo=gnu-bash&logoColor=white)

A secure, production-ready 3-tier AWS infrastructure deployed with Terraform. While many projects implement a standard AWS 3-tier architecture, this one is designed with security and compliance as first-class concerns from the start. It provisions a complete web application stack including networking, compute, database, load balancing, CDN, and monitoring - all built using best-practice guardrails, least-privilege access, encryption, and auditable configurations to support real-world deployments.

## Features

- **Networking**: VPC with public/private subnets across multiple AZs, NAT gateways, VPC endpoints.
- **Compute**: Auto Scaling Group with Launch Templates, EC2 instances with IMDSv2, encrypted EBS volumes.
- **Storage**: S3 buckets for assets and logs with versioning, encryption, and lifecycle policies.
- **Database**: RDS with Multi-AZ support, encryption at rest, automated backups.
- **Load Balancing**: Application Load Balancer with HTTP/HTTPS support.
- **SSL/TLS**: Automatic ACM certificate provisioning with DNS validation.
- **CDN**: CloudFront distribution with ALB origin (default) and S3 origin for static assets.
- **Security**: IAM roles, KMS encryption (customer-managed keys), CloudTrail logging, security groups.
- **Instance Access**: EC2 Instance Connect Endpoint for secure SSH access without public IPs.
- **Monitoring**: CloudWatch alarms and dashboards.

## Prerequisites

- [Terraform](https://www.terraform.io/downloads.html) >= 1.3.0.
- [AWS CLI](https://aws.amazon.com/cli/) configured with appropriate credentials.
- An AWS account with sufficient permissions.
- A registered domain name.

## Using Custom Domains

This project is configured to provision an SSL/TLS certificate using AWS Certificate Manager (ACM) with DNS validation (required for HTTPS). You have two options for Route53 DNS configuration:

| Option | Use Case | Certificate Validation Time |
|--------|----------|----------------------------|
| **A: Use Existing Zone** (default) | You already have a Route53 hosted zone | 2-5 minutes |
| **B: Create New Zone** | Starting fresh, no existing zone | Up to 48 hours (DNS propagation) |

Option A: use existing Route53 Zone - is recommended for fast deployment. 
Option B: If you set `create_route53_zone = true`, you must configure your domain registrar to use the Route53 nameservers after the first apply. 

## Using an Existing SSL/TLS Certificate

If you already have an ACM certificate, you can use it instead of creating a new one:

```hcl
# In terraform.tfvars:

alb_certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/abcd-1234-abcd-1234"
```

---

## Quick Start

### Clone the Repository

```bash
git clone https://github.com/gabrielPav/terraform-aws-secure-3tier.git
cd terraform-aws-secure-3tier
```

### Option A: Use Existing Route53 Zone (Recommended - Faster)

Use this option if you already have a Route53 hosted zone configured for your domain.

#### Step 1: Configure Variables

```hcl
# In terraform.tfvars:

# Your application's domain name
domain_name = "app.example.com"

# Use existing Route53 zone (default)
create_route53_zone = false

# Optional: Customize other settings
project_name = "web-app"
environment  = "production"
aws_region   = "us-east-1"
```

#### Step 2: Initialize and Apply

```bash
terraform init
terraform plan
terraform apply
```

Terraform will:
1. Look up your existing Route53 hosted zone
2. Request an ACM certificate for your domain
3. Create DNS validation records in your existing zone
4. Wait for certificate validation (2-5 minutes)
5. Create HTTPS listener on ALB
6. Create A record pointing your domain to the ALB

**That's it!** No manual steps required. Certificate validates automatically.

---

### Option B: Create New Route53 Zone (Slower)

Use this option if you don't have an existing Route53 hosted zone.

#### Step 1: Configure Variables

```hcl
# In terraform.tfvars

# Your application's domain name
domain_name = "app.example.com"

# Create a new Route53 hosted zone
create_route53_zone = true

# Optional: Customize other settings
project_name = "web-app"
environment  = "production"
aws_region   = "us-east-1"
```

#### Step 2: Initialize and Apply

```bash
terraform init
terraform plan
terraform apply
```

Terraform will create:
1. A new Route53 hosted zone for your root domain (e.g., `app.example.com`)
2. An ACM certificate request for your domain
3. DNS validation records for the certificate
4. An HTTPS listener on the ALB (port 443)
5. An A record pointing your domain to the ALB

After apply completes, note the `route53_name_servers` output:

```
Outputs:

alb_dns_name         = "web-app-production-alb-1234abcd.us-east-1.elb.amazonaws.com"
https_endpoint_url   = "https://app.example.com"
route53_zone_created = true
route53_name_servers = [
  "ns-123.awsdns-45.com",
  "ns-678.awsdns-90.net",
  "ns-111.awsdns-22.org",
  "ns-333.awsdns-44.co.uk",
]
```

#### Step 3: Update Your Domain Registrar's Nameservers

This is a **one-time manual step** that Terraform can't automate. You need to configure your domain registrar to use the Route53 nameservers.

### Step 4: Wait for DNS Propagation

After updating the nameservers:

- **DNS propagation** typically takes 15 minutes to 48 hours
- **Certificate validation** completes automatically once DNS propagates (usually 2-5 minutes after propagation)

You can check propagation status using:

```bash
# Check if nameservers are updated
dig NS example.com

# Check if your domain resolves to the ALB
dig app.example.com
```

---

### Connect to EC2 Instances

EC2 instances are deployed in private subnets without public IP addresses. This project uses **EC2 Instance Connect Endpoint (EICE)** to provide secure SSH access without requiring a bastion host, complex SSM configs, or VPN. No SSH port (22) is exposed to the Internet, SSH access is only allowed from the EIC Endpoint's security group, all connections are authenticated via IAM, connection logs are recorded in CloudTrail.

You can also disable the EIC Endpoint if you don't need SSH access to instances:

```hcl
# In terraform.tfvars:

enable_eic_endpoint = false
```

### Destroy Infrastructure

```bash
terraform destroy
```

---

## Input Variables

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `domain_name` | FQDN for HTTPS endpoint (e.g., `app.example.com`) | `string` | `""` | No |
| `create_route53_zone` | Create new Route53 zone (`true`) or use existing (`false`) | `bool` | `false` | No |
| `alb_certificate_arn` | ARN of existing ACM certificate | `string` | `""` | No |
| `redirect_http_to_https` | Redirect HTTP to HTTPS when enabled | `bool` | `true` | No |
| `enable_eic_endpoint` | Enable EC2 Instance Connect Endpoint for SSH access | `bool` | `true` | No |
| `project_name` | Name of the project | `string` | `"web-app"` | No |
| `environment` | Environment (dev/staging/production) | `string` | `"production"` | No |
| `aws_region` | AWS region for resources | `string` | `"us-east-1"` | No |

See `variables.tf` for the complete list of available variables.

## Outputs

| Name | Description |
|------|-------------|
| `alb_dns_name` | The DNS name of the Application Load Balancer |
| `https_endpoint_url` | The HTTPS URL for your application |
| `http_endpoint_url` | The HTTP URL (redirects to HTTPS if enabled) |
| `route53_zone_created` | Whether a new Route53 zone was created |
| `route53_name_servers` | Nameservers to configure (only if zone was created) |
| `acm_certificate_arn` | ARN of the SSL certificate |
| `cloudfront_domain_name` | CloudFront distribution domain |
| `eic_endpoint_id` | EC2 Instance Connect Endpoint ID for SSH access |

## Implemented Security Best Practices

### Encryption

- All data encrypted at rest using customer-managed KMS keys
- KMS key rotation enabled (automatic annual rotation)
- EBS volumes encrypted with KMS
- RDS storage encryption enabled
- S3 server-side encryption (SSE-KMS)
- CloudTrail logs encrypted with KMS
- CloudWatch Logs encrypted with KMS

### Network Security

- EC2 instances deployed in private subnets with no public IPs
- RDS not publicly accessible, isolated in private subnets
- VPC Flow Logs enabled for network traffic auditing
- Security groups follow least-privilege principle
- Default VPC security group restricts all traffic
- VPC Gateway Endpoints for S3 and DynamoDB (traffic stays in AWS)
- VPC Interface Endpoints for private AWS service access
- NAT Gateway for secure outbound-only internet access

### Identity & Access Management

- Least-privilege IAM policies throughout all resources
- IAM roles scoped to specific resources and actions
- EC2 instance profile with minimal permissions
- Secrets Manager integration for RDS credentials (no hardcoded passwords)
- EC2 Instance Connect Endpoint for SSH (IAM-authenticated, no bastion host)

### Instance Hardening

- IMDSv2 required on all EC2 instances (SSRF protection)
- Metadata hop limit restricted to 2
- Only verified Amazon Linux 2 AMIs used
- Termination protection enabled in production

### Transport Security

- HTTPS enforced with TLS 1.2 minimum
- HTTP automatically redirected to HTTPS
- ACM certificates with DNS validation
- CloudFront origin connections use HTTPS-only
- RDS connections require SSL/TLS encryption
- ALB drops invalid header fields

### S3 Security

- Public access blocked on all buckets
- Bucket versioning enabled
- Access logging enabled
- Lifecycle policies for log retention and archival
- Multipart upload auto-abort for incomplete uploads

### Logging & Auditing

- CloudTrail enabled (multi-region, all events)
- CloudTrail log file validation enabled
- CloudTrail log retention (1+ year) for compliance (SOC2, PCI-DSS, HIPAA)
- S3 access logging for all buckets
- ALB access logs enabled
- VPC Flow Logs to CloudWatch

### Database Security

- Multi-AZ deployment for high availability
- Automated backups with configurable retention
- Auto minor version upgrade for automatic security patches
- Deletion protection enabled in production
- Access restricted to EC2 security group only

### Application Protection

- AWS WAF with OWASP managed rules (optional)
- CloudFront Origin Access Control for S3
- CloudFront geo-restriction for regional access control
- CloudFront security headers policy (HSTS, X-Frame-Options, Content-Security-Policy)
- Cross-zone load balancing enabled

### Monitoring & Alerting

- CloudWatch alarms for CPU, errors, and performance
- CloudWatch dashboard for infrastructure visibility
- Log retention policies enforced

## License

This project is licensed under the MIT License.
