# Terraform AWS Secure 3-Tier Infrastructure

A production-ready, secure 3-tier AWS infrastructure deployed with Terraform. While many projects implement a standard AWS 3-tier architecture, this one is designed with security and compliance as first-class concerns from the start. It provisions a complete web application stack including networking, compute, database, load balancing, CDN, and monitoring — all built using best-practice guardrails, least-privilege access, encryption, and auditable configurations to support real-world, enterprise-ready deployments.

## Features

- **Networking**: VPC with public/private subnets across multiple AZs, NAT gateways, VPC endpoints
- **Compute**: Auto Scaling Group with Launch Templates, EC2 instances with IMDSv2, encrypted EBS volumes
- **Storage**: S3 buckets for assets and logs with versioning, encryption, and lifecycle policies
- **Database**: RDS with Multi-AZ support, encryption at rest, automated backups
- **Load Balancing**: Application Load Balancer with HTTP/HTTPS support
- **SSL/TLS**: Automatic ACM certificate provisioning with DNS validation
- **CDN**: CloudFront distribution with S3 origin
- **Security**: IAM roles, KMS encryption (customer-managed keys), CloudTrail logging, security groups
- **Instance Access**: EC2 Instance Connect Endpoint for secure SSH access without public IPs
- **Monitoring**: CloudWatch alarms and dashboards

## Prerequisites

- [Terraform](https://www.terraform.io/downloads.html) >= 1.3.0
- [AWS CLI](https://aws.amazon.com/cli/) configured with appropriate credentials
- An AWS account with sufficient permissions
- A registered domain name

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/gabrielPav/terraform-aws-secure-3tier.git
cd terraform-aws-secure-3tier
```

### 2. Configure Variables

Create a `terraform.tfvars` file:

```hcl
# Required: Your domain name for HTTPS
domain_name = "example.com"

# Optional: Customize other settings
project_name = "web-app"
environment  = "production"
aws_region   = "us-east-1"
```

### 3. Initialize and Apply

```bash
terraform init
terraform plan
terraform apply
```

### 4. Configure DNS (If Creating New Zone)

If you set `create_route53_zone = true`, you must configure your domain registrar to use the Route53 nameservers after the first apply. See [Option B: Create New Route53 Zone](#option-b-create-new-route53-zone-slower-setup) below.

---

## Configuring HTTPS with Custom Domain

This project automatically provisions an SSL/TLS certificate using AWS Certificate Manager (ACM) with DNS validation. You have two options for Route53 configuration:

| Option | Use Case | Certificate Validation Time |
|--------|----------|----------------------------|
| **A: Use Existing Zone** (default) | You already have a Route53 hosted zone | 2-5 minutes |
| **B: Create New Zone** | Starting fresh, no existing zone | Up to 48 hours (DNS propagation) |

---

### Option A: Use Existing Route53 Zone (Recommended - Faster)

Use this option if you already have a Route53 hosted zone configured for your domain.

#### Step 1: Set Variables

```hcl
# terraform.tfvars

# Your application's domain name
domain_name = "app.example.com"

# Use existing Route53 zone (default)
create_route53_zone = false

# Optional: Disable HTTP to HTTPS redirect (enabled by default)
redirect_http_to_https = true
```

#### Step 2: Run Terraform Apply

```bash
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

### Option B: Create New Route53 Zone (Slower Setup)

Use this option if you don't have an existing Route53 hosted zone.

#### Step 1: Set Variables

```hcl
# terraform.tfvars

# Your application's domain name
domain_name = "app.example.com"

# Create a new Route53 hosted zone
create_route53_zone = true

# Optional: Disable HTTP to HTTPS redirect (enabled by default)
redirect_http_to_https = true
```

**Examples of valid domain names:**
- `app.example.com`
- `www.webapp.io`

#### Step 2: Run Terraform Apply

```bash
terraform apply
```

Terraform will create:
1. A new Route53 hosted zone for your root domain (e.g., `example.com`)
2. An ACM certificate request for your domain
3. DNS validation records for the certificate
4. An HTTPS listener on the ALB (port 443)
5. An A record pointing your domain to the ALB

After apply completes, note the `route53_name_servers` output:

```
Outputs:

alb_dns_name         = "my-app-production-alb-123456789.us-east-1.elb.amazonaws.com"
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

This is a **one-time manual step** that Terraform cannot automate. You need to configure your domain registrar to use the AWS Route53 nameservers.

#### General Steps for Any Registrar:

1. Log in to your domain registrar's control panel
2. Find the DNS or Nameserver settings for your domain
3. Replace the existing nameservers with the 4 AWS nameservers from the Terraform output
4. Save the changes

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

### Step 5: Verify HTTPS is Working

Once DNS propagates and the certificate is validated:

```bash
# Test HTTPS endpoint
curl -I https://app.example.com

# You should see:
# HTTP/2 200
# ...
```

You can also check the certificate status in the AWS Console:
1. Go to **AWS Certificate Manager**
2. Find your certificate
3. Status should be **Issued**

---

## Using an Existing Certificate

If you already have an ACM certificate, you can use it instead of creating a new one:

```hcl
# In terraform.tfvars
alb_certificate_arn = "arn:aws:acm:us-east-1:123456789:certificate/abcd-1234-abcd"

# Domain_name is not required when using existing certificate but can still be set for DNS records
```

---

## Connecting to EC2 Instances

EC2 instances are deployed in private subnets without public IP addresses. This project uses **EC2 Instance Connect Endpoint (EIC)** to provide secure SSH access without requiring a bastion host or VPN.

### Prerequisites

- AWS CLI v2.12.0 or later
- Appropriate IAM permissions (`ec2-instance-connect:OpenTunnel`, `ec2:DescribeInstances`)

### Connect via AWS CLI

```bash
# Get an instance ID from the Auto Scaling Group
INSTANCE_ID=$(aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names "web-app-production-asg" \
  --query 'AutoScalingGroups[0].Instances[0].InstanceId' \
  --output text)

# Connect using EC2 Instance Connect Endpoint
aws ec2-instance-connect ssh --instance-id $INSTANCE_ID --connection-type eice
```

### Connect via SSH with EIC Tunnel

You can also use a standard SSH client by opening a tunnel:

```bash
# Open a tunnel (runs in background)
aws ec2-instance-connect open-tunnel \
  --instance-id $INSTANCE_ID \
  --local-port 2222 &

# Connect via SSH
ssh -p 2222 ec2-user@localhost
```

### Security Notes

- No SSH port (22) is exposed to the internet
- SSH access is only allowed from the EIC Endpoint's security group
- All connections are authenticated via IAM
- Connection logs are recorded in CloudTrail

### Disabling EIC Endpoint

If you don't need SSH access to instances, you can disable the EIC Endpoint:

```hcl
# terraform.tfvars
enable_eic_endpoint = false
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

## Troubleshooting

### Certificate Stuck in "Pending Validation"

**Cause**: DNS is not resolving correctly.

**Solution (if `create_route53_zone = true`)**:
1. Verify nameservers are updated at your registrar
2. Check DNS propagation: `dig NS yourdomain.com`
3. Wait up to 48 hours for full propagation

**Solution (if `create_route53_zone = false`)**:
1. Verify the Route53 hosted zone exists for your domain
2. Check that the zone has the correct nameservers configured at your registrar
3. Run `terraform apply` again to retry validation

### "No Hosted Zone Found" Error

**Cause**: Using `create_route53_zone = false` (default) but no hosted zone exists.

**Solution**: Either:
- Create a Route53 hosted zone manually in AWS Console, OR
- Set `create_route53_zone = true` in your `terraform.tfvars`

### HTTPS Not Working After Apply

**Cause**: DNS hasn't propagated yet (only applies if `create_route53_zone = true`).

**Solution**:
1. Check certificate status in ACM console
2. Verify DNS resolution: `dig yourdomain.com`
3. Wait for propagation (can take up to 48 hours)

### Certificate Validates but Domain Doesn't Resolve

**Cause**: Using existing zone but A record wasn't created.

**Solution**:
1. Check Route53 for the A record pointing to ALB
2. Run `terraform apply` to ensure all resources are created

## Security Best Practices

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
- VPC Gateway Endpoints for S3 and DynamoDB (traffic stays in AWS)
- VPC Interface Endpoints for private AWS service access
- NAT Gateway for secure outbound-only internet access

### Identity & Access Management

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
- ALB drops invalid header fields

### S3 Security

- Public access blocked on all buckets
- Bucket versioning enabled
- Access logging enabled
- Lifecycle policies for log retention and archival

### Logging & Auditing

- CloudTrail enabled (multi-region, all events)
- CloudTrail log file validation enabled
- S3 access logging for all buckets
- ALB access logs enabled
- VPC Flow Logs to CloudWatch

### Database Security

- Multi-AZ deployment for high availability
- Automated backups with configurable retention
- Deletion protection in production
- Access restricted to EC2 security group only

### Application Protection

- AWS WAF with OWASP managed rules (optional)
- CloudFront Origin Access Control for S3
- Cross-zone load balancing enabled

### Monitoring & Alerting

- CloudWatch alarms for CPU, errors, and performance
- CloudWatch dashboard for infrastructure visibility
- Log retention policies enforced

## Architecture Notes

- **Storage**: Each EC2 instance uses encrypted EBS volumes for local storage. S3 is used for shared assets and logging. No shared filesystem (EFS) is deployed.
- **Database**: RDS instance with credentials managed by AWS Secrets Manager. The endpoint is accessible only from EC2 instances in private subnets.
- **Scaling**: Auto Scaling Group manages EC2 instances across multiple availability zones for high availability.

## Cost Considerations

This infrastructure includes resources that incur AWS charges:
- EC2 instances (Auto Scaling Group)
- RDS database (Multi-AZ in production)
- NAT Gateways
- Application Load Balancer
- Route53 hosted zone ($0.50/month)
- CloudFront distribution
- KMS keys ($1/month per key)
- Data transfer costs

**Free tier resources:**
- EC2 Instance Connect Endpoint (no hourly charge)
- S3 Gateway Endpoints (S3, DynamoDB)

Use `terraform plan` to review resources before applying.

## License

This project is licensed under the MIT License.
