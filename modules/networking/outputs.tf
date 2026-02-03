output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "VPC CIDR block"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "internet_gateway_id" {
  description = "Internet Gateway ID"
  value       = aws_internet_gateway.main.id
}

output "nat_gateway_ids" {
  description = "NAT Gateway IDs"
  value       = aws_nat_gateway.main[*].id
}

output "eic_endpoint_security_group_id" {
  description = "EC2 Instance Connect Endpoint security group ID"
  value       = var.enable_eic_endpoint ? aws_security_group.eic_endpoint[0].id : null
}

output "eic_endpoint_id" {
  description = "EC2 Instance Connect Endpoint ID"
  value       = var.enable_eic_endpoint ? aws_ec2_instance_connect_endpoint.main[0].id : null
}
