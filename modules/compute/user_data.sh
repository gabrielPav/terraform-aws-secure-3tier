#!/bin/bash

# Exit on error and treat unset variables as an error
set -euo pipefail

# Update
yum update -y

# Install EFS utils and AWS CLI (for Secrets Manager)
yum install -y amazon-efs-utils jq

# Mount EFS
if [ -n "${efs_file_system_id}" ] && [ -n "${efs_access_point_id}" ]; then
  mkdir -p /mnt/efs
  mount -t efs -o tls,accesspoint=${efs_access_point_id} ${efs_file_system_id}:/ /mnt/efs
  echo "${efs_file_system_id}:/ /mnt/efs efs defaults,_netdev,tls,accesspoint=${efs_access_point_id} 0 0" >> /etc/fstab
  # Ensure the web server can access the mount
  chown -R apache:apache /mnt/efs
fi

# Install application dependencies
yum install -y httpd php php-mysqlnd

# ============================================================================
# RDS database credentials are stored in AWS Secrets Manager
# The application should retrieve them at runtime using the AWS SDK
# ============================================================================

# Configure application with secure credential handling
cat > /var/www/html/index.php <<'PHPEOF'
<?php
// Database connection using AWS Secrets Manager
// Credentials are retrieved at runtime. NEVER hardcode passwords

$region = getenv('AWS_REGION') ?: 'us-east-1';
$secret_arn = getenv('DB_SECRET_ARN');
$db_host = getenv('DB_HOST');
$db_port = getenv('DB_PORT') ?: '3306';
$db_name = getenv('DB_NAME') ?: 'appdb';

// In production, use AWS SDK to retrieve credentials from Secrets Manager

echo "Application is configured to connect to: " . htmlspecialchars($db_host) . ":" . htmlspecialchars($db_port);
echo "<br>Database credentials are securely managed by AWS Secrets Manager";
?>
PHPEOF

# Set environment variables for the application (non-sensitive values only)
cat > /etc/httpd/conf.d/env.conf <<EOF
SetEnv DB_HOST "${rds_endpoint}"
SetEnv DB_PORT "${rds_port}"
SetEnv DB_NAME "appdb"
SetEnv DB_SECRET_ARN "${db_secret_arn}"
EOF

# Start services
chown apache:apache /var/www/html/index.php
systemctl enable httpd
systemctl start httpd
