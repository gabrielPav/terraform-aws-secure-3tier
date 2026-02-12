#!/bin/bash
set -euo pipefail

# 1. Install Apache, PHP, and MySQL
dnf install -y httpd php8.3 php8.3-mysqlnd

# 2. Get metadata for AWS region
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
AWS_REGION=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)

# 3. Create the app configuration file
cat > /etc/app-config.php <<EOF
<?php
return [
    'db_host'       => '${rds_endpoint}',
    'db_port'       => '${rds_port}',
    'db_name'       => '${db_name}',
    'db_secret_arn' => '${db_secret_arn}',
    'aws_region'    => '$AWS_REGION',
];
EOF
chown root:apache /etc/app-config.php
chmod 0640 /etc/app-config.php

# 4. Create index.php 
cat > /var/www/html/index.php <<'PHPEOF'
<?php
$config = require '/etc/app-config.php';

// Fetch credentials via AWS CLI
$command = sprintf("aws secretsmanager get-secret-value --secret-id %s --region %s --query SecretString --output text",escapeshellarg($config['db_secret_arn']),escapeshellarg($config['aws_region']));

$secret_json = shell_exec($command);
$credentials = json_decode($secret_json, true);

$db_connected = false;
$db_error = '';
$secrets_ok = !empty($credentials);

if ($secrets_ok) {
    mysqli_report(MYSQLI_REPORT_OFF);
    $conn = mysqli_init();
    // Connect using the fetched credentials and SSH flag
    $status = @$conn->real_connect(
        $config['db_host'], 
        $credentials['username'], 
        $credentials['password'], 
        $config['db_name'], 
        (int)$config['db_port'],
        NULL,
        MYSQLI_CLIENT_SSL
    );
    if (!$status) {
        $db_error = mysqli_connect_error();
    } else {
        $db_connected = true;
        $conn->close();
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>AWS 3-Tier Architecture Status</title>
    <style>
        body { font-family: system-ui, -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: linear-gradient(135deg, #232f3e 0%, #1a242f 100%); }
        .card { padding: 40px 50px; background: #fff; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); text-align: center; max-width: 500px; }
        h1 { color: #232f3e; margin: 0 0 8px 0; font-size: 24px; }
        .subtitle { color: #666; margin-bottom: 30px; font-size: 14px; }
        .checks { text-align: left; }
        .check-item { display: flex; align-items: center; padding: 12px 0; border-bottom: 1px solid #eee; }
        .check-item:last-child { border-bottom: none; }
        .icon { width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 14px; font-size: 16px; flex-shrink: 0; }
        .icon.ok { background: #d4edda; color: #155724; }
        .icon.fail { background: #f8d7da; color: #721c24; }
        .label { font-size: 15px; color: #333; }
        .desc { font-size: 12px; color: #888; margin-top: 2px; }
        .footer { margin-top: 24px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #999; }
    </style>
</head>
<body>
    <div class="card">
        <h1>AWS 3-Tier Architecture</h1>
        <p class="subtitle">Secure infrastructure deployment status</p>
        <div class="checks">
            <div class="check-item">
                <div class="icon ok">&#10003;</div>
                <div>
                    <div class="label">Application Layer (EC2)</div>
                    <div class="desc">Web servers running in private subnets</div>
                </div>
            </div>
            <div class="check-item">
                <div class="icon ok">&#10003;</div>
                <div>
                    <div class="label">Load Balancer (ALB)</div>
                    <div class="desc">Traffic routed through Application Load Balancer</div>
                </div>
            </div>
            <div class="check-item">
                <div class="icon <?= $secrets_ok ? 'ok' : 'fail' ?>"><?= $secrets_ok ? '&#10003;' : '&#10007;' ?></div>
                <div>
                    <div class="label">Secrets Manager Access</div>
                    <div class="desc">Database credentials retrieved securely</div>
                </div>
            </div>
            <div class="check-item">
                <div class="icon <?= $db_connected ? 'ok' : 'fail' ?>"><?= $db_connected ? '&#10003;' : '&#10007;' ?></div>
                <div>
                    <div class="label">Database Layer (RDS)</div>
                    <div class="desc"><?= $db_connected ? 'EC2 to RDS connectivity verified' : htmlspecialchars($db_error ?: 'Connection failed') ?></div>
                </div>
            </div>
        </div>
        <div class="footer">Deployed with Terraform on AWS</div>
    </div>
</body>
</html>
PHPEOF

# 5. Set permissions
chown apache:apache /var/www/html/index.php
chmod 0644 /var/www/html/index.php

# 6. Allow Apache to network out
setsebool -P httpd_can_network_connect 1 || true

# 7. Start and enable
systemctl enable --now httpd
