#!/bin/bash
set -euo pipefail

# Amazon Linux 2023 uses dnf package manager
# Pin PHP version to 8.3 for deterministic builds
# Security patches are applied via AMI updates and instance refresh
dnf install -y httpd php8.3 php8.3-mysqlnd php8.3-xml

# Install AWS SDK for PHP so the app can call AWS APIs natively
# Download the Composer installer and verify its SHA-384 checksum against the official signature before executing it.
EXPECTED_CHECKSUM="$(php -r "copy('https://composer.github.io/installer.sig', 'php://stdout');")"
php -r "copy('https://getcomposer.org/installer', '/tmp/composer-setup.php');"
ACTUAL_CHECKSUM="$(php -r "echo hash_file('SHA384', '/tmp/composer-setup.php');")"
if [ "$EXPECTED_CHECKSUM" != "$ACTUAL_CHECKSUM" ]; then
    echo 'ERROR: Composer installer checksum verification failed' >&2
    rm -f /tmp/composer-setup.php
    exit 1
fi
php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer
rm -f /tmp/composer-setup.php

# Run Composer as the apache user (least privilege) instead of root
mkdir -p /opt/aws-sdk
chown apache:apache /opt/aws-sdk
runuser -u apache -- composer require aws/aws-sdk-php --working-dir=/opt/aws-sdk --no-interaction --no-dev

TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
AWS_REGION=$(curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)

cat > /var/www/html/index.php <<'PHPEOF'
<?php
require '/opt/aws-sdk/vendor/autoload.php';

use Aws\SecretsManager\SecretsManagerClient;

$credentials = null;
try {
    $client = new SecretsManagerClient([
        'region'  => getenv('AWS_REGION'),
        'version' => 'latest',
    ]);
    $result = $client->getSecretValue([
        'SecretId' => getenv('DB_SECRET_ARN'),
    ]);
    $credentials = json_decode($result['SecretString'], true);
} catch (Exception $e) {
    $credentials = null;
}

$db_connected = false;
$db_error = '';
$secrets_ok = !empty($credentials);
if ($secrets_ok) {
    mysqli_report(MYSQLI_REPORT_OFF);
    $conn = mysqli_init();
    $conn->options(MYSQLI_SET_CHARSET_NAME, 'utf8mb4');
    $conn->ssl_set(NULL, NULL, '/etc/pki/tls/certs/ca-bundle.crt', NULL, NULL);
    @$conn->real_connect(getenv('DB_HOST'), $credentials['username'], $credentials['password'], getenv('DB_NAME'), (int)getenv('DB_PORT'), NULL, MYSQLI_CLIENT_SSL);
    if ($conn->connect_error) {
        error_log('DB connection failed: ' . $conn->connect_error);
        $db_error = 'Database connection failed';
    } else {
        $db_connected = true;
        $conn->close();
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>AWS 3-Tier Architecture Demo</title>
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
                    <div class="desc">Web server running in private subnet</div>
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
                    <div class="label">Database Layer (RDS MySQL)</div>
                    <div class="desc"><?= $db_connected ? 'EC2 to RDS connectivity verified' : htmlspecialchars($db_error ?: 'Connection failed') ?></div>
                </div>
            </div>
        </div>
        <div class="footer">Deployed with Terraform on AWS</div>
    </div>
</body>
</html>
PHPEOF

cat > /etc/httpd/conf.d/env.conf <<EOF
SetEnv DB_HOST "${rds_endpoint}"
SetEnv DB_PORT "${rds_port}"
SetEnv DB_NAME "${db_name}"
SetEnv DB_SECRET_ARN "${db_secret_arn}"
SetEnv AWS_REGION "$AWS_REGION"
EOF

chown apache:apache /var/www/html/index.php
systemctl enable httpd
systemctl start httpd
