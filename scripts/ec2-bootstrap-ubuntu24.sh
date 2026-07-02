#!/bin/bash
# ============================================================
#  InfiniteX WAF — EC2 Ubuntu 24 Bootstrap Installer
#  Usage:
#    bash scripts/ec2-bootstrap-ubuntu24.sh
#    or remotely:
#    bash <(curl -fsSL https://raw.githubusercontent.com/Dip0375/infinitexwaf/main/scripts/ec2-bootstrap-ubuntu24.sh)
# ============================================================
set -euo pipefail

# --- Configuration ----------------------------------------------------------
REPO_URL="${REPO_URL:-https://github.com/Dip0375/infinitexwaf.git}"
BRANCH="${BRANCH:-main}"
APP_DIR="${APP_DIR:-/opt/infinitexwaf}"
APP_USER="${APP_USER:-infinitex}"
ENV_DIR="${ENV_DIR:-/etc/infinitex}"
LOG_DIR="${LOG_DIR:-/var/log/infinitex}"
WAF_PORT="${WAF_PORT:-3000}"
BACKEND_URL="${BACKEND_URL:-http://localhost:8080}"
NODE_VERSION="20"

# --- Helpers ---------------------------------------------------------------
print() { echo -e "[INFO] $1"; }
warn() { echo -e "[WARN] $1"; }
err() { echo -e "[ERROR] $1" >&2; exit 1; }

# --- Begin -----------------------------------------------------------------
print "Starting InfiniteX WAF EC2 bootstrap"

print "Updating system packages"
sudo apt-get update -qq
sudo apt-get upgrade -y -qq

print "Installing prerequisites"
sudo apt-get install -y -qq \
  curl wget git nginx certbot python3-certbot-nginx ufw fail2ban \
  build-essential

print "Installing Node.js $NODE_VERSION"
if ! command -v node >/dev/null 2>&1 || [[ "$(node -v)" != v${NODE_VERSION}* ]]; then
  curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | sudo -E bash - -qq
  sudo apt-get install -y -qq nodejs
fi
print "Node version: $(node -v), npm version: $(npm -v)"

print "Installing PM2"
sudo npm install -g pm2 --quiet
print "PM2 version: $(pm2 -v)"

print "Creating application user and directories"
if ! id "$APP_USER" >/dev/null 2>&1; then
  sudo useradd --system --shell /bin/bash --home "$APP_DIR" "$APP_USER"
fi
sudo mkdir -p "$APP_DIR" "$ENV_DIR" "$LOG_DIR"
sudo chown -R "$APP_USER":"$APP_USER" "$APP_DIR" "$LOG_DIR"
sudo chmod 750 "$ENV_DIR"

print "Cloning repository into $APP_DIR"
if [ -d "$APP_DIR/.git" ]; then
  print "Repository already exists, fetching latest"
  sudo -u "$APP_USER" git -C "$APP_DIR" fetch origin --quiet
  sudo -u "$APP_USER" git -C "$APP_DIR" reset --hard "origin/$BRANCH"
else
  sudo -u "$APP_USER" git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
fi

print "Installing backend dependencies and building WAF"
sudo -u "$APP_USER" bash -lc "cd '$APP_DIR' && npm ci --prefer-offline --quiet && npm run build"

print "Installing dashboard dependencies and building UI"
sudo -u "$APP_USER" bash -lc "cd '$APP_DIR/dashboard' && npm ci --prefer-offline --quiet && npm run build"

print "Creating environment configuration"
ENV_FILE="$ENV_DIR/infinitex.env"
sudo tee "$ENV_FILE" >/dev/null <<EOF
NODE_ENV=production
INFINITEX_PORT=$WAF_PORT
BACKEND_URL=$BACKEND_URL
INFINITEX_CONFIG=$ENV_DIR/infinitex-config.json
LOG_DIR=$LOG_DIR
EOF
sudo chmod 640 "$ENV_FILE"
sudo chown root:"$APP_USER" "$ENV_FILE"

print "Copying WAF config"
WAF_CONFIG="$ENV_DIR/infinitex-config.json"
sudo mkdir -p "$ENV_DIR"
sudo cp "$APP_DIR/waf-config-advanced.json" "$WAF_CONFIG" 2>/dev/null || sudo cp "$APP_DIR/waf-config.json" "$WAF_CONFIG"
sudo chown root:"$APP_USER" "$WAF_CONFIG"
sudo chmod 640 "$WAF_CONFIG"

print "Creating PM2 ecosystem configuration"
cat <<'EOF' | sudo tee "$APP_DIR/ecosystem.config.js" >/dev/null
module.exports = {
  apps: [{
    name: 'infinitex',
    script: '$APP_DIR/dist/standalone/infinitex-server.js',
    cwd: '$APP_DIR',
    instances: 1,
    exec_mode: 'fork',
    env_file: '$ENV_DIR/infinitex.env',
    env: {
      NODE_ENV: 'production',
    },
    out_file: '$LOG_DIR/out.log',
    error_file: '$LOG_DIR/error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss',
    max_memory_restart: '512M',
    watch: false,
  }],
};
EOF
sudo chown "$APP_USER":"$APP_USER" "$APP_DIR/ecosystem.config.js"

print "Starting InfiniteX WAF with PM2"
sudo -u "$APP_USER" pm2 delete infinitex 2>/dev/null || true
sudo -u "$APP_USER" pm2 start "$APP_DIR/ecosystem.config.js"
sudo -u "$APP_USER" pm2 save
sudo -u "$APP_USER" pm2 startup systemd -u "$APP_USER" --hp "$APP_DIR" | tail -n 1 | sudo bash

print "Configuring Nginx reverse proxy"
cat <<'EOF' | sudo tee /etc/nginx/sites-available/infinitex >/dev/null
server {
    listen 80;
    listen [::]:80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:$WAF_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
        client_max_body_size 50m;
    }
}
EOF
sudo ln -sf /etc/nginx/sites-available/infinitex /etc/nginx/sites-enabled/infinitex
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx

print "Configuring UFW firewall"
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
# Restrict dashboard port 3000 to your IP if needed
# sudo ufw allow from <YOUR_IP> to any port 3000
sudo ufw --force enable

print "Starting fail2ban"
sudo systemctl enable fail2ban
sudo systemctl restart fail2ban

print "Bootstrap complete"
print "Verify the service: curl http://127.0.0.1:$WAF_PORT/api/health"
print "If you want dashboard access via port 3000, open it only to your IP in UFW and the AWS security group."
print "Note: Nginx uses server_name '_' so you do not need to hardcode EC2 IP in the config. Replace '_' with a domain name if you use one."
