#!/bin/bash
# ============================================================
#  InfiniteX WAF — EC2 Ubuntu Bootstrap Script
#  Run as: bash scripts/ec2-bootstrap.sh
#  Or remotely: bash <(curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/YOUR_REPO/main/scripts/ec2-bootstrap.sh)
# ============================================================
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
step() { echo -e "\n${GREEN}━━━ $1 ━━━${NC}"; }

# ── Config — edit these before running ───────────────────────
REPO_URL="${REPO_URL:-https://github.com/Dip0375/infinitexwaf.git}"
BRANCH="${BRANCH:-main}"
APP_DIR="/opt/infinitex"
APP_USER="infinitex"
ENV_DIR="/etc/infinitex"
LOG_DIR="/var/log/infinitex"
BACKEND_URL="${BACKEND_URL:-http://localhost:8080}"
WAF_PORT="${WAF_PORT:-3000}"
NODE_VERSION="20"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║     🛡️  InfiniteX WAF — EC2 Bootstrap Installer       ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── 1. System update ─────────────────────────────────────────
step "System update"
sudo apt-get update -qq
sudo apt-get upgrade -y -qq
sudo apt-get install -y -qq \
    curl wget git unzip build-essential \
    nginx certbot python3-certbot-nginx \
    ufw fail2ban
ok "System packages installed"

# ── 2. Node.js 20 via NodeSource ─────────────────────────────
step "Node.js $NODE_VERSION"
if ! command -v node &>/dev/null || [[ "$(node -v)" != v${NODE_VERSION}* ]]; then
    curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | sudo -E bash -s --
    sudo apt-get update -qq
    sudo apt-get install -y -qq nodejs
fi
ok "Node $(node -v) / npm $(npm -v)"

# ── 3. PM2 ───────────────────────────────────────────────────
step "PM2 process manager"
sudo npm install -g pm2 --quiet
ok "PM2 $(pm2 -v)"

# ── 4. App user & directories ────────────────────────────────
step "App user and directories"
if ! id "$APP_USER" &>/dev/null; then
    sudo useradd --system --shell /bin/bash --home "$APP_DIR" "$APP_USER"
fi
sudo mkdir -p "$APP_DIR" "$ENV_DIR" "$LOG_DIR"
sudo chown -R "$APP_USER":"$APP_USER" "$APP_DIR" "$LOG_DIR"
sudo chmod 750 "$ENV_DIR"
ok "User '$APP_USER' and directories ready"

# ── 5. Clone / update repo ───────────────────────────────────
step "Clone repository"
if [ -d "$APP_DIR/.git" ]; then
    warn "Repo already exists — pulling latest"
    sudo -u "$APP_USER" git -C "$APP_DIR" fetch origin
    sudo -u "$APP_USER" git -C "$APP_DIR" reset --hard "origin/$BRANCH"
else
    sudo -u "$APP_USER" git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
fi
ok "Repository at $APP_DIR"

# ── 6. Install dependencies & build WAF ──────────────────────
step "Build WAF backend"
sudo -u "$APP_USER" bash -c "
    cd $APP_DIR
    npm ci --prefer-offline --quiet
    npm run build
"
ok "WAF backend built"

# ── 7. Build dashboard ───────────────────────────────────────
step "Build dashboard UI"
sudo -u "$APP_USER" bash -c "
    cd $APP_DIR/dashboard
    npm ci --prefer-offline
    npm run build
"
ok "Dashboard built → $APP_DIR/dashboard/dist"

# ── 8. Environment file ──────────────────────────────────────
step "Environment configuration"
ENV_FILE="$ENV_DIR/infinitex.env"
if [ ! -f "$ENV_FILE" ]; then
    sudo tee "$ENV_FILE" > /dev/null <<EOF
NODE_ENV=production
INFINITEX_PORT=$WAF_PORT
BACKEND_URL=$BACKEND_URL
INFINITEX_CONFIG=$ENV_DIR/infinitex-config.json
LOG_DIR=$LOG_DIR
EOF
    sudo chmod 640 "$ENV_FILE"
    sudo chown root:"$APP_USER" "$ENV_FILE"
    ok "Created $ENV_FILE"
else
    warn "$ENV_FILE already exists — skipping (edit manually if needed)"
fi

# ── 9. WAF config file ───────────────────────────────────────
WAF_CONFIG="$ENV_DIR/infinitex-config.json"
if [ ! -f "$WAF_CONFIG" ]; then
    sudo cp "$APP_DIR/waf-config-advanced.json" "$WAF_CONFIG" 2>/dev/null || \
    sudo cp "$APP_DIR/waf-config.json" "$WAF_CONFIG"
    sudo chown root:"$APP_USER" "$WAF_CONFIG"
    sudo chmod 640 "$WAF_CONFIG"
    ok "WAF config copied to $WAF_CONFIG"
fi

# ── 10. PM2 ecosystem file ───────────────────────────────────
step "PM2 ecosystem"
sudo -u "$APP_USER" tee "$APP_DIR/ecosystem.config.js" > /dev/null <<EOF
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
    restart_delay: 3000,
    watch: false,
  }],
};
EOF
ok "PM2 ecosystem file written"

# ── 11. Start with PM2 ───────────────────────────────────────
step "Start InfiniteX WAF"
sudo -u "$APP_USER" pm2 delete infinitex 2>/dev/null || true
sudo -u "$APP_USER" pm2 start "$APP_DIR/ecosystem.config.js"
sudo -u "$APP_USER" pm2 save

# Register PM2 startup
PM2_STARTUP=$(sudo -u "$APP_USER" pm2 startup systemd -u "$APP_USER" --hp "$APP_DIR" | tail -1)
eval "$PM2_STARTUP" 2>/dev/null || true
ok "InfiniteX WAF started via PM2"

# ── 12. Nginx config ─────────────────────────────────────────
step "Nginx reverse proxy"
sudo tee /etc/nginx/sites-available/infinitex > /dev/null <<'NGINX'
# InfiniteX WAF — Nginx front door
# Listens on 80, proxies to WAF on 3000

map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    listen [::]:80;
    server_name _;          # replace _ with your domain once DNS is set

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Gzip
    gzip on;
    gzip_types text/plain text/css application/json application/javascript;

    # Proxy to InfiniteX WAF
    location / {
        proxy_pass         http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection $connection_upgrade;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
        client_max_body_size 50m;
    }

    # Health check (bypass WAF for load balancer probes)
    location /nginx-health {
        access_log off;
        return 200 "ok\n";
        add_header Content-Type text/plain;
    }
}
NGINX

sudo ln -sf /etc/nginx/sites-available/infinitex /etc/nginx/sites-enabled/infinitex
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
ok "Nginx configured and reloaded"

# ── 13. UFW firewall ─────────────────────────────────────────
step "Firewall (UFW)"
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
# Port 3000 (dashboard) — restrict to your IP in production
# sudo ufw allow from YOUR_IP to any port 3000
sudo ufw --force enable
ok "UFW firewall active"

# ── 14. Fail2ban ─────────────────────────────────────────────
step "Fail2ban"
sudo systemctl enable fail2ban --quiet
sudo systemctl start fail2ban
ok "Fail2ban running"

# ── 15. Health check ─────────────────────────────────────────
step "Health check"
sleep 3
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/health || echo "000")
if [ "$HTTP_STATUS" = "200" ]; then
    ok "WAF is healthy (HTTP $HTTP_STATUS)"
else
    warn "WAF returned HTTP $HTTP_STATUS — check logs: pm2 logs infinitex"
fi

# ── Done ─────────────────────────────────────────────────────
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com 2>/dev/null || echo "<EC2_PUBLIC_IP>")

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║           🛡️  InfiniteX WAF is running!               ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                      ║"
echo "║  Dashboard:  http://$PUBLIC_IP:3000              "
echo "║  WAF entry:  http://$PUBLIC_IP (port 80)         "
echo "║  Health:     http://$PUBLIC_IP/api/health        "
echo "║                                                      ║"
echo "║  Logs:       pm2 logs infinitex                      ║"
echo "║  Status:     pm2 status                              ║"
echo "║  Restart:    pm2 restart infinitex                   ║"
echo "║  Update:     sudo /opt/infinitex/scripts/update.sh   ║"
echo "║                                                      ║"
echo "║  Edit config: sudo nano /etc/infinitex/infinitex.env ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
warn "Next steps:"
echo "  1. Edit BACKEND_URL in /etc/infinitex/infinitex.env"
echo "  2. Point your domain DNS A record to $PUBLIC_IP"
echo "  3. Run: sudo certbot --nginx -d yourdomain.com"
echo "  4. Restrict port 3000 in your EC2 Security Group to your IP"
echo ""
