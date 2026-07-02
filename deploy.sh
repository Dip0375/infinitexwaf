#!/bin/bash
# ============================================================
#  InfiniteX WAF — Deploy Script
#
#  TWO ways to use this:
#
#  1. ON THE SERVER (after SSH in + git clone):
#       bash deploy.sh install     ← full install: Node, Nginx, PM2, build, start
#       bash deploy.sh update      ← pull latest code + rebuild + restart
#
#  2. FROM YOUR LOCAL MACHINE (deploy to remote server):
#       bash deploy.sh server      ← rsync + build + restart via SSH
#       bash deploy.sh build       ← build locally only
#       bash deploy.sh docker      ← build Docker image
#       bash deploy.sh k8s         ← kubectl apply
#
#  Interactive menu (no args):
#       bash deploy.sh
# ============================================================
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
step() { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }
info() { echo -e "    $1"; }

# ── Config ────────────────────────────────────────────────────
APP_DIR="${APP_DIR:-$(cd "$(dirname "$0")" && pwd)}"  # defaults to script location
APP_USER="${APP_USER:-$(whoami)}"
ENV_DIR="/etc/infinitex"
LOG_DIR="/var/log/infinitex"
WAF_PORT="${WAF_PORT:-3000}"
BACKEND_URL="${BACKEND_URL:-http://localhost:8080}"
NODE_VERSION="20"

# Remote deploy config (only needed for 'server' option)
SERVER_USER="${SERVER_USER:-ubuntu}"
SERVER_HOST="${SERVER_HOST:-}"
SERVER_KEY="${SERVER_KEY:-~/.ssh/id_rsa}"
DOCKER_TAG="${DOCKER_TAG:-infinitex-waf:latest}"

# ── Banner ────────────────────────────────────────────────────
banner() {
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║     🛡️  InfiniteX WAF — Deploy Script                 ║${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
  echo ""
}

# ═══════════════════════════════════════════════════════════════
#  ON-SERVER FUNCTIONS  (run these after SSH into the server)
# ═══════════════════════════════════════════════════════════════

# ── Install Node.js 20 ────────────────────────────────────────
install_node() {
  step "Node.js $NODE_VERSION"
  if command -v node &>/dev/null && [[ "$(node -v)" == v${NODE_VERSION}* ]]; then
    ok "Node.js $(node -v) already installed"
    return
  fi
  curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | sudo -E bash - -qq
  sudo apt-get install -y -qq nodejs
  ok "Node $(node -v) / npm $(npm -v)"
}

# ── Install system packages ───────────────────────────────────
install_system() {
  step "System packages"
  sudo apt-get update -qq
  sudo apt-get install -y -qq curl wget git unzip build-essential \
    nginx certbot python3-certbot-nginx ufw fail2ban
  ok "nginx, certbot, ufw, fail2ban installed"
}

# ── Install PM2 ───────────────────────────────────────────────
install_pm2() {
  step "PM2 process manager"
  if command -v pm2 &>/dev/null; then
    ok "PM2 $(pm2 -v) already installed"
    return
  fi
  sudo npm install -g pm2 --quiet
  ok "PM2 $(pm2 -v) installed"
}

# ── Create directories & env file ────────────────────────────
setup_env() {
  step "Environment configuration"
  sudo mkdir -p "$ENV_DIR" "$LOG_DIR"
  sudo chown "$APP_USER":"$APP_USER" "$LOG_DIR" 2>/dev/null || true

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
    ok "Created $ENV_FILE"
    warn "Edit BACKEND_URL: sudo nano $ENV_FILE"
  else
    ok "$ENV_FILE already exists — skipping"
  fi

  # WAF rules config
  WAF_CFG="$ENV_DIR/infinitex-config.json"
  if [ ! -f "$WAF_CFG" ]; then
    sudo cp "$APP_DIR/waf-config-advanced.json" "$WAF_CFG" 2>/dev/null || \
    sudo cp "$APP_DIR/waf-config.json" "$WAF_CFG" 2>/dev/null || true
    [ -f "$WAF_CFG" ] && ok "WAF config copied to $WAF_CFG"
  fi
}

# ── Build backend + dashboard ─────────────────────────────────
build_on_server() {
  step "Installing backend dependencies"
  npm ci --prefer-offline --quiet
  ok "Backend deps installed"

  step "Building WAF backend"
  npm run build
  [ -d "$APP_DIR/dist" ] || err "Backend build failed"
  ok "Backend built → dist/"

  step "Installing dashboard dependencies"
  npm ci --prefer-offline --quiet --prefix "$APP_DIR/dashboard"
  ok "Dashboard deps installed"

  step "Building dashboard UI"
  npm run build --prefix "$APP_DIR/dashboard"
  [ -d "$APP_DIR/dashboard/dist" ] || err "Dashboard build failed"
  ok "Dashboard built → dashboard/dist/"
}

# ── Write PM2 ecosystem file ──────────────────────────────────
setup_pm2() {
  step "PM2 ecosystem"
  cat > "$APP_DIR/ecosystem.config.js" <<EOF
module.exports = {
  apps: [{
    name: 'infinitex',
    script: '$APP_DIR/dist/standalone/infinitex-server.js',
    cwd: '$APP_DIR',
    instances: 1,
    exec_mode: 'fork',
    env_file: '$ENV_DIR/infinitex.env',
    env: { NODE_ENV: 'production' },
    out_file: '$LOG_DIR/out.log',
    error_file: '$LOG_DIR/error.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss',
    max_memory_restart: '512M',
    restart_delay: 3000,
    watch: false,
  }],
};
EOF
  ok "ecosystem.config.js written"

  pm2 delete infinitex 2>/dev/null || true
  pm2 start "$APP_DIR/ecosystem.config.js"
  pm2 save

  # Register startup — capture and run the generated command
  STARTUP_CMD=$(pm2 startup 2>&1 | grep "sudo" | tail -1 || true)
  if [ -n "$STARTUP_CMD" ]; then
    eval "$STARTUP_CMD" 2>/dev/null || true
  fi
  ok "InfiniteX WAF started via PM2"
}

# ── Configure Nginx ───────────────────────────────────────────
setup_nginx() {
  step "Nginx reverse proxy (port 80 → WAF :$WAF_PORT)"
  sudo tee /etc/nginx/sites-available/infinitex > /dev/null <<NGINX
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}
server {
    listen 80;
    listen [::]:80;
    server_name _;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    gzip on;
    gzip_types text/plain text/css application/json application/javascript;

    location / {
        proxy_pass         http://127.0.0.1:$WAF_PORT;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade \$http_upgrade;
        proxy_set_header   Connection \$connection_upgrade;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 60s;
        client_max_body_size 50m;
    }

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
  ok "Nginx configured and running"
}

# ── Firewall ──────────────────────────────────────────────────
setup_firewall() {
  step "UFW firewall"
  sudo ufw --force reset -qq
  sudo ufw default deny incoming -qq
  sudo ufw default allow outgoing -qq
  sudo ufw allow ssh -qq
  sudo ufw allow 80/tcp -qq
  sudo ufw allow 443/tcp -qq
  sudo ufw --force enable -qq
  ok "Firewall active (22, 80, 443 open)"
}

# ── Health check ──────────────────────────────────────────────
health_check() {
  step "Health check"
  sleep 3
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$WAF_PORT/api/health 2>/dev/null || echo "000")
  if [ "$STATUS" = "200" ]; then
    ok "WAF is healthy (HTTP $STATUS)"
  else
    warn "WAF returned HTTP $STATUS — run: pm2 logs infinitex"
  fi
}

# ── MAIN: Full install on server ──────────────────────────────
install_on_server() {
  step "Full InfiniteX WAF install"
  info "App directory: $APP_DIR"
  info "Backend URL:   $BACKEND_URL"
  echo ""

  install_system
  install_node
  install_pm2
  setup_env
  build_on_server
  setup_pm2
  setup_nginx
  setup_firewall
  health_check

  PUBLIC_IP=$(curl -s http://checkip.amazonaws.com 2>/dev/null || echo "YOUR_SERVER_IP")

  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║        🛡️  InfiniteX WAF is LIVE!                     ║${NC}"
  echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC}                                                      ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  Dashboard : ${GREEN}http://$PUBLIC_IP${NC}"
  echo -e "${CYAN}║${NC}  Health    : ${GREEN}http://$PUBLIC_IP/api/health${NC}"
  echo -e "${CYAN}║${NC}                                                      ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  pm2 status          — check process                ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  pm2 logs infinitex  — live logs                    ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  pm2 restart infinitex — restart                    ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  bash deploy.sh update — pull & rebuild              ${CYAN}║${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
  echo ""
  warn "Next: edit BACKEND_URL → sudo nano $ENV_DIR/infinitex.env"
  warn "HTTPS: sudo certbot --nginx -d yourdomain.com"
}

# ── MAIN: Update on server (pull + rebuild + restart) ─────────
update_on_server() {
  step "Pulling latest code"
  git -C "$APP_DIR" pull origin "$(git -C "$APP_DIR" branch --show-current)"
  ok "Code updated"

  build_on_server

  step "Restarting WAF"
  pm2 restart infinitex
  ok "WAF restarted"

  health_check
}

# ═══════════════════════════════════════════════════════════════
#  REMOTE FUNCTIONS  (run from your local machine)
# ═══════════════════════════════════════════════════════════════

build_local() {
  step "Local build"
  command -v node >/dev/null 2>&1 || err "Node.js not found"
  npm ci --prefer-offline
  npm run build
  npm ci --prefer-offline --prefix dashboard
  npm run build --prefix dashboard
  ok "Build complete — dist/ and dashboard/dist/ ready"
}

deploy_remote_server() {
  step "Remote server deployment"
  [ -z "$SERVER_HOST" ] && read -rp "  Server IP or hostname: " SERVER_HOST
  [ -z "$SERVER_HOST" ] && err "SERVER_HOST required"

  info "Target: ${SERVER_USER}@${SERVER_HOST}"

  step "Testing SSH"
  ssh -i "$SERVER_KEY" -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
    "${SERVER_USER}@${SERVER_HOST}" "echo ok" >/dev/null 2>&1 \
    && ok "SSH OK" || err "SSH failed — check SERVER_KEY and SERVER_HOST"

  step "Syncing code"
  rsync -az --delete \
    --exclude='.git' --exclude='node_modules' \
    --exclude='dashboard/node_modules' \
    --exclude='dist' --exclude='dashboard/dist' \
    --exclude='*.log' --exclude='.env' \
    --exclude='infinitex-config.json' \
    -e "ssh -i ${SERVER_KEY} -o StrictHostKeyChecking=accept-new" \
    ./ "${SERVER_USER}@${SERVER_HOST}:${APP_DIR}/"
  ok "Code synced"

  step "Building and restarting on server"
  ssh -i "$SERVER_KEY" "${SERVER_USER}@${SERVER_HOST}" \
    "cd ${APP_DIR} && bash deploy.sh update"

  step "Health check"
  sleep 4
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://${SERVER_HOST}/api/health" 2>/dev/null || echo "000")
  [ "$STATUS" = "200" ] \
    && ok "Live at http://${SERVER_HOST}" \
    || warn "HTTP $STATUS — check: ssh ${SERVER_USER}@${SERVER_HOST} 'pm2 logs infinitex'"
}

deploy_docker() {
  command -v docker >/dev/null 2>&1 || err "Docker not installed"
  step "Building Docker image: $DOCKER_TAG"
  docker build -t "$DOCKER_TAG" .
  ok "Image built: $DOCKER_TAG"
  read -rp "  Run container now? [y/N]: " RUN
  if [[ "$RUN" =~ ^[Yy]$ ]]; then
    docker run -d --name infinitex-waf --restart unless-stopped \
      -p 3000:3000 -e BACKEND_URL="${BACKEND_URL}" -e NODE_ENV=production "$DOCKER_TAG"
    ok "Running → http://localhost:3000"
  fi
}

deploy_k8s() {
  command -v kubectl >/dev/null 2>&1 || err "kubectl not installed"
  [ -d "k8s" ] || err "k8s/ directory not found"
  kubectl apply -f k8s/
  kubectl rollout status deployment/infinitex-waf -n infinitex --timeout=120s \
    && ok "Rollout complete" || warn "Check: kubectl get pods -n infinitex"
}

# ── Interactive menu ──────────────────────────────────────────
show_menu() {
  echo ""
  echo -e "  ${CYAN}── On this server ──────────────────────────────────${NC}"
  echo -e "  ${GREEN}1)${NC} Install WAF here   — full setup (Node, Nginx, PM2, build, start)"
  echo -e "  ${GREEN}2)${NC} Update WAF here    — git pull + rebuild + pm2 restart"
  echo ""
  echo -e "  ${CYAN}── From local machine ──────────────────────────────${NC}"
  echo -e "  ${YELLOW}3)${NC} Build locally       — compile backend + dashboard"
  echo -e "  ${YELLOW}4)${NC} Deploy to server    — rsync + SSH build + restart"
  echo -e "  ${YELLOW}5)${NC} Docker              — build image + optional run"
  echo -e "  ${YELLOW}6)${NC} Kubernetes          — kubectl apply k8s/"
  echo ""
  echo -e "  ${RED}7)${NC} Exit"
  echo ""
}

# ── Entry point ───────────────────────────────────────────────
banner

case "${1:-menu}" in
  install) install_on_server    ;;
  update)  update_on_server     ;;
  build)   build_local          ;;
  server)  deploy_remote_server ;;
  docker)  deploy_docker        ;;
  k8s)     deploy_k8s           ;;
  menu|*)
    while true; do
      show_menu
      read -rp "  Choice [1-7]: " CHOICE
      case "$CHOICE" in
        1) install_on_server    ;;
        2) update_on_server     ;;
        3) build_local          ;;
        4) deploy_remote_server ;;
        5) deploy_docker        ;;
        6) deploy_k8s           ;;
        7) ok "Goodbye!"; exit 0 ;;
        *) warn "Invalid choice" ;;
      esac
    done
    ;;
esac
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }
step()  { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }
info()  { echo -e "    $1"; }

# ── Config (override via env vars) ───────────────────────────
SERVER_USER="${SERVER_USER:-ubuntu}"
SERVER_HOST="${SERVER_HOST:-}"          # e.g. 203.0.113.10
SERVER_KEY="${SERVER_KEY:-~/.ssh/id_rsa}"
APP_DIR="${APP_DIR:-/opt/infinitex}"
DOCKER_TAG="${DOCKER_TAG:-infinitex-waf:latest}"

# ── Banner ────────────────────────────────────────────────────
banner() {
  echo ""
  echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║     🛡️  InfiniteX WAF — Deploy Script                 ║${NC}"
  echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
  echo ""
}

# ── Prerequisite checks ───────────────────────────────────────
check_prereqs() {
  step "Checking prerequisites"
  command -v node  >/dev/null 2>&1 && ok "Node.js $(node -v)"  || err "Node.js not found. Install from https://nodejs.org"
  command -v npm   >/dev/null 2>&1 && ok "npm $(npm -v)"       || err "npm not found"
  command -v git   >/dev/null 2>&1 && ok "git $(git --version | cut -d' ' -f3)" || err "git not found"
  command -v docker>/dev/null 2>&1 && ok "Docker $(docker --version | cut -d' ' -f3 | tr -d ',')" || warn "Docker not found (optional)"
  command -v kubectl>/dev/null 2>&1&& ok "kubectl found"       || warn "kubectl not found (optional)"
}

# ── Build WAF backend ─────────────────────────────────────────
build_backend() {
  step "Installing backend dependencies"
  npm ci --prefer-offline
  ok "Backend dependencies installed"

  step "Building WAF backend (TypeScript → dist/)"
  npm run build
  [ -d "dist" ] || err "Build failed — dist/ not found"
  ok "Backend built → dist/"
}

# ── Build dashboard ───────────────────────────────────────────
build_dashboard() {
  step "Installing dashboard dependencies"
  npm ci --prefer-offline --prefix dashboard
  ok "Dashboard dependencies installed"

  step "Building dashboard UI (Vite → dashboard/dist/)"
  npm run build --prefix dashboard
  [ -d "dashboard/dist" ] || err "Dashboard build failed — dashboard/dist/ not found"
  ok "Dashboard built → dashboard/dist/"
}

# ── Full local build ──────────────────────────────────────────
build_all() {
  check_prereqs
  build_backend
  build_dashboard
  echo ""
  ok "Full build complete. Ready to deploy."
  info "Backend entry:  dist/standalone/infinitex-server.js"
  info "Dashboard:      dashboard/dist/"
  info "Start locally:  npm start"
}

# ── Deploy to remote server via SSH ──────────────────────────
deploy_server() {
  step "Server deployment via SSH"

  if [ -z "$SERVER_HOST" ]; then
    read -rp "  Enter server IP or hostname: " SERVER_HOST
  fi
  [ -z "$SERVER_HOST" ] && err "SERVER_HOST is required"

  info "Target: ${SERVER_USER}@${SERVER_HOST}"
  info "App dir: ${APP_DIR}"
  echo ""

  # Test SSH connection
  step "Testing SSH connection"
  ssh -i "$SERVER_KEY" -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
    "${SERVER_USER}@${SERVER_HOST}" "echo ok" >/dev/null 2>&1 \
    && ok "SSH connection successful" \
    || err "Cannot connect to ${SERVER_USER}@${SERVER_HOST} with key ${SERVER_KEY}"

  # Sync code (exclude build artifacts and secrets)
  step "Syncing code to server"
  rsync -az --delete \
    --exclude='.git' \
    --exclude='node_modules' \
    --exclude='dashboard/node_modules' \
    --exclude='dist' \
    --exclude='dashboard/dist' \
    --exclude='*.log' \
    --exclude='.env' \
    --exclude='infinitex-config.json' \
    -e "ssh -i ${SERVER_KEY} -o StrictHostKeyChecking=accept-new" \
    ./ "${SERVER_USER}@${SERVER_HOST}:${APP_DIR}/"
  ok "Code synced to ${APP_DIR}"

  # Run update script on server
  step "Building and restarting on server"
  ssh -i "$SERVER_KEY" "${SERVER_USER}@${SERVER_HOST}" \
    "sudo bash ${APP_DIR}/scripts/update.sh"

  # Health check
  step "Health check"
  sleep 4
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://${SERVER_HOST}/api/health" 2>/dev/null || echo "000")

  if [ "$STATUS" = "200" ]; then
    ok "WAF is live and healthy (HTTP $STATUS)"
    echo ""
    echo -e "  ${CYAN}Dashboard:${NC} http://${SERVER_HOST}"
    echo -e "  ${CYAN}Health:${NC}    http://${SERVER_HOST}/api/health"
  else
    warn "Health check returned HTTP $STATUS"
    info "Check logs: ssh ${SERVER_USER}@${SERVER_HOST} 'pm2 logs infinitex'"
  fi
}

# ── Docker build & run ────────────────────────────────────────
deploy_docker() {
  command -v docker >/dev/null 2>&1 || err "Docker not installed"

  step "Building Docker image: ${DOCKER_TAG}"
  docker build -t "$DOCKER_TAG" .
  ok "Image built: ${DOCKER_TAG}"

  echo ""
  read -rp "  Run container now? [y/N]: " RUN_NOW
  if [[ "$RUN_NOW" =~ ^[Yy]$ ]]; then
    BACKEND="${BACKEND_URL:-http://host.docker.internal:8080}"
    step "Starting container"
    docker run -d \
      --name infinitex-waf \
      --restart unless-stopped \
      -p 3000:3000 \
      -e BACKEND_URL="$BACKEND" \
      -e NODE_ENV=production \
      "$DOCKER_TAG"
    ok "Container started → http://localhost:3000"
    info "Logs: docker logs -f infinitex-waf"
    info "Stop: docker stop infinitex-waf"
  fi
}

# ── Kubernetes deploy ─────────────────────────────────────────
deploy_k8s() {
  command -v kubectl >/dev/null 2>&1 || err "kubectl not installed"
  [ -d "k8s" ] || err "k8s/ directory not found"

  step "Deploying to Kubernetes"
  kubectl apply -f k8s/
  ok "Manifests applied"

  step "Waiting for rollout"
  kubectl rollout status deployment/infinitex-waf -n infinitex --timeout=120s \
    && ok "Rollout complete" \
    || warn "Rollout timed out — check: kubectl get pods -n infinitex"
}

# ── Interactive menu ──────────────────────────────────────────
show_menu() {
  echo ""
  echo "  Select an option:"
  echo ""
  echo -e "  ${CYAN}1)${NC} Build only          — compile backend + dashboard locally"
  echo -e "  ${CYAN}2)${NC} Deploy to server    — rsync + build + restart via SSH"
  echo -e "  ${CYAN}3)${NC} Docker              — build image + optional run"
  echo -e "  ${CYAN}4)${NC} Kubernetes          — kubectl apply k8s/"
  echo -e "  ${CYAN}5)${NC} Exit"
  echo ""
}

# ── Entry point ───────────────────────────────────────────────
banner

case "${1:-menu}" in
  build)   build_all      ;;
  server)  deploy_server  ;;
  docker)  deploy_docker  ;;
  k8s)     deploy_k8s     ;;
  menu|*)
    while true; do
      show_menu
      read -rp "  Choice [1-5]: " CHOICE
      case "$CHOICE" in
        1) build_all     ;;
        2) deploy_server ;;
        3) deploy_docker ;;
        
        4) deploy_k8s    ;;
        5) ok "Goodbye!"; exit 0 ;;
        *) warn "Invalid choice" ;;
      esac
    done
    ;;
esac
