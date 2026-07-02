#!/bin/bash
# ============================================================
#  InfiniteX WAF — Update Script
#  Run as: sudo /opt/infinitex/scripts/update.sh
# ============================================================
set -euo pipefail

APP_DIR="/opt/infinitex"
APP_USER="infinitex"
BRANCH="${BRANCH:-main}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
step() { echo -e "\n${GREEN}━━━ $1 ━━━${NC}"; }

step "Pull latest from GitHub"
sudo -u "$APP_USER" git -C "$APP_DIR" fetch origin
sudo -u "$APP_USER" git -C "$APP_DIR" reset --hard "origin/$BRANCH"
ok "Code updated"

step "Install dependencies"
sudo -u "$APP_USER" bash -c "cd $APP_DIR && npm ci --prefer-offline --quiet"
ok "Backend deps installed"

step "Build WAF backend"
sudo -u "$APP_USER" bash -c "cd $APP_DIR && npm run build"
ok "Backend built"

step "Build dashboard"
sudo -u "$APP_USER" bash -c "cd $APP_DIR/dashboard && npm ci --prefer-offline && npm run build"
ok "Dashboard built"

step "Restart WAF"
sudo -u "$APP_USER" pm2 restart infinitex
ok "InfiniteX WAF restarted"

sleep 2
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/health || echo "000")
echo ""
if [ "$STATUS" = "200" ]; then
    ok "Health check passed (HTTP $STATUS)"
else
    echo -e "${YELLOW}[!]${NC} Health check returned HTTP $STATUS — run: pm2 logs infinitex"
fi
echo ""
