# InfiniteX WAF — Ubuntu EC2 Deployment Guide

## Architecture

```
Internet → EC2 (InfiniteX WAF :80/:443) → Your Backend App (:8080)
                        ↓
               Dashboard UI (:3000)
```

---

## Step 1 — Launch the EC2 Instance

### Recommended specs
| Field | Value |
|---|---|
| AMI | Ubuntu Server 22.04 LTS (64-bit x86) |
| Instance type | t3.medium (2 vCPU, 4 GB RAM) minimum |
| Storage | 20 GB gp3 |
| Key pair | Create or use existing `.pem` |

### Security Group rules (inbound)
| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 22 | TCP | Your IP only | SSH |
| 80 | TCP | 0.0.0.0/0 | HTTP (WAF entry) |
| 443 | TCP | 0.0.0.0/0 | HTTPS (WAF entry) |
| 3000 | TCP | Your IP only | Dashboard UI |

> Keep port 3000 restricted to your IP — it's the admin dashboard.

---

## Step 2 — SSH into the Instance

```bash
chmod 400 your-key.pem
ssh -i your-key.pem ubuntu@<EC2_PUBLIC_IP>
```

---

## Step 3 — Run the Bootstrap Script

Copy and paste this entire block into your SSH session.
It installs Node.js 20, Nginx, PM2, clones your repo, builds everything, and starts the WAF.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Dip0375/infinitexwaf/main/scripts/ec2-bootstrap.sh)
```

Or run it manually step by step — see **scripts/ec2-bootstrap.sh** in this repo.

---

## Step 4 — Set Environment Variables

```bash
sudo nano /etc/infinitex/infinitex.env
```

Fill in:
```env
NODE_ENV=production
INFINITEX_PORT=3000
BACKEND_URL=http://localhost:8080   # your app's internal address
INFINITEX_CONFIG=/etc/infinitex/infinitex-config.json
```

Restart after changes:
```bash
pm2 restart infinitex
```

---

## Step 5 — Verify

```bash
# WAF health
curl http://localhost:3000/api/health

# Dashboard (from your browser)
http://<EC2_PUBLIC_IP>:3000

# Nginx proxy (port 80 → WAF)
curl http://<EC2_PUBLIC_IP>/api/health
```

---

## Nginx as Front Door (HTTP → WAF)

Nginx listens on 80/443 and forwards to the WAF on port 3000.
The bootstrap script configures this automatically.
Config lives at `/etc/nginx/sites-available/infinitex`.

---

## SSL / HTTPS with Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d yourdomain.com
sudo systemctl reload nginx
```

---

## PM2 Process Management

```bash
pm2 status              # check WAF is running
pm2 logs infinitex      # live logs
pm2 restart infinitex   # restart
pm2 stop infinitex      # stop
pm2 startup             # auto-start on reboot (run the printed command)
pm2 save                # save process list
```

---

## Updating from GitHub

```bash
cd /opt/infinitex
git pull origin main
npm ci
npm run build
cd dashboard && npm ci && npm run build && cd ..
pm2 restart infinitex
```

Or use the included update script:
```bash
sudo /opt/infinitex/scripts/update.sh
```

---

## File Locations

| Path | Purpose |
|---|---|
| `/opt/infinitex` | Application root |
| `/etc/infinitex/infinitex.env` | Environment variables |
| `/etc/infinitex/infinitex-config.json` | WAF rule config |
| `/var/log/infinitex/` | Application logs |
| `/etc/nginx/sites-available/infinitex` | Nginx config |
