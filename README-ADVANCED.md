# Universal WAF - Advanced Protection Platform

A comprehensive Web Application Firewall with enterprise-grade security features protecting applications across AWS CloudFront, Application Load Balancers, and standalone deployments.

## 🚀 Features

### Core Protection

| Feature | Description | Action Types |
|---------|-------------|--------------|
| **Geo-IP Restriction** | Block/challenge by country code | BLOCK, CHALLENGE_JS, CAPTCHA |
| **Rate Limiting** | Sliding window with burst detection | RATE_LIMIT, BLOCK, CHALLENGE_JS |
| **IP Whitelist/Blacklist** | CIDR support, reputation-based blocking | ALLOW, BLOCK, CHALLENGE_JS |
| **Brute Force Protection** | Endpoint-specific failed attempt tracking | BLOCK, RATE_LIMIT |
| **HTTP Method Control** | Whitelist/blacklist HTTP methods | BLOCK, LOG |
| **File Upload Protection** | Extension filtering, content scanning | BLOCK, LOG |
| **Anonymous IP Detection** | TOR, VPN, Proxy, Hosting provider detection | BLOCK, CHALLENGE_JS, CAPTCHA |

### OWASP Top 10 Protection

| Threat | Detection Level | Action |
|--------|-----------------|--------|
| SQL Injection | BASIC / MODERATE / STRICT | BLOCK, LOG, CHALLENGE_JS |
| XSS (Cross-Site Scripting) | BASIC / MODERATE / STRICT | BLOCK, LOG |
| Path Traversal | Standard patterns | BLOCK |
| Command Injection | Shell injection patterns | BLOCK |
| NoSQL Injection | MongoDB-specific patterns | BLOCK |
| SSRF | Internal IP/URL patterns | BLOCK |
| CSRF | Token validation | BLOCK |

### Advanced Bot Protection

| Detection Method | Description |
|------------------|-------------|
| User Agent Analysis | Known bot/scanner signatures |
| Browser Fingerprinting | Canvas, WebGL, Audio fingerprinting |
| Behavioral Analysis | Request timing patterns, mouse movements |
| JavaScript Challenges | Client-side verification |
| Headless Detection | Puppeteer, Selenium, Playwright detection |
| Rate Analysis | Requests per minute tracking |

**Protection Levels:**
- `LOW` - Basic detection, minimal false positives
- `MEDIUM` - Balanced protection (recommended)
- `HIGH` - Aggressive bot blocking
- `AGGRESSIVE` - Maximum protection, may challenge legitimate users

### Layer 7 DDoS Protection

| Detection Type | Threshold | Response |
|----------------|-----------|----------|
| Request Rate | Configurable RPS | Challenge/Block |
| Burst Detection | Multiplier-based | Challenge/Block |
| Geo Anomaly | Multiple countries | Challenge/Block |
| UA Anomaly | Multiple user agents | Challenge/Block |
| Behavioral | Pattern analysis | Challenge/Block |

## 📋 Action Types

| Action | Behavior | Use Case |
|--------|----------|----------|
| `ALLOW` | Forward to origin | Whitelisted traffic |
| `BLOCK` | Return 403/400 error | Confirmed threats |
| `LOG` | Log only, allow request | Monitoring mode |
| `RATE_LIMIT` | Return 429 with Retry-After | Rate limiting |
| `CHALLENGE_JS` | JavaScript browser challenge | Suspicious traffic |
| `CAPTCHA` | reCAPTCHA/hCaptcha challenge | Human verification |
| `REDIRECT` | 302 to another URL | Custom handling |
| `DROP` | Close connection | DDoS mitigation |

## 🔧 Configuration

### Full Configuration Example

```json
{
  "_comment": "Universal WAF Advanced Configuration",

  "geoBlacklist": ["CN", "RU", "KP", "IR"],
  "geoWhitelist": [],
  "geoChallenge": [],

  "ipWhitelist": ["10.0.0.0/8", "192.168.0.0/16"],
  "ipBlacklist": [],
  "ipReputationBlock": true,

  "rateLimitEnabled": true,
  "rateLimitRequests": 100,
  "rateLimitWindow": 60,
  "rateLimitBurst": 150,
  "rateLimitAction": "RATE_LIMIT",

  "bruteForceEnabled": true,
  "bruteForceThreshold": 5,
  "bruteForceWindow": 300,
  "bruteForceBlockDuration": 3600,
  "bruteForceEndpoints": ["/login", "/api/auth"],

  "allowedMethods": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
  "blockedMethods": ["TRACE", "TRACK", "CONNECT"],
  "methodAction": "BLOCK",

  "uploadEnabled": true,
  "uploadMaxSize": 10485760,
  "uploadAllowedExtensions": [".jpg", ".png", ".pdf"],
  "uploadBlockedExtensions": [".php", ".asp", ".exe"],
  "uploadScanContent": true,
  "uploadMimeTypeValidation": true,
  "uploadAction": "BLOCK",

  "blockTor": false,
  "blockVpn": false,
  "blockProxy": false,
  "blockHosting": false,
  "anonymousIpAction": "CHALLENGE_JS",

  "botProtectionEnabled": true,
  "botProtectionLevel": "MEDIUM",
  "botJsChallenge": true,
  "botFingerprint": true,
  "botBehavioral": true,
  "botBlockHeadless": false,
  "botRatePerMinute": 60,

  "ddosEnabled": true,
  "ddosRequestThreshold": 1000,
  "ddosBurstMultiplier": 3,
  "ddosBlockDuration": 300,
  "ddosChallengeMode": true,
  "ddosGeoAnomaly": true,
  "ddosUAAnomaly": true,

  "sqliEnabled": true,
  "sqliAction": "BLOCK",
  "sqliLevel": "MODERATE",

  "xssEnabled": true,
  "xssAction": "BLOCK",
  "xssLevel": "MODERATE",

  "csrfEnabled": false,
  "csrfTokenRequired": false,
  "csrfEndpoints": [],

  "logAllRequests": false,
  "logBlockedOnly": true,
  "logFormat": "JSON",
  "logSensitiveData": false,

  "captchaProvider": "RECAPTCHA_V3",
  "challengePassDuration": 3600
}
```

## 🚀 Deployment

### Option 1: AWS CloudFront (Lambda@Edge)

```bash
# Build and package
cd waf-core
npm install
npm run build

# Package for Lambda@Edge
cd dist && zip -r ../lambda-edge-advanced.zip lambda-edge/advanced.* && cd ..

# Deploy with Terraform
cd terraform
terraform init
terraform apply -var="waf_mode=BLOCK" -var="bot_protection_level=MEDIUM"
```

### Option 2: AWS Application Load Balancer

```bash
# Package for ALB Lambda
cd dist && zip -r ../lambda-alb-advanced.zip lambda-alb/advanced.* && cd ..

# Deploy
cd terraform
terraform apply -target=aws_lambda_function.waf_alb
```

### Option 3: Standalone (Docker)

```bash
# Build image
docker build -t universal-waf:advanced .

# Run with custom config
docker run -d \
  --name waf \
  -p 3000:3000 \
  -e BACKEND_URL=http://your-app:8080 \
  -e WAF_CONFIG_PATH=/app/waf-config-advanced.json \
  -v $(pwd)/waf-config-advanced.json:/app/waf-config-advanced.json \
  universal-waf:advanced
```

### Option 4: Kubernetes

```bash
# Apply manifests
kubectl apply -f k8s/

# Verify deployment
kubectl get pods -l app=universal-waf
```

## 🧪 Testing

### Security Testing

```bash
# SQL Injection
curl "http://localhost:3000/api/users?id=1' OR '1'='1"
# → BLOCKED: SQL Injection detected

# XSS Attack
curl "http://localhost:3000/search?q=<script>alert(1)</script>"
# → BLOCKED: XSS detected

# Path Traversal
curl "http://localhost:3000/files/../../../etc/passwd"
# → BLOCKED: Path Traversal detected

# Command Injection
curl -X POST "http://localhost:3000/exec" -d "cmd=cat /etc/passwd"
# → BLOCKED: Command Injection detected

# Malicious Bot
curl -H "User-Agent: sqlmap/1.0" http://localhost:3000/
# → BLOCKED/CHALLENGED: Bot detected

# Rate Limiting
for i in {1..110}; do curl http://localhost:3000/api; done
# → 429: Rate limit exceeded
```

### Challenge Testing

```bash
# Trigger JS challenge
curl -H "X-Forwarded-For: 185.220.101.1" http://localhost:3000/
# → Returns challenge page

# Complete challenge (simulated)
curl -X POST http://localhost:3000/waf/verify-challenge \
  -H "Content-Type: application/json" \
  -d '{"challenge": "eyJ0b2tlbiI6ICJ0ZXN0In0=", "token": "test"}'
```

## 📊 Monitoring

### Health Check

```bash
curl http://localhost:3000/waf/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "mode": "MEDIUM",
  "features": {
    "geoIp": true,
    "rateLimit": true,
    "bruteForce": true,
    "botProtection": true,
    "ddos": true,
    "sqlInjection": true,
    "xss": true,
    "csrf": false
  }
}
```

### Metrics

```bash
curl http://localhost:3000/waf/metrics
```

### CloudWatch Integration

```bash
# View Lambda logs
aws logs tail /aws/lambda/universal-waf-edge-prod --follow

# View metrics
aws cloudwatch get-metric-statistics \
  --namespace WAF \
  --metric-name BlockedRequests \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-15T00:00:00Z \
  --period 3600 \
  --statistics Sum
```

## 📁 Project Structure

```
waf-core/
├── src/
│   ├── core/
│   │   ├── engine-advanced.ts      # Advanced WAF engine
│   │   ├── rules-advanced.ts       # Advanced rules & config
│   │   └── *.test.ts               # Test suites
│   ├── lambda-edge/
│   │   ├── advanced.ts             # CloudFront Lambda@Edge
│   │   └── index.ts                # Basic Lambda@Edge
│   ├── lambda-alb/
│   │   ├── advanced.ts             # ALB Lambda target
│   │   └── index.ts                # Basic ALB Lambda
│   ├── standalone/
│   │   ├── advanced-server.ts      # Full-featured proxy
│   │   └── server.ts               # Basic proxy
│   ├── index.ts                    # Basic exports
│   └── index-advanced.ts           # Advanced exports
├── terraform/
│   ├── main.tf                     # Basic infrastructure
│   ├── advanced.tf                 # Advanced infrastructure
│   └── providers.tf
├── k8s/
│   └── deployment.yaml
├── waf-config.json                 # Basic config
├── waf-config-advanced.json        # Advanced config
├── Dockerfile
├── deploy.sh
└── README.md
```

## 🔒 Security Best Practices

1. **Start in MONITOR mode** - Observe before blocking
2. **Tune thresholds** - Adjust based on your traffic patterns
3. **Use IP whitelisting** - For known good traffic sources
4. **Enable logging** - Monitor for false positives
5. **Regular updates** - Keep threat intelligence current
6. **Test thoroughly** - Validate all protection rules
7. **Use challenges** - For suspicious but not confirmed threats

## 🌍 Code for Humanity

This WAF is free for:
- Non-profit organizations
- Educational institutions
- Open source projects
- Small businesses
- Personal use

Built to protect the internet for everyone.

## License

MIT License - See LICENSE file

## Support

For issues and feature requests, please use GitHub Issues.

For security vulnerabilities, please email security@your-org.com

---

**Version:** 2.0.0
**Status:** Production Ready
**Node.js:** >= 18.0.0
