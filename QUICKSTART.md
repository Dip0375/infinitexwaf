# Universal WAF - Quick Start Guide

Get your WAF running in 5 minutes!

## Prerequisites

- Node.js 18+ and npm
- Docker (optional)
- AWS CLI configured (for cloud deployment)

## Option 1: Standalone (Fastest)

```bash
# 1. Clone and enter directory
cd /root/waf-core

# 2. Install dependencies
npm install

# 3. Build
npm run build

# 4. Configure
# Edit waf-config-advanced.json to your needs

# 5. Run
export BACKEND_URL=http://localhost:8080
npm run proxy:start:advanced
```

**Access your app:** http://localhost:3000

**Test WAF:**
```bash
# Should be blocked
curl "http://localhost:3000/api?id=1' OR '1'='1"

# Should be allowed
curl "http://localhost:3000/health"
```

## Option 2: Docker

```bash
# Build
docker build -t universal-waf:advanced .

# Run
docker run -d \
  --name waf \
  -p 3000:3000 \
  -e BACKEND_URL=http://host.docker.internal:8080 \
  -v $(pwd)/waf-config-advanced.json:/app/waf-config-advanced.json \
  universal-waf:advanced
```

## Option 3: AWS CloudFront

```bash
# 1. Build
cd waf-core
npm install && npm run build

# 2. Package
cd dist && zip -r ../lambda-edge-advanced.zip lambda-edge/advanced.* && cd ..

# 3. Deploy
cd terraform
terraform init
terraform apply

# 4. Get Lambda ARN
terraform output waf_edge_lambda_arn

# 5. Configure CloudFront to use Lambda@Edge
# AWS Console → CloudFront → Behaviors → Edit → Lambda Function Associations
```

## Configuration Quick Reference

### Block All SQL Injection
```json
{
  "sqliEnabled": true,
  "sqliLevel": "STRICT",
  "sqliAction": "BLOCK"
}
```

### Block Specific Countries
```json
{
  "geoBlacklist": ["CN", "RU", "KP"],
  "anonymousIpAction": "BLOCK"
}
```

### Enable Bot Protection
```json
{
  "botProtectionEnabled": true,
  "botProtectionLevel": "HIGH",
  "botJsChallenge": true,
  "botFingerprint": true
}
```

### Protect Login Page from Brute Force
```json
{
  "bruteForceEnabled": true,
  "bruteForceThreshold": 5,
  "bruteForceWindow": 300,
  "bruteForceEndpoints": ["/login", "/api/auth"]
}
```

## Common Commands

```bash
# Health check
curl http://localhost:3000/waf/health

# View metrics
curl http://localhost:3000/waf/metrics

# Test SQLi protection
curl "http://localhost:3000/api?id=1' OR '1'='1"

# Test XSS protection
curl "http://localhost:3000/search?q=<script>alert(1)</script>"

# Test rate limiting (send 110 requests)
for i in {1..110}; do curl -s -o /dev/null http://localhost:3000/; done

# View logs
docker logs waf
```

## Troubleshooting

### Build Errors
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install
```

### Lambda Too Large
```bash
# Use production dependencies only
npm ci --only=production
npm run build
```

### Configuration Not Loading
```bash
# Check file path
ls -la waf-config-advanced.json

# Validate JSON
node -e "JSON.parse(require('fs').readFileSync('./waf-config-advanced.json'))"
```

## Next Steps

1. **Read the full docs:** [ADVANCED-FEATURES.md](ADVANCED-FEATURES.md)
2. **Customize rules:** Edit `waf-config-advanced.json`
3. **Monitor logs:** Check CloudWatch or stdout
4. **Tune thresholds:** Adjust based on your traffic
5. **Add CAPTCHA keys:** Configure in config for human verification

## Getting Help

- Check [README-ADVANCED.md](README-ADVANCED.md) for detailed docs
- See [FEATURES-SUMMARY.md](FEATURES-SUMMARY.md) for feature list
- Review test files in `src/core/*.test.ts` for examples

## One-Line Deploy

```bash
cd /root/waf-core && npm install && npm run build && export BACKEND_URL=http://localhost:8080 && npm run proxy:start:advanced
```

Done! Your WAF is protecting your application. 🛡️
