# Universal WAF - Advanced Features

Comprehensive Web Application Firewall with enterprise-grade protection capabilities.

## Feature Overview

### 1. Geo-IP Restriction Policy

Block or challenge requests based on geographic location.

```json
{
  "geoBlacklist": ["CN", "RU", "KP", "IR"],
  "geoWhitelist": ["US", "GB", "CA"],
  "geoChallenge": ["XX"]  // Require CAPTCHA for these countries
}
```

**Actions:** `BLOCK`, `CHALLENGE_JS`, `CAPTCHA`, `LOG`

### 2. Rate Limiting

Sophisticated rate limiting with burst detection and sliding windows.

```json
{
  "rateLimitEnabled": true,
  "rateLimitRequests": 100,
  "rateLimitWindow": 60,
  "rateLimitBurst": 150,
  "rateLimitAction": "RATE_LIMIT"
}
```

**Actions:** `BLOCK`, `RATE_LIMIT`, `CHALLENGE_JS`, `LOG`

### 3. IP Sets (Whitelist/Blacklist)

Manage IP access with CIDR support.

```json
{
  "ipWhitelist": ["10.0.0.0/8", "192.168.1.0/24", "127.0.0.1"],
  "ipBlacklist": ["192.168.1.100", "10.0.0.50"],
  "ipReputationBlock": true
}
```

**Actions:** `ALLOW`, `BLOCK`, `CHALLENGE_JS`, `LOG`

### 4. Brute Force Attack Prevention

Protect sensitive endpoints from brute force attacks.

```json
{
  "bruteForceEnabled": true,
  "bruteForceThreshold": 5,
  "bruteForceWindow": 300,
  "bruteForceBlockDuration": 3600,
  "bruteForceEndpoints": ["/login", "/admin", "/api/auth"]
}
```

**Actions:** `BLOCK`, `RATE_LIMIT`, `CHALLENGE_JS`

### 5. HTTP Method Control

Restrict allowed HTTP methods.

```json
{
  "allowedMethods": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
  "blockedMethods": ["TRACE", "TRACK", "CONNECT"],
  "methodAction": "BLOCK"
}
```

**Actions:** `BLOCK`, `LOG`

### 6. File Upload Protection

Secure file uploads with extension and content validation.

```json
{
  "uploadEnabled": true,
  "uploadMaxSize": 10485760,
  "uploadAllowedExtensions": [".jpg", ".png", ".pdf"],
  "uploadBlockedExtensions": [".php", ".asp", ".exe"],
  "uploadScanContent": true,
  "uploadMimeTypeValidation": true,
  "uploadAction": "BLOCK"
}
```

**Actions:** `BLOCK`, `LOG`

### 7. Anonymous IP Protection

Block or challenge traffic from anonymization services.

```json
{
  "blockTor": false,
  "blockVpn": false,
  "blockProxy": false,
  "blockHosting": false,
  "anonymousIpAction": "CHALLENGE_JS"
}
```

**Detects:** TOR exit nodes, VPN endpoints, proxies, cloud hosting

**Actions:** `BLOCK`, `CHALLENGE_JS`, `CAPTCHA`, `LOG`

### 8. OWASP Top 10 Protection

Comprehensive protection against web application vulnerabilities.

| Threat | Rule ID | Level |
|--------|---------|-------|
| SQL Injection | SQLI-001 | BASIC/MODERATE/STRICT |
| XSS | XSS-001 | BASIC/MODERATE/STRICT |
| Path Traversal | PT-001 | HIGH |
| Command Injection | CMDI-001 | CRITICAL |
| NoSQL Injection | NOSQLI-001 | CRITICAL |
| SSRF | SSRF-001 | HIGH |
| CSRF | CSRF-001 | MEDIUM |

### 9. Advanced Bot Protection

Multi-layer bot detection with behavioral analysis.

```json
{
  "botProtectionEnabled": true,
  "botProtectionLevel": "MEDIUM",
  "botJsChallenge": true,
  "botFingerprint": true,
  "botBehavioral": true,
  "botBlockHeadless": false,
  "botRatePerMinute": 60
}
```

**Detection Methods:**
- User agent pattern matching
- Browser fingerprinting
- Behavioral analysis (timing patterns)
- JavaScript challenges
- Canvas/WebGL fingerprinting

**Actions:** `BLOCK`, `CHALLENGE_JS`, `RATE_LIMIT`, `LOG`

### 10. Layer 7 DDoS Protection

Application-layer DDoS mitigation with behavioral detection.

```json
{
  "ddosEnabled": true,
  "ddosRequestThreshold": 1000,
  "ddosBurstMultiplier": 3,
  "ddosBlockDuration": 300,
  "ddosChallengeMode": true,
  "ddosGeoAnomaly": true,
  "ddosUAAnomaly": true
}
```

**Detects:**
- High request rates
- Request bursts
- Geographic anomalies
- User agent anomalies
- Behavioral patterns

**Actions:** `BLOCK`, `CHALLENGE_JS`, `RATE_LIMIT`

## Action Types

The WAF supports multiple response actions:

| Action | Description | Status Code |
|--------|-------------|-------------|
| `ALLOW` | Forward request to origin | 200 |
| `BLOCK` | Block request with error | 403/400 |
| `LOG` | Log but allow request | 200 |
| `RATE_LIMIT` | Return rate limit response | 429 |
| `CHALLENGE_JS` | JavaScript challenge page | 403 |
| `CAPTCHA` | CAPTCHA challenge | 403 |
| `REDIRECT` | Redirect to another URL | 302 |
| `DROP` | Drop connection | 444 |

## JavaScript Challenge

The `CHALLENGE_JS` action presents a challenge page that:

1. Collects browser fingerprint data:
   - Screen dimensions
   - Timezone
   - Language settings
   - Canvas/WebGL fingerprint
   - Audio context fingerprint
   - Hardware capabilities

2. Verifies browser capabilities:
   - JavaScript execution
   - DOM manipulation
   - Timing consistency

3. Sets verification cookie on success

4. Redirects to original URL

## Configuration Examples

### High Security Mode

```json
{
  "mode": "BLOCK",
  "geoBlacklist": ["CN", "RU", "KP"],
  "anonymousIpAction": "BLOCK",
  "botProtectionLevel": "AGGRESSIVE",
  "ddosChallengeMode": false,
  "sqliLevel": "STRICT",
  "xssLevel": "STRICT",
  "csrfEnabled": true
}
```

### Monitoring Mode

```json
{
  "mode": "LOG",
  "logAllRequests": true,
  "anonymousIpAction": "LOG",
  "botProtectionLevel": "LOW",
  "ddosChallengeMode": true
}
```

### E-commerce Protection

```json
{
  "bruteForceEndpoints": ["/login", "/checkout", "/account"],
  "rateLimitRequests": 200,
  "uploadEnabled": true,
  "uploadMaxSize": 20971520,
  "botProtectionLevel": "HIGH",
  "ddosRequestThreshold": 500
}
```

## Deployment

### CloudFront (Lambda@Edge)

```bash
npm run build
zip -r lambda-edge-advanced.zip dist/lambda-edge/advanced.js
# Upload to AWS Lambda
```

### ALB Lambda Target

```bash
npm run build
zip -r lambda-alb-advanced.zip dist/lambda-alb/advanced.js
# Upload to AWS Lambda and configure ALB target
```

### Standalone

```bash
npm run build
npm run proxy:start:advanced
```

### Docker

```bash
docker build -t universal-waf:advanced .
docker run -p 3000:3000 \
  -e WAF_CONFIG_PATH=/app/waf-config-advanced.json \
  -e BACKEND_URL=http://backend:8080 \
  universal-waf:advanced
```

## Monitoring

### Health Check

```bash
curl http://localhost:3000/waf/health
```

Response:
```json
{
  "status": "healthy",
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

## Testing

### SQL Injection
```bash
curl "http://localhost:3000/api?id=1' OR '1'='1"
# Expected: BLOCKED - SQL Injection detected
```

### XSS
```bash
curl "http://localhost:3000/search?q=<script>alert(1)</script>"
# Expected: BLOCKED - XSS detected
```

### Bot Detection
```bash
curl -H "User-Agent: sqlmap/1.0" http://localhost:3000/
# Expected: BLOCKED - Malicious bot detected
```

### Rate Limiting
```bash
for i in {1..110}; do curl http://localhost:3000/api; done
# Expected: 429 - Rate limit exceeded
```

## Threat Score

Each request is assigned a threat score (0-100):

| Score | Level | Action |
|-------|-------|--------|
| 0-30 | LOW | ALLOW |
| 31-50 | MEDIUM | LOG/CHALLENGE |
| 51-70 | HIGH | RATE_LIMIT |
| 71-90 | CRITICAL | BLOCK |
| 91-100 | SEVERE | BLOCK + Alert |

## License

MIT - Free for commercial and personal use.

Built for humanity. 🌍
