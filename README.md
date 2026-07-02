# Universal WAF

A Web Application Firewall that protects applications across multiple deployment scenarios:

- **Lambda@Edge** - CloudFront integration
- **ALB Lambda Target** - Application Load Balancer integration  
- **Standalone Proxy** - On-prem and cloud server deployments

## Features

### OWASP Top 10 Protection

- **SQL Injection** - Pattern-based detection for common SQLi attacks
- **XSS (Cross-Site Scripting)** - Script tag and event handler detection
- **Path Traversal** - Directory traversal attempt blocking
- **Command Injection** - Shell command injection prevention
- **NoSQL Injection** - MongoDB and other NoSQL attack detection
- **SSRF** - Server-side request forgery pattern matching

### Additional Features

- **Rate Limiting** - Configurable request throttling per IP
- **IP Blacklist/Whitelist** - CIDR and wildcard support
- **Bot Detection** - Blocks known malicious scanners
- **Custom Rules** - Extensible rule engine
- **Three Operation Modes**:
  - `BLOCK` - Block malicious requests
  - `MONITOR` - Add headers but allow (safe testing)
  - `COUNT` - Log only, allow all

## Quick Start

### Standalone Proxy Mode

```bash
cd waf-core
npm install

# Set your backend URL
export BACKEND_URL=http://your-app:8080
export WAF_PORT=3000

npm run build
npm run proxy:start
```

Your app is now protected at `http://localhost:3000`

### Lambda@Edge (CloudFront)

1. Build the project:
```bash
npm run build
npm run package:lambda
```

2. Upload `lambda-edge.zip` to AWS Lambda
3. Configure as CloudFront viewer request function
4. Set `WAF_CONFIG` environment variable if needed

### ALB Lambda Target

1. Build and package:
```bash
npm run build
npm run package:lambda
```

2. Upload `lambda-alb.zip` to AWS Lambda
3. Configure ALB to use Lambda as target
4. Enable health checks

## Configuration

Create a `waf-config.json` file:

```json
{
  "mode": "BLOCK",
  "rules": ["SQLI-001", "XSS-001", "PT-001"],
  "rateLimit": {
    "enabled": true,
    "windowMs": 60000,
    "maxRequests": 100
  },
  "ipBlacklist": ["192.168.1.100", "10.0.0.0/24"],
  "ipWhitelist": ["127.0.0.1"]
}
```

| Option | Description | Default |
|--------|-------------|---------|
| `mode` | `BLOCK`, `MONITOR`, or `COUNT` | `BLOCK` |
| `rules` | Array of rule IDs to enable | All core rules |
| `rateLimit.enabled` | Enable rate limiting | `true` |
| `rateLimit.maxRequests` | Requests per window | `100` |
| `rateLimit.windowMs` | Time window in ms | `60000` |

## Deployment Examples

### Docker (Standalone)

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY dist ./dist
ENV WAF_PORT=80
ENV BACKEND_URL=http://backend:8080
EXPOSE 80
CMD ["node", "dist/standalone/server.js"]
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-proxy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: waf-proxy
  template:
    metadata:
      labels:
        app: waf-proxy
    spec:
      containers:
      - name: waf
        image: waf-proxy:latest
        ports:
        - containerPort: 3000
        env:
        - name: BACKEND_URL
          value: "http://backend-service:8080"
---
apiVersion: v1
kind: Service
metadata:
  name: waf-proxy
spec:
  selector:
    app: waf-proxy
  ports:
  - port: 80
    targetPort: 3000
```

## Testing

Test the WAF:

```bash
# Should be blocked (SQL Injection)
curl "http://localhost:3000/api/users?id=1' OR '1'='1"

# Should be blocked (XSS)
curl "http://localhost:3000/search?q=<script>alert(1)</script>"

# Should pass
curl "http://localhost:3000/api/users"

# Check health
curl "http://localhost:3000/waf/health"
```

## Architecture

```
                    ┌─────────────────┐
                    │   CloudFront    │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
     ┌──────────────┤  Lambda@Edge    │
     │              │  (WAF Check)    │
     │              └────────┬────────┘
     │                       │
┌────┴─────┐          ┌─────▼─────┐
│   ALB    │◄─────────┤   Origin  │
│ (Lambda) │          │           │
└────┬─────┘          └───────────┘
     │
┌────▼─────┐
│ Standalone│◄── On-prem / Cloud
│  Proxy   │
└──────────┘
```

## License

MIT - Free for commercial and personal use.

Built for humanity. 🌍
