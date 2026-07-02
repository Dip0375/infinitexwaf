/**
 * Standalone WAF Proxy Server
 * For on-prem and cloud server deployments
 */

import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { WAFRequest } from '../core/rules';
import { WAFEngine, WAFConfig } from '../core/engine';
import * as fs from 'fs';
import * as path from 'path';

// Load configuration
const CONFIG_PATH = process.env.WAF_CONFIG_PATH || './waf-config.json';

function loadConfig(): Partial<WAFConfig> {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
      console.log(`[WAF] Loaded configuration from ${CONFIG_PATH}`);
      return config;
    }
  } catch (error) {
    console.error(`[WAF] Error loading config: ${error}`);
  }
  return {};
}

// Initialize WAF
const wafEngine = new WAFEngine(loadConfig());

// Watch for config changes
if (fs.existsSync(CONFIG_PATH)) {
  fs.watchFile(CONFIG_PATH, () => {
    console.log('[WAF] Configuration changed, reloading...');
    wafEngine.updateConfig(loadConfig());
  });
}

const app = express();

// Parse JSON bodies
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health check endpoint
app.get('/waf/health', (_req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    mode: wafEngine.getConfig().mode,
  });
});

// Metrics endpoint (basic)
app.get('/waf/metrics', (_req, res) => {
  const config = wafEngine.getConfig();
  res.json({
    mode: config.mode,
    rulesEnabled: config.rules.length,
    rateLimitEnabled: config.rateLimit.enabled,
    blacklistedIps: config.ipBlacklist.length,
    whitelistedIps: config.ipWhitelist.length,
  });
});

// WAF middleware
app.use((req, res, next) => {
  // Build WAF request
  const wafRequest: WAFRequest = {
    method: req.method,
    uri: req.path,
    headers: req.headers as Record<string, string | string[]>,
    queryString: req.url.includes('?') ? req.url.split('?')[1] : undefined,
    body: req.body ? JSON.stringify(req.body) : undefined,
    clientIp: (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() ||
              req.socket.remoteAddress ||
              'unknown',
    userAgent: req.headers['user-agent'] as string | undefined,
    timestamp: Date.now(),
  };

  // Process through WAF
  const result = wafEngine.processRequest(wafRequest);

  // Log request
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    clientIp: wafRequest.clientIp,
    method: req.method,
    path: req.path,
    allowed: result.allowed,
    ruleId: result.ruleId,
    severity: result.severity,
  }));

  // Add WAF headers
  res.setHeader('X-WAF-Version', '1.0.0');

  if (!result.allowed) {
    res.status(result.statusCode);
    res.setHeader('X-WAF-Blocked', 'true');
    res.setHeader('X-WAF-Rule', result.ruleId || 'unknown');

    if (result.blockedReason) {
      res.setHeader('X-WAF-Reason', result.blockedReason);
    }

    res.json({
      error: 'Access Denied',
      message: 'Your request has been blocked by the Web Application Firewall',
      ruleId: result.ruleId,
      timestamp: new Date().toISOString(),
    });
    return;
  }

  // Add monitoring headers if in monitor mode
  if (result.blockedReason) {
    res.setHeader('X-WAF-Alert', result.blockedReason);
  }

  res.setHeader('X-WAF-Verified', 'true');
  next();
});

// Backend target configuration
const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:8080';

// Create proxy middleware
const proxyMiddleware = createProxyMiddleware({
  target: BACKEND_URL,
  changeOrigin: true,
  // Don't parse the body - we've already parsed it
  // The proxy will re-serialize it
  onProxyReq: (proxyReq, req: any) => {
    // If body was parsed, write it back
    if (req.body && Object.keys(req.body).length > 0) {
      const bodyData = JSON.stringify(req.body);
      proxyReq.setHeader('Content-Type', 'application/json');
      proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
      proxyReq.write(bodyData);
    }
  },
  onError: (err, _req, res) => {
    console.error('[WAF] Proxy error:', err);
    res.status(502).json({
      error: 'Bad Gateway',
      message: 'Unable to reach backend server',
    });
  },
});

// Use proxy for all other routes
app.use('/', proxyMiddleware);

// Start server
const PORT = process.env.WAF_PORT || 3000;

app.listen(PORT, () => {
  console.log(`[WAF] Server running on port ${PORT}`);
  console.log(`[WAF] Proxying to: ${BACKEND_URL}`);
  console.log(`[WAF] Health check: http://localhost:${PORT}/waf/health`);
  console.log(`[WAF] Metrics: http://localhost:${PORT}/waf/metrics`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[WAF] SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('[WAF] SIGINT received, shutting down gracefully');
  process.exit(0);
});
