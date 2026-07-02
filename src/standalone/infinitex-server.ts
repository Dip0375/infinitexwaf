/**
 * InfiniteX WAF Server
 * Full-featured WAF with Dashboard, Analytics, and Alerts
 */

import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import path from 'path';
import cors from 'cors';
import { AdvancedWAFEngine, AdvancedWAFResult } from '../core/engine-advanced';
import { AdvancedWAFConfig, DEFAULT_ADVANCED_CONFIG } from '../core/rules-advanced';
import dashboardAPI, { logRequestForDashboard } from '../dashboard/api';
import dashboardRoutes from '../dashboard/routes';
import { getExportLogger } from '../dashboard/export-logger';
import { alertManager } from '../dashboard/alerts';
import * as fs from 'fs';

// Configuration
const CONFIG_PATH = process.env.INFINITEX_CONFIG || './infinitex-config.json';

function loadConfig(): Partial<AdvancedWAFConfig> {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
      console.log(`[InfiniteX] Loaded configuration from ${CONFIG_PATH}`);
      return config;
    }
  } catch (error) {
    console.error(`[InfiniteX] Error loading config: ${error}`);
  }
  return DEFAULT_ADVANCED_CONFIG;
}

// Initialize WAF
const wafEngine = new AdvancedWAFEngine(loadConfig());
const exportLogger = getExportLogger();

// Watch for config changes
if (fs.existsSync(CONFIG_PATH)) {
  fs.watchFile(CONFIG_PATH, () => {
    console.log('[InfiniteX] Configuration changed, reloading...');
    try {
      const newConfig = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
      wafEngine.updateConfig(newConfig);
    } catch (error) {
      console.error('[InfiniteX] Error reloading config:', error);
    }
  });
}

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Dashboard static files
app.use(express.static(path.join(__dirname, '../../dashboard/dist')));

// API Routes
app.use('/api/dashboard', dashboardAPI);
app.use('/api', dashboardRoutes);

// Serve dashboard
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../../dashboard/dist/index.html'));
});

// Health check
app.get('/api/health', (req, res) => {
  const config = wafEngine.getConfig();
  res.json({
    status: 'healthy',
    service: 'InfiniteX WAF',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    features: {
      geoIp: true,
      rateLimit: config.rateLimitEnabled,
      bruteForce: config.bruteForceEnabled,
      botProtection: config.botProtectionEnabled,
      ddos: config.ddosEnabled,
      sqlInjection: config.sqliEnabled,
      xss: config.xssEnabled,
      csrf: config.csrfEnabled,
      alerts: true,
      export: true,
      dashboard: true,
    },
  });
});

// WAF Middleware
app.use(async (req, res, next) => {
  // Skip for internal routes
  if (req.path.startsWith('/api/') || req.path.startsWith('/waf/')) {
    return next();
  }

  // Build WAF request
  const wafRequest = {
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
  const result = await wafEngine.processRequest(wafRequest);

  // Log for dashboard
  logRequestForDashboard(wafRequest, result);

  // Log for export
  exportLogger.log({
    timestamp: new Date().toISOString(),
    clientIp: wafRequest.clientIp,
    method: req.method,
    uri: wafRequest.uri,
    action: result.action,
    allowed: result.allowed,
    ruleId: result.ruleId,
    reasons: result.reasons,
    threatScore: result.threatScore,
    geoCountry: result.geoCountry,
  });

  // Process for alerts
  alertManager.processRequest(wafRequest, result);

  // Log to console
  wafEngine.logRequest(wafRequest, result);

  // Handle result
  if (result.action === 'ALLOW' || result.action === 'LOG') {
    res.setHeader('X-InfiniteX-Verified', 'true');
    res.setHeader('X-InfiniteX-Action', result.action);
    if (result.threatScore) {
      res.setHeader('X-InfiniteX-Threat-Score', String(result.threatScore));
    }
    return next();
  }

  // Return block response
  handleWAFResult(result, res);
});

function handleWAFResult(result: AdvancedWAFResult, res: express.Response): void {
  res.setHeader('X-InfiniteX-Action', result.action);

  switch (result.action) {
    case 'BLOCK':
      res.status(result.statusCode || 403);
      res.json({
        error: 'Access Denied',
        message: result.message,
        action: result.action,
        reasons: result.reasons,
        service: 'InfiniteX WAF',
        timestamp: new Date().toISOString(),
      });
      break;

    case 'RATE_LIMIT':
      res.status(429);
      res.setHeader('Retry-After', '60');
      res.json({
        error: 'Rate Limited',
        message: 'Too many requests',
        retryAfter: 60,
      });
      break;

    case 'CHALLENGE_JS':
      res.status(403);
      res.setHeader('Content-Type', 'text/html');
      res.send(generateChallengePage(result.challengeToken || ''));
      break;

    case 'CAPTCHA':
      res.redirect(`/waf/captcha?token=${result.challengeToken}`);
      break;

    case 'DROP':
      res.destroy();
      break;

    default:
      res.status(403);
      res.json({ error: 'Forbidden' });
  }
}

function generateChallengePage(token: string): string {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>InfiniteX Security Verification</title>
    <style>
      * { margin: 0; padding: 0; box-sizing: border-box; }
      body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 20px;
      }
      .card {
        background: white;
        border-radius: 16px;
        padding: 48px;
        max-width: 440px;
        width: 100%;
        text-align: center;
        box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      }
      .logo {
        width: 64px;
        height: 64px;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 50%;
        margin: 0 auto 24px;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-size: 32px;
      }
      h1 { color: #1a1a1a; font-size: 24px; margin-bottom: 12px; }
      p { color: #666; margin-bottom: 32px; }
      .spinner {
        width: 48px;
        height: 48px;
        border: 4px solid #f3f3f3;
        border-top: 4px solid #667eea;
        border-radius: 50%;
        animation: spin 1s linear infinite;
        margin: 0 auto;
      }
      @keyframes spin { to { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="card">
      <div class="logo">🛡️</div>
      <h1>InfiniteX Security</h1>
      <p>Verifying your browser... Please wait.</p>
      <div class="spinner"></div>
    </div>
    <script>
      // Challenge verification code would go here
      setTimeout(() => {
        window.location.reload();
      }, 3000);
    </script>
</body>
</html>
  `;
}

// Proxy to backend
const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:8080';

const proxyMiddleware = createProxyMiddleware({
  target: BACKEND_URL,
  changeOrigin: true,
  onProxyReq: (proxyReq, req: any) => {
    if (req.body && Object.keys(req.body).length > 0) {
      const bodyData = JSON.stringify(req.body);
      proxyReq.setHeader('Content-Type', 'application/json');
      proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
      proxyReq.write(bodyData);
    }
  },
});

app.use('/', proxyMiddleware);

// Start server
const PORT = process.env.INFINITEX_PORT || 3000;

app.listen(PORT, () => {
  console.log('');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║                                                            ║');
  console.log('║     🛡️  InfiniteX WAF - Advanced Security Platform  🛡️      ║');
  console.log('║                                                            ║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log('║                                                            ║');
  console.log(`║     Dashboard: http://localhost:${PORT}                          ║`);
  console.log(`║     Backend:   ${BACKEND_URL.padEnd(45)} ║`);
  console.log('║     Health:    http://localhost:' + PORT + '/api/health                    ║');
  console.log('║                                                            ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[InfiniteX] Shutting down gracefully...');
  exportLogger.stop();
  alertManager.stopMonitoring();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('[InfiniteX] Shutting down gracefully...');
  exportLogger.stop();
  alertManager.stopMonitoring();
  process.exit(0);
});
