/**
 * Advanced Standalone WAF Proxy Server
 * Full-featured reverse proxy with comprehensive protection
 */

import express from 'express';
import { createProxyMiddleware, Options } from 'http-proxy-middleware';
import { AdvancedWAFEngine, AdvancedWAFResult } from '../core/engine-advanced';
import { AdvancedWAFConfig, DEFAULT_ADVANCED_CONFIG, WAFAction } from '../core/rules-advanced';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

// Configuration loading
const CONFIG_PATH = process.env.WAF_CONFIG_PATH || './waf-config-advanced.json';

function loadConfig(): Partial<AdvancedWAFConfig> {
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
const wafEngine = new AdvancedWAFEngine(loadConfig());

// Watch for config changes
if (fs.existsSync(CONFIG_PATH)) {
  fs.watchFile(CONFIG_PATH, () => {
    console.log('[WAF] Configuration changed, reloading...');
    try {
      const newConfig = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
      wafEngine.updateConfig(newConfig);
      console.log('[WAF] Configuration reloaded successfully');
    } catch (error) {
      console.error('[WAF] Error reloading config:', error);
    }
  });
}

const app = express();

// Parse bodies
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Health check
app.get('/waf/health', (_req, res) => {
  const config = wafEngine.getConfig();
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    mode: config.botProtectionLevel,
    features: {
      geoIp: true,
      rateLimit: config.rateLimitEnabled,
      bruteForce: config.bruteForceEnabled,
      botProtection: config.botProtectionEnabled,
      ddos: config.ddosEnabled,
      sqlInjection: config.sqliEnabled,
      xss: config.xssEnabled,
      csrf: config.csrfEnabled,
    },
  });
});

// Metrics endpoint
app.get('/waf/metrics', (_req, res) => {
  const config = wafEngine.getConfig();
  res.json({
    timestamp: new Date().toISOString(),
    config: {
      geoBlacklistCount: config.geoBlacklist.length,
      geoWhitelistCount: config.geoWhitelist.length,
      ipBlacklistCount: config.ipBlacklist.length,
      ipWhitelistCount: config.ipWhitelist.length,
      allowedMethods: config.allowedMethods,
      blockedExtensions: config.uploadBlockedExtensions,
    },
    capabilities: [
      'GeoIP Filtering',
      'Rate Limiting',
      'Brute Force Protection',
      'Bot Protection',
      'DDoS Protection',
      'SQL Injection Detection',
      'XSS Protection',
      'CSRF Protection',
      'File Upload Protection',
      'Anonymous IP Detection',
      'Challenge/CAPTCHA',
    ],
  });
});

// Challenge verification endpoint
app.post('/waf/verify-challenge', express.json(), (req, res) => {
  const { challenge, token } = req.body;

  if (!challenge || !token) {
    return res.status(400).json({ error: 'Missing challenge data' });
  }

  try {
    // Decode challenge
    const decoded = JSON.parse(Buffer.from(challenge, 'base64').toString());

    // Verify challenge (in production, verify signature and token)
    const isValid = decoded.token === token &&
                   decoded.timestamp > Date.now() - 60000 && // Within 1 minute
                   decoded.screen &&
                   decoded.timezone;

    if (isValid) {
      // Set verification cookie
      res.cookie('_waf_verified', token, {
        maxAge: 3600000, // 1 hour
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
      });
      res.json({ success: true, message: 'Challenge passed' });
    } else {
      res.status(403).json({ error: 'Challenge failed' });
    }
  } catch (error) {
    console.error('[WAF] Challenge verification error:', error);
    res.status(400).json({ error: 'Invalid challenge data' });
  }
});

// CAPTCHA endpoint (for CAPTCHA action)
app.get('/waf/captcha', (req, res) => {
  const token = req.query.token as string;

  if (!token) {
    return res.status(400).send('Missing token');
  }

  res.send(generateCaptchaPage(token));
});

// WAF middleware
app.use(async (req, res, next) => {
  // Skip WAF for WAF endpoints
  if (req.path.startsWith('/waf/')) {
    return next();
  }

  // Check for existing challenge cookie
  const challengeCookie = req.cookies?._waf_verified;

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

  // Log request
  wafEngine.logRequest(wafRequest, result);

  // Handle WAF result
  if (result.action === 'ALLOW' || result.action === 'LOG') {
    // Add WAF headers
    res.setHeader('X-WAF-Verified', 'true');
    res.setHeader('X-WAF-Action', result.action);
    if (result.threatScore) {
      res.setHeader('X-WAF-Threat-Score', String(result.threatScore));
    }
    if (result.geoCountry) {
      res.setHeader('X-WAF-Country', result.geoCountry);
    }
    return next();
  }

  // Handle blocking actions
  handleWAFResult(result, res);
});

/**
 * Handle WAF result with appropriate response
 */
function handleWAFResult(result: AdvancedWAFResult, res: express.Response): void {
  res.setHeader('X-WAF-Action', result.action);
  res.setHeader('X-WAF-Threat-Score', String(result.threatScore || 0));

  if (result.reasons?.length) {
    res.setHeader('X-WAF-Reasons', result.reasons.join(','));
  }

  if (result.ruleId) {
    res.setHeader('X-WAF-Rule', result.ruleId);
  }

  switch (result.action) {
    case 'BLOCK':
      res.status(result.statusCode || 403);
      res.setHeader('X-WAF-Blocked', 'true');
      res.json({
        error: 'Access Denied',
        message: result.message,
        action: result.action,
        reasons: result.reasons,
        timestamp: new Date().toISOString(),
      });
      break;

    case 'RATE_LIMIT':
      res.status(429);
      res.setHeader('Retry-After', '60');
      res.json({
        error: 'Rate Limited',
        message: 'Too many requests. Please slow down.',
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

    case 'REDIRECT':
      res.redirect('https://example.com/blocked');
      break;

    case 'DROP':
      res.destroy();
      break;

    default:
      res.status(403);
      res.json({ error: 'Forbidden' });
  }
}

/**
 * Generate challenge page
 */
function generateChallengePage(token: string): string {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Verification - WAF</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
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
        .icon {
            width: 64px;
            height: 64px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            margin: 0 auto 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
        }
        h1 {
            color: #1a1a1a;
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 12px;
        }
        p {
            color: #666;
            font-size: 16px;
            line-height: 1.5;
            margin-bottom: 32px;
        }
        .spinner {
            width: 48px;
            height: 48px;
            border: 4px solid #f3f3f3;
            border-top-color: #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .status {
            margin-top: 16px;
            font-size: 14px;
            color: #999;
        }
        .error {
            display: none;
            margin-top: 24px;
            padding: 16px;
            background: #fee;
            border-radius: 8px;
            color: #c33;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">🔒</div>
        <h1>Security Verification</h1>
        <p>We're checking your browser to ensure you're not a bot. This will only take a few seconds.</p>
        <div class="spinner" id="spinner"></div>
        <div class="status" id="status">Verifying...</div>
        <div class="error" id="error">
            <strong>Verification Failed</strong><br>
            Please disable any VPN/proxy and try again.
        </div>
    </div>

    <script>
        (function() {
            const spinner = document.getElementById('spinner');
            const status = document.getElementById('status');
            const error = document.getElementById('error');

            async function runChallenge() {
                try {
                    // Collect browser data
                    const data = {
                        token: '${token}',
                        timestamp: Date.now(),
                        performance: performance.now(),
                        memory: performance.memory ? {
                            usedJSHeapSize: performance.memory.usedJSHeapSize,
                            totalJSHeapSize: performance.memory.totalJSHeapSize,
                        } : null,
                        screen: {
                            width: screen.width,
                            height: screen.height,
                            availWidth: screen.availWidth,
                            availHeight: screen.availHeight,
                            colorDepth: screen.colorDepth,
                            pixelDepth: screen.pixelDepth,
                        },
                        navigator: {
                            userAgent: navigator.userAgent,
                            language: navigator.language,
                            languages: navigator.languages,
                            platform: navigator.platform,
                            cookieEnabled: navigator.cookieEnabled,
                            hardwareConcurrency: navigator.hardwareConcurrency,
                            deviceMemory: navigator.deviceMemory,
                            maxTouchPoints: navigator.maxTouchPoints,
                            pdfViewerEnabled: navigator.pdfViewerEnabled,
                            webdriver: navigator.webdriver,
                        },
                        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                        timezoneOffset: new Date().getTimezoneOffset(),
                        plugins: Array.from(navigator.plugins).map(p => p.name),
                        mimeTypes: Array.from(navigator.mimeTypes).map(m => m.type),
                    };

                    // Canvas fingerprinting
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    if (ctx) {
                        canvas.width = 200;
                        canvas.height = 50;
                        ctx.fillStyle = 'rgb(255, 0, 0)';
                        ctx.fillRect(10, 10, 50, 50);
                        ctx.fillStyle = 'rgb(0, 255, 0)';
                        ctx.fillRect(70, 10, 50, 50);
                        ctx.fillStyle = 'rgb(0, 0, 255)';
                        ctx.fillRect(130, 10, 50, 50);
                        ctx.fillStyle = 'black';
                        ctx.font = '20px Arial';
                        ctx.fillText('WAF Challenge', 10, 40);
                        data.canvas = canvas.toDataURL();
                    }

                    // WebGL fingerprinting
                    const glCanvas = document.createElement('canvas');
                    const gl = glCanvas.getContext('webgl') || glCanvas.getContext('experimental-webgl');
                    if (gl) {
                        data.webgl = {
                            vendor: gl.getParameter(gl.VENDOR),
                            renderer: gl.getParameter(gl.RENDERER),
                            version: gl.getParameter(gl.VERSION),
                            shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
                        };
                    }

                    // Audio fingerprinting
                    try {
                        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
                        const oscillator = audioCtx.createOscillator();
                        const analyser = audioCtx.createAnalyser();
                        const gain = audioCtx.createGain();
                        const scriptProcessor = audioCtx.createScriptProcessor(4096, 1, 1);

                        data.audio = {
                            sampleRate: audioCtx.sampleRate,
                            state: audioCtx.state,
                        };
                    } catch (e) {
                        data.audio = null;
                    }

                    // Submit challenge
                    const response = await fetch('/waf/verify-challenge', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            challenge: btoa(JSON.stringify(data)),
                            token: '${token}'
                        })
                    });

                    if (response.ok) {
                        status.textContent = 'Verified! Redirecting...';
                        const url = new URL(window.location.href);
                        url.searchParams.set('_waf_verified', '${token}');
                        window.location.replace(url.toString());
                    } else {
                        throw new Error('Challenge failed');
                    }
                } catch (err) {
                    console.error('Challenge error:', err);
                    spinner.style.display = 'none';
                    status.style.display = 'none';
                    error.style.display = 'block';
                }
            }

            // Delay slightly to ensure page is rendered
            setTimeout(runChallenge, 100);
        })();
    </script>
</body>
</html>
  `;
}

/**
 * Generate CAPTCHA page
 */
function generateCaptchaPage(token: string): string {
  return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CAPTCHA Verification</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 16px;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 { margin-bottom: 20px; }
        p { color: #666; margin-bottom: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 CAPTCHA Verification</h1>
        <p>Please complete the CAPTCHA to continue.</p>
        <div class="g-recaptcha" data-sitekey="YOUR_SITE_KEY" data-callback="onCaptchaSuccess"></div>
    </div>
    <script>
        function onCaptchaSuccess(token) {
            fetch('/waf/verify-captcha', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: token, waf_token: '${token}' })
            }).then(function(res) {
                if (res.ok) {
                    window.location.reload();
                }
            });
        }
    </script>
</body>
</html>
  `;
}

// Proxy configuration
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
  onError: (err, _req, res: any) => {
    console.error('[WAF] Proxy error:', err);
    res.status(502).json({
      error: 'Bad Gateway',
      message: 'Unable to reach backend server',
    });
  },
} as Options);

// Use proxy for all other routes
app.use('/', proxyMiddleware);

// Start server
const PORT = process.env.WAF_PORT || 3000;

app.listen(PORT, () => {
  console.log('[WAF] ╔════════════════════════════════════════════════════╗');
  console.log('[WAF] ║     Universal WAF - Advanced Protection Layer      ║');
  console.log('[WAF] ╠════════════════════════════════════════════════════╣');
  console.log('[WAF] ║  Server: http://localhost:' + PORT + '                    ║');
  console.log('[WAF] ║  Backend: ' + BACKEND_URL.padEnd(42) + ' ║');
  console.log('[WAF] ║  Health: http://localhost:' + PORT + '/waf/health            ║');
  console.log('[WAF] ║  Metrics: http://localhost:' + PORT + '/waf/metrics          ║');
  console.log('[WAF] ╚════════════════════════════════════════════════════╝');
  console.log('');
  console.log('[WAF] Features enabled:');
  const config = wafEngine.getConfig();
  console.log(`[WAF]   - GeoIP Filtering: ${config.geoBlacklist.length > 0 || config.geoWhitelist.length > 0}`);
  console.log(`[WAF]   - Rate Limiting: ${config.rateLimitEnabled}`);
  console.log(`[WAF]   - Brute Force Protection: ${config.bruteForceEnabled}`);
  console.log(`[WAF]   - Bot Protection: ${config.botProtectionEnabled} (${config.botProtectionLevel})`);
  console.log(`[WAF]   - DDoS Protection: ${config.ddosEnabled}`);
  console.log(`[WAF]   - SQL Injection: ${config.sqliEnabled} (${config.sqliLevel})`);
  console.log(`[WAF]   - XSS Protection: ${config.xssEnabled} (${config.xssLevel})`);
  console.log(`[WAF]   - CSRF Protection: ${config.csrfEnabled}`);
  console.log(`[WAF]   - Anonymous IP Detection: ${config.blockTor || config.blockVpn || config.blockProxy}`);
  console.log('');
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
