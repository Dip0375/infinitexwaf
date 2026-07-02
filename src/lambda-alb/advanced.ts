/**
 * Advanced ALB Lambda Target Adapter
 * Supports all WAF actions including CAPTCHA and Challenges
 */

import { ALBEvent, ALBResult } from 'aws-lambda';
import { AdvancedWAFEngine, AdvancedWAFResult } from '../core/engine-advanced';
import { AdvancedWAFConfig, DEFAULT_ADVANCED_CONFIG, WAFAction } from '../core/rules-advanced';

// Initialize WAF
const getConfig = (): Partial<AdvancedWAFConfig> => {
  try {
    const envConfig = process.env.WAF_CONFIG || '{}';
    const parsed = JSON.parse(envConfig);
    return { ...DEFAULT_ADVANCED_CONFIG, ...parsed };
  } catch {
    return DEFAULT_ADVANCED_CONFIG;
  }
};

const wafEngine = new AdvancedWAFEngine(getConfig());

/**
 * Convert ALB event to WAF request
 */
function convertToWAFRequest(event: ALBEvent): any {
  const headers: Record<string, string | string[]> = {};

  if (event.headers) {
    for (const [key, value] of Object.entries(event.headers)) {
      if (value !== undefined) {
        headers[key.toLowerCase()] = value;
      }
    }
  }

  if (event.multiValueHeaders) {
    for (const [key, values] of Object.entries(event.multiValueHeaders)) {
      if (values) {
        headers[key.toLowerCase()] = values;
      }
    }
  }

  // Get GeoIP from X-Forwarded headers if available
  const country = typeof headers['cloudfront-viewer-country'] === 'string'
    ? headers['cloudfront-viewer-country']
    : undefined;

  return {
    method: event.httpMethod,
    uri: event.path,
    headers,
    queryString: event.queryStringParameters
      ? new URLSearchParams(event.queryStringParameters as Record<string, string>).toString()
      : undefined,
    body: event.body,
    clientIp: event.headers?.['x-forwarded-for']?.split(',')[0].trim() || 'unknown',
    userAgent: typeof headers['user-agent'] === 'string' ? headers['user-agent'] : undefined,
    geoCountry: country,
    timestamp: Date.now(),
  };
}

/**
 * Create ALB response based on action
 */
function createActionResponse(result: AdvancedWAFResult): ALBResult {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-WAF-Action': result.action,
    'X-WAF-Threat-Score': String(result.threatScore || 0),
  };

  if (result.geoCountry) {
    headers['X-WAF-Country'] = result.geoCountry;
  }

  if (result.reasons?.length) {
    headers['X-WAF-Reasons'] = result.reasons.join(',');
  }

  if (result.ruleId) {
    headers['X-WAF-Rule'] = result.ruleId;
  }

  switch (result.action) {
    case 'ALLOW':
    case 'LOG':
      return {
        statusCode: 200,
        statusDescription: '200 OK',
        headers: {
          ...headers,
          'X-WAF-Verified': 'true',
        },
        body: JSON.stringify({
          message: 'WAF check passed',
          action: result.action,
          threatScore: result.threatScore,
        }),
        isBase64Encoded: false,
      };

    case 'BLOCK':
      headers['X-WAF-Blocked'] = 'true';
      return {
        statusCode: result.statusCode,
        statusDescription: `${result.statusCode} Forbidden`,
        headers,
        body: JSON.stringify({
          error: 'Access Denied',
          message: result.message,
          action: result.action,
          reasons: result.reasons,
          timestamp: new Date().toISOString(),
        }),
        isBase64Encoded: false,
      };

    case 'RATE_LIMIT':
      headers['Retry-After'] = '60';
      return {
        statusCode: 429,
        statusDescription: '429 Too Many Requests',
        headers,
        body: JSON.stringify({
          error: 'Rate Limited',
          message: 'Too many requests. Please slow down.',
          retryAfter: 60,
        }),
        isBase64Encoded: false,
      };

    case 'CHALLENGE_JS':
    case 'CAPTCHA':
      headers['Content-Type'] = 'text/html';
      headers['Cache-Control'] = 'no-cache, no-store';
      return {
        statusCode: 403,
        statusDescription: '403 Forbidden - Challenge Required',
        headers,
        body: generateChallengePage(result),
        isBase64Encoded: false,
      };

    case 'REDIRECT':
      headers['Location'] = 'https://example.com/blocked';
      return {
        statusCode: 302,
        statusDescription: '302 Found',
        headers,
        body: '',
        isBase64Encoded: false,
      };

    case 'DROP':
      // Close connection
      return {
        statusCode: 444,
        statusDescription: '444 No Response',
        headers: {},
        body: '',
        isBase64Encoded: false,
      };

    default:
      return {
        statusCode: 403,
        statusDescription: '403 Forbidden',
        headers,
        body: JSON.stringify({ error: 'Forbidden' }),
        isBase64Encoded: false,
      };
  }
}

/**
 * Generate JavaScript challenge page
 */
function generateChallengePage(result: AdvancedWAFResult): string {
  const token = result.challengeToken || '';

  return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Verification</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .container { text-align: center; padding: 40px; background: white; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); max-width: 400px; }
        h1 { color: #333; margin-bottom: 10px; }
        p { color: #666; margin-bottom: 30px; }
        .spinner { width: 50px; height: 50px; border: 5px solid #f3f3f3; border-top: 5px solid #667eea; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 20px; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .info { font-size: 12px; color: #999; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Verification</h1>
        <p>We're verifying your browser. This will only take a moment.</p>
        <div class="spinner"></div>
        <p class="info">Token: ${token.substring(0, 20)}...</p>
    </div>
    <script>
        (function() {
            const challenge = {
                token: '${token}',
                timestamp: Date.now(),
                screen: window.screen ? { width: screen.width, height: screen.height, colorDepth: screen.colorDepth } : null,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                timezoneOffset: new Date().getTimezoneOffset(),
                language: navigator.language,
                languages: navigator.languages,
                platform: navigator.platform,
                cookieEnabled: navigator.cookieEnabled,
                doNotTrack: navigator.doNotTrack,
                hardwareConcurrency: navigator.hardwareConcurrency || null,
                deviceMemory: navigator.deviceMemory || null,
                maxTouchPoints: navigator.maxTouchPoints || 0,
                pdfViewerEnabled: navigator.pdfViewerEnabled || false,
                webdriver: navigator.webdriver || false,
                plugins: Array.from(navigator.plugins || []).map(p => p.name),
                mimeTypes: Array.from(navigator.mimeTypes || []).map(m => m.type),
            };

            // Fingerprint calculation
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            if (ctx) {
                ctx.textBaseline = 'top';
                ctx.font = '14px Arial';
                ctx.fillText('Fingerprint test!', 2, 2);
                challenge.canvas = canvas.toDataURL().slice(-50);
            }

            // WebGL fingerprint
            const gl = document.createElement('canvas').getContext('webgl');
            if (gl) {
                challenge.webgl = {
                    vendor: gl.getParameter(gl.VENDOR),
                    renderer: gl.getParameter(gl.RENDERER),
                };
            }

            const response = btoa(JSON.stringify(challenge));

            fetch('/waf/verify-challenge', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ challenge: response, token: '${token}' })
            }).then(function(res) {
                if (res.ok) {
                    const originalUrl = new URL(window.location.href);
                    originalUrl.searchParams.set('_waf_verified', '${token}');
                    window.location.replace(originalUrl.toString());
                } else {
                    throw new Error('Challenge failed');
                }
            }).catch(function(err) {
                console.error('Challenge error:', err);
                document.querySelector('.container').innerHTML = '<h1>❌ Access Denied</h1><p>Unable to verify your browser. Please disable any automation tools and try again.</p>';
            });
        })();
    </script>
</body>
</html>
  `;
}

/**
 * ALB handler
 */
export const handler = async (event: ALBEvent): Promise<ALBResult> => {
  // Convert to WAF format
  const wafRequest = convertToWAFRequest(event);

  // Process through WAF
  const result = await wafEngine.processRequest(wafRequest);

  // Log request
  wafEngine.logRequest(wafRequest, result);

  // Return appropriate response
  return createActionResponse(result);
};

module.exports = { handler };
