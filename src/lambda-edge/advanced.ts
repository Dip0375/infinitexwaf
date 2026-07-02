/**
 * Advanced Lambda@Edge Adapter for CloudFront
 * Supports CAPTCHA, Challenges, GeoIP, and all advanced actions
 */

import { CloudFrontRequestEvent, CloudFrontRequestResult, CloudFrontHeaders } from 'aws-lambda';
import { AdvancedWAFEngine, AdvancedWAFResult } from '../core/engine-advanced';
import { AdvancedWAFConfig, DEFAULT_ADVANCED_CONFIG } from '../core/rules-advanced';
import { WAFAction } from '../core/rules-advanced';

// Initialize WAF engine
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
 * Convert CloudFront request to WAF format with GeoIP
 */
function convertToWAFRequest(
  cfRequest: CloudFrontRequestEvent['Records'][0]['cf']['request']
): any {
  const headers: Record<string, string | string[]> = {};

  for (const [key, values] of Object.entries(cfRequest.headers)) {
    if (values.length === 1) {
      headers[key] = values[0].value;
    } else {
      headers[key] = values.map((v) => v.value);
    }
  }

  // Extract GeoIP country from CloudFront
  const country = cfRequest.headers['cloudfront-viewer-country']?.[0]?.value ||
                  cfRequest.headers['cloudfront-viewer-country-name']?.[0]?.value;

  return {
    method: cfRequest.method,
    uri: cfRequest.uri,
    headers,
    queryString: cfRequest.querystring,
    body: cfRequest.body?.data,
    clientIp: cfRequest.clientIp,
    userAgent: typeof headers['user-agent'] === 'string' ? headers['user-agent'] : undefined,
    geoCountry: country,
    timestamp: Date.now(),
  };
}

/**
 * Create response for each action type
 */
function createActionResponse(result: AdvancedWAFResult): CloudFrontRequestResult {
  const headers: CloudFrontHeaders = {
    'content-type': [{ key: 'Content-Type', value: 'application/json' }],
    'x-waf-action': [{ key: 'X-WAF-Action', value: result.action }],
    'x-waf-threat-score': [{ key: 'X-WAF-Threat-Score', value: String(result.threatScore || 0) }],
  };

  if (result.geoCountry) {
    headers['x-waf-country'] = [{ key: 'X-WAF-Country', value: result.geoCountry }];
  }

  if (result.reasons?.length) {
    headers['x-waf-reasons'] = [{ key: 'X-WAF-Reasons', value: result.reasons.join(',') }];
  }

  switch (result.action) {
    case 'ALLOW':
      return { // Continue to origin
        status: '200',
        headers,
      };

    case 'BLOCK':
      headers['x-waf-blocked'] = [{ key: 'X-WAF-Blocked', value: 'true' }];
      if (result.ruleId) {
        headers['x-waf-rule'] = [{ key: 'X-WAF-Rule', value: result.ruleId }];
      }
      return {
        status: String(result.statusCode),
        headers,
        body: JSON.stringify({
          error: 'Access Denied',
          message: result.message,
          action: result.action,
          timestamp: new Date().toISOString(),
          requestId: `waf-${Date.now()}`,
        }),
      };

    case 'LOG':
      // Return request with logging headers
      return {
        status: '200',
        headers,
      };

    case 'CHALLENGE_JS':
    case 'CAPTCHA':
      // JavaScript challenge page
      headers['content-type'] = [{ key: 'Content-Type', value: 'text/html' }];
      headers['cache-control'] = [{ key: 'Cache-Control', value: 'no-cache, no-store' }];
      return {
        status: '403',
        statusDescription: 'Forbidden - Challenge Required',
        headers,
        body: generateChallengePage(result),
      };

    case 'RATE_LIMIT':
      headers['retry-after'] = [{ key: 'Retry-After', value: '60' }];
      return {
        status: '429',
        statusDescription: 'Too Many Requests',
        headers,
        body: JSON.stringify({
          error: 'Rate Limited',
          message: 'Too many requests. Please slow down.',
          retryAfter: 60,
        }),
      };

    case 'REDIRECT':
      headers['location'] = [{ key: 'Location', value: 'https://example.com/blocked' }];
      return {
        status: '302',
        statusDescription: 'Found',
        headers,
      };

    case 'DROP':
      // Return empty response (connection dropped)
      return {
        status: '444',
        statusDescription: 'No Response',
        headers: {},
        body: '',
      };

    default:
      return {
        status: '403',
        headers,
        body: JSON.stringify({ error: 'Forbidden' }),
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
    <title>Security Check</title>
    <style>
        body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }
        .container { text-align: center; padding: 40px; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        p { color: #666; }
        .spinner { width: 40px; height: 40px; border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; animation: spin 1s linear infinite; margin: 20px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Check</h1>
        <p>Verifying your browser... Please wait.</p>
        <div class="spinner"></div>
        <p>This will only take a moment.</p>
    </div>
    <script>
        (function() {
            // JavaScript challenge - verify browser capabilities
            const challenge = {
                token: '${token}',
                timestamp: Date.now(),
                screen: window.screen ? { width: screen.width, height: screen.height } : null,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                language: navigator.language,
                platform: navigator.platform,
                cookieEnabled: navigator.cookieEnabled,
                doNotTrack: navigator.doNotTrack,
                hardwareConcurrency: navigator.hardwareConcurrency || null,
                deviceMemory: navigator.deviceMemory || null,
            };

            // Calculate challenge response
            const response = btoa(JSON.stringify(challenge));

            // Submit challenge
            fetch('/waf/verify-challenge', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ challenge: response, token: '${token}' })
            }).then(function(res) {
                if (res.ok) {
                    window.location.reload();
                } else {
                    document.body.innerHTML = '<div class="container"><h1>Access Denied</h1><p>Unable to verify your browser. Please contact support.</p></div>';
                }
            }).catch(function() {
                // Retry after delay
                setTimeout(function() { window.location.reload(); }, 5000);
            });
        })();
    </script>
</body>
</html>
  `;
}

/**
 * Lambda@Edge handler
 */
export const handler = async (
  event: CloudFrontRequestEvent
): Promise<CloudFrontRequestResult> => {
  const request = event.Records[0].cf.request;

  // Convert to WAF format
  const wafRequest = convertToWAFRequest(request);

  // Process through WAF
  const result = await wafEngine.processRequest(wafRequest);

  // Log request
  wafEngine.logRequest(wafRequest, result);

  // If allowed, continue to origin with WAF headers
  if (result.action === 'ALLOW' || result.action === 'LOG') {
    // Add WAF verification headers
    request.headers['x-waf-verified'] = [{ key: 'X-WAF-Verified', value: 'true' }];
    if (result.threatScore) {
      request.headers['x-waf-threat-score'] = [{ key: 'X-WAF-Threat-Score', value: String(result.threatScore) }];
    }
    if (result.geoCountry) {
      request.headers['x-waf-country'] = [{ key: 'X-WAF-Country', value: result.geoCountry }];
    }

    return request;
  }

  // Return action response
  return createActionResponse(result);
};

module.exports = { handler };
