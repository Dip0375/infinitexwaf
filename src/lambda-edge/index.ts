/**
 * Lambda@Edge Adapter for CloudFront
 * Deploy this to CloudFront as a viewer request function
 */

import { CloudFrontRequestEvent, CloudFrontRequestResult, CloudFrontHeaders } from 'aws-lambda';
import { WAFRequest, WAFResult } from '../core/rules';
import { WAFEngine, WAFConfig } from '../core/engine';

// Initialize WAF engine with config from environment
const getConfig = (): Partial<WAFConfig> => {
  try {
    return JSON.parse(process.env.WAF_CONFIG || '{}');
  } catch {
    return {};
  }
};

const wafEngine = new WAFEngine(getConfig());

/**
 * Convert CloudFront request to WAF request format
 */
function convertToWAFRequest(
  cfRequest: CloudFrontRequestEvent['Records'][0]['cf']['request']
): WAFRequest {
  const headers: Record<string, string | string[]> = {};

  for (const [key, values] of Object.entries(cfRequest.headers)) {
    if (values.length === 1) {
      headers[key] = values[0].value;
    } else {
      headers[key] = values.map((v) => v.value);
    }
  }

  return {
    method: cfRequest.method,
    uri: cfRequest.uri,
    headers,
    queryString: cfRequest.querystring,
    body: cfRequest.body?.data,
    clientIp: cfRequest.clientIp,
    userAgent: typeof headers['user-agent'] === 'string' ? headers['user-agent'] : undefined,
    timestamp: Date.now(),
  };
}

/**
 * Convert WAF result to CloudFront response
 */
function createBlockResponse(result: WAFResult): CloudFrontRequestResult {
  const responseHeaders: CloudFrontHeaders = {
    'content-type': [{ key: 'Content-Type', value: 'application/json' }],
    'x-waf-blocked': [{ key: 'X-WAF-Blocked', value: 'true' }],
    'x-waf-rule': [{ key: 'X-WAF-Rule', value: result.ruleId || 'unknown' }],
  };

  // Add monitoring headers if in monitor mode
  if (result.blockedReason) {
    responseHeaders['x-waf-reason'] = [{ key: 'X-WAF-Reason', value: result.blockedReason }];
  }

  return {
    status: String(result.statusCode),
    headers: responseHeaders,
    body: JSON.stringify({
      error: 'Access Denied',
      message: 'Your request has been blocked by the Web Application Firewall',
      requestId: `waf-${Date.now()}`,
    }),
  };
}

/**
 * Lambda@Edge handler for viewer requests
 */
export const handler = async (
  event: CloudFrontRequestEvent
): Promise<CloudFrontRequestResult> => {
  const request = event.Records[0].cf.request;

  // Convert to WAF format
  const wafRequest = convertToWAFRequest(request);

  // Process through WAF
  const result = wafEngine.processRequest(wafRequest);

  // Log the request (CloudFront logs this automatically)
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    clientIp: request.clientIp,
    uri: request.uri,
    method: request.method,
    allowed: result.allowed,
    ruleId: result.ruleId,
    severity: result.severity,
  }));

  // If blocked, return block response
  if (!result.allowed) {
    return createBlockResponse(result);
  }

  // If monitoring mode with detected issue, add headers
  if (result.blockedReason) {
    request.headers['x-waf-alert'] = [{ key: 'X-WAF-Alert', value: result.blockedReason }];
  }

  // Add WAF pass header
  request.headers['x-waf-verified'] = [{ key: 'X-WAF-Verified', value: 'true' }];

  // Return the request to continue to origin
  return request;
};

// For CommonJS compatibility
module.exports = { handler };
