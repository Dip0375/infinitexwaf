/**
 * ALB Lambda Target Adapter
 * Deploy this as a Lambda target behind an Application Load Balancer
 */

import { ALBEvent, ALBResult } from 'aws-lambda';
import { WAFRequest } from '../core/rules';
import { WAFEngine, WAFConfig } from '../core/engine';

// Initialize WAF engine
const getConfig = (): Partial<WAFConfig> => {
  try {
    return JSON.parse(process.env.WAF_CONFIG || '{}');
  } catch {
    return {};
  }
};

const wafEngine = new WAFEngine(getConfig());

/**
 * Convert ALB request to WAF request format
 */
function convertToWAFRequest(event: ALBEvent): WAFRequest {
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

  return {
    method: event.httpMethod,
    uri: event.path,
    headers,
    queryString: event.queryStringParameters
      ? new URLSearchParams(event.queryStringParameters as Record<string, string>).toString()
      : undefined,
    body: event.body ?? undefined,
    clientIp: event.headers?.['x-forwarded-for']?.split(',')[0].trim() || 'unknown',
    userAgent: typeof headers['user-agent'] === 'string' ? headers['user-agent'] : undefined,
    timestamp: Date.now(),
  };
}

/**
 * Create ALB response for blocked requests
 */
function createBlockResponse(result: import('../core/rules').WAFResult): ALBResult {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-WAF-Blocked': 'true',
  };

  if (result.ruleId) {
    headers['X-WAF-Rule'] = result.ruleId;
  }

  if (result.blockedReason) {
    headers['X-WAF-Reason'] = result.blockedReason;
  }

  return {
    statusCode: result.statusCode,
    statusDescription: `${result.statusCode} Forbidden`,
    headers,
    body: JSON.stringify({
      error: 'Access Denied',
      message: 'Your request has been blocked by the Web Application Firewall',
      ruleId: result.ruleId,
      timestamp: new Date().toISOString(),
    }),
    isBase64Encoded: false,
  };
}

/**
 * Create ALB response to forward to actual target
 * In this mode, the Lambda acts as a check before forwarding
 */
function createAllowResponse(event: ALBEvent): ALBResult {
  // In a real scenario, you might forward to the actual target
  // For now, return a success response indicating WAF passed
  return {
    statusCode: 200,
    statusDescription: '200 OK',
    headers: {
      'Content-Type': 'application/json',
      'X-WAF-Verified': 'true',
    },
    body: JSON.stringify({
      message: 'WAF check passed',
      path: event.path,
      method: event.httpMethod,
    }),
    isBase64Encoded: false,
  };
}

/**
 * ALB Lambda handler
 */
export const handler = async (event: ALBEvent): Promise<ALBResult> => {
  // Convert to WAF format
  const wafRequest = convertToWAFRequest(event);

  // Process through WAF
  const result = wafEngine.processRequest(wafRequest);

  // Log the request
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    clientIp: wafRequest.clientIp,
    path: event.path,
    method: event.httpMethod,
    allowed: result.allowed,
    ruleId: result.ruleId,
    severity: result.severity,
  }));

  // If blocked, return block response
  if (!result.allowed) {
    return createBlockResponse(result);
  }

  // Request allowed - return success
  return createAllowResponse(event);
};

// For CommonJS compatibility
module.exports = { handler };
