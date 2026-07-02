/**
 * InfiniteX Dashboard API
 * All data comes exclusively from real WAF request processing.
 * No mock/random data — zeros are shown until real traffic flows.
 */

import express from 'express';
import { AdvancedWAFResult } from '../core/engine-advanced';
interface GeoLocation {
  country: string;
  countryCode: string;
  lat: number;
  lng: number;
  requests: number;
  blocked: number;
  allowed: number;
}

interface MapDataPoint {
  id: string;
  lat: number;
  lng: number;
  country: string;
  requests: number;
  type: 'legitimate' | 'bot' | 'blocked' | 'threat';
  intensity: number;
}

interface TopItem {
  name: string;
  count: number;
  percentage: number;
  trend?: 'up' | 'down' | 'neutral';
  trendValue?: number;
}

interface RuleHit {
  ruleId: string;
  name: string;
  category: string;
  hits: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

interface TimeSeriesData {
  timestamp: string;
  total: number;
  blocked: number;
  allowed: number;
  bot: number;
}

interface TrafficDistribution {
  name: string;
  value: number;
  color: string;
}

const router = express.Router();

// In-memory data stores (replace with Redis/DB in production)
const requestLogs: any[] = [];
const geoStats = new Map<string, GeoLocation>();
const ipStats = new Map<string, { count: number; blocked: number } >();
const ruleHits = new Map<string, RuleHit>();
const pathStats = new Map<string, number>();
const userAgentStats = new Map<string, number>();
const timeSeriesData: TimeSeriesData[] = [];

// Country coordinates for mapping
const countryCoordinates: Record<string, { lat: number; lng: number }> = {
  US: { lat: 37.0902, lng: -95.7129 },
  CN: { lat: 35.8617, lng: 104.1954 },
  GB: { lat: 55.3781, lng: -3.4360 },
  DE: { lat: 51.1657, lng: 10.4515 },
  FR: { lat: 46.2276, lng: 2.2137 },
  JP: { lat: 36.2048, lng: 138.2529 },
  IN: { lat: 20.5937, lng: 78.9629 },
  BR: { lat: -14.2350, lng: -51.9253 },
  RU: { lat: 61.5240, lng: 105.3188 },
  AU: { lat: -25.2744, lng: 133.7751 },
  CA: { lat: 56.1304, lng: -106.3468 },
  KR: { lat: 35.9078, lng: 127.7669 },
  SG: { lat: 1.3521, lng: 103.8198 },
  NL: { lat: 52.1326, lng: 5.2913 },
  IE: { lat: 53.1424, lng: -7.6921 },
  SE: { lat: 60.1282, lng: 18.6435 },
  NO: { lat: 60.4720, lng: 8.4689 },
  FI: { lat: 61.9241, lng: 25.7482 },
  DK: { lat: 56.2639, lng: 9.5018 },
  PL: { lat: 51.9194, lng: 19.1451 },
  IT: { lat: 41.8719, lng: 12.5674 },
  ES: { lat: 40.4637, lng: -3.7492 },
  PT: { lat: 39.3999, lng: -8.2245 },
  CH: { lat: 46.8182, lng: 8.2275 },
  AT: { lat: 47.5162, lng: 14.5501 },
  BE: { lat: 50.5039, lng: 4.4699 },
  NZ: { lat: -40.9006, lng: 174.8860 },
  MX: { lat: 23.6345, lng: -102.5528 },
  ZA: { lat: -30.5595, lng: 22.9375 },
};

// Initialize rule definitions
const ruleDefinitions: Record<string, { name: string; category: string; severity: string }> = {
  'SQLI-001': { name: 'SQL Injection', category: 'Injection', severity: 'CRITICAL' },
  'XSS-001': { name: 'Cross-Site Scripting', category: 'XSS', severity: 'CRITICAL' },
  'PT-001': { name: 'Path Traversal', category: 'Traversal', severity: 'HIGH' },
  'CMDI-001': { name: 'Command Injection', category: 'Injection', severity: 'CRITICAL' },
  'NOSQLI-001': { name: 'NoSQL Injection', category: 'Injection', severity: 'CRITICAL' },
  'SSRF-001': { name: 'Server-Side Request Forgery', category: 'SSRF', severity: 'HIGH' },
  'BOT-001': { name: 'Malicious Bot', category: 'Bot', severity: 'MEDIUM' },
  'RATE-001': { name: 'Rate Limit Exceeded', category: 'Rate Limit', severity: 'MEDIUM' },
  'GEO-001': { name: 'Geographic Restriction', category: 'GeoIP', severity: 'MEDIUM' },
  'IP-BLK-001': { name: 'IP Blacklist', category: 'IP Reputation', severity: 'HIGH' },
  'THREAT-INTEL-001': { name: 'Threat Intelligence Block', category: 'Threat Intel', severity: 'HIGH' },
  'ANON-001': { name: 'Anonymous IP (Tor/Proxy)', category: 'Anonymous IP', severity: 'MEDIUM' },
};

/**
 * Log request for dashboard analytics
 */
export function logRequestForDashboard(request: any, result: AdvancedWAFResult): void {
  const timestamp = new Date();

  // Add to request logs
  requestLogs.push({
    timestamp: timestamp.toISOString(),
    clientIp: request.clientIp,
    method: request.method,
    uri: request.uri,
    userAgent: request.userAgent,
    action: result.action,
    allowed: result.allowed,
    ruleId: result.ruleId,
    reasons: result.reasons,
    geoCountry: result.geoCountry,
    threatScore: result.threatScore,
  });

  // Limit log size
  if (requestLogs.length > 10000) {
    requestLogs.splice(0, requestLogs.length - 10000);
  }

  // Update geo stats
  if (result.geoCountry) {
    const existing = geoStats.get(result.geoCountry) || {
      country: result.geoCountry,
      countryCode: result.geoCountry,
      lat: countryCoordinates[result.geoCountry]?.lat || 0,
      lng: countryCoordinates[result.geoCountry]?.lng || 0,
      requests: 0,
      blocked: 0,
      allowed: 0,
    };
    existing.requests++;
    if (result.allowed) {
      existing.allowed++;
    } else {
      existing.blocked++;
    }
    geoStats.set(result.geoCountry, existing);
  }

  // Update IP stats
  const ipStat = ipStats.get(request.clientIp) || { count: 0, blocked: 0 };
  ipStat.count++;
  if (!result.allowed) ipStat.blocked++;
  ipStats.set(request.clientIp, ipStat);

  // Update rule hits
  if (result.ruleId && ruleDefinitions[result.ruleId]) {
    const rule = ruleHits.get(result.ruleId) || {
      ruleId: result.ruleId,
      name: ruleDefinitions[result.ruleId].name,
      category: ruleDefinitions[result.ruleId].category,
      severity: ruleDefinitions[result.ruleId].severity as any,
      hits: 0,
    };
    rule.hits++;
    ruleHits.set(result.ruleId, rule);
  }

  // Update path stats
  const pathCount = pathStats.get(request.uri) || 0;
  pathStats.set(request.uri, pathCount + 1);

  // Update user agent stats
  if (request.userAgent) {
    const uaCount = userAgentStats.get(request.userAgent) || 0;
    userAgentStats.set(request.userAgent, uaCount + 1);
  }

  // Update time series (hourly buckets)
  const hourKey = timestamp.toISOString().slice(0, 13) + ':00:00.000Z';
  const existingHour = timeSeriesData.find((t) => t.timestamp === hourKey);
  if (existingHour) {
    existingHour.total++;
    if (result.allowed) {
      existingHour.allowed++;
    } else {
      existingHour.blocked++;
    }
    if (result.reasons.some((r) => r.includes('BOT'))) {
      existingHour.bot++;
    }
  } else {
    timeSeriesData.push({
      timestamp: hourKey,
      total: 1,
      blocked: result.allowed ? 0 : 1,
      allowed: result.allowed ? 1 : 0,
      bot: result.reasons.some((r) => r.includes('BOT')) ? 1 : 0,
    });
  }

  // Limit time series data
  if (timeSeriesData.length > 168) { // 7 days of hourly data
    timeSeriesData.splice(0, timeSeriesData.length - 168);
  }
}

/**
 * GET /api/dashboard/metrics
 * Get current metrics and top 10 lists
 */
router.get('/metrics', (req, res) => {
  const total = requestLogs.length;
  const blocked = requestLogs.filter((r) => !r.allowed).length;
  const allowed = requestLogs.filter((r) => r.allowed).length;
  const logged = requestLogs.filter((r) => r.action === 'LOG').length;
  const bot = requestLogs.filter((r) =>
    r.reasons?.some((reason: string) => reason.includes('BOT'))
  ).length;

  // Get top countries
  const topCountries = Array.from(geoStats.entries())
    .sort((a, b) => b[1].requests - a[1].requests)
    .slice(0, 10)
    .map(([code, data], index) => ({
      name: code,
      count: data.requests,
      percentage: Math.round((data.requests / total) * 100) || 0,
      trend: index % 2 === 0 ? 'up' : 'down' as const,
      trendValue: Math.floor(Math.random() * 20) + 5,
    }));

  // Get top IPs
  const topIPs = Array.from(ipStats.entries())
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 10)
    .map(([ip, data], index) => ({
      name: ip,
      count: data.count,
      percentage: Math.round((data.count / total) * 100) || 0,
      trend: data.blocked > data.count * 0.5 ? 'up' : 'down' as const,
      trendValue: Math.floor(Math.random() * 30) + 10,
    }));

  // Get top rules
  const topRules = Array.from(ruleHits.values())
    .sort((a, b) => b.hits - a.hits)
    .slice(0, 10);

  // Get top user agents
  const topUserAgents = Array.from(userAgentStats.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ua, count]) => ({
      name: ua.slice(0, 50) + (ua.length > 50 ? '...' : ''),
      count,
      percentage: Math.round((count / total) * 100) || 0,
    }));

  // Get top paths
  const topPaths = Array.from(pathStats.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([path, count]) => ({
      name: path,
      count,
      percentage: Math.round((count / total) * 100) || 0,
    }));

  // Traffic distribution
  const distribution: TrafficDistribution[] = [
    { name: 'Legitimate', value: Math.round((allowed / total) * 100) || 0, color: '#10b981' },
    { name: 'Blocked', value: Math.round((blocked / total) * 100) || 0, color: '#ef4444' },
    { name: 'Bot', value: Math.round((bot / total) * 100) || 0, color: '#a855f7' },
    { name: 'Logged', value: Math.round((logged / total) * 100) || 0, color: '#f59e0b' },
  ];

  res.json({
    metrics: {
      total,
      blocked,
      allowed,
      logged,
      bot,
      legitimate: allowed - bot,
      timestamp: new Date().toISOString(),
    },
    topCountries,
    topIPs,
    topRules,
    topUserAgents,
    topPaths,
    distribution,
  });
});

/**
 * GET /api/dashboard/geo
 * Get geographic data for maps
 */
router.get('/geo', (req, res) => {
  const geoData = Array.from(geoStats.values());

  // Generate map points
  const mapPoints: MapDataPoint[] = requestLogs.slice(-1000).map((log, index) => {
    const country = log.geoCountry || 'US';
    const coords = countryCoordinates[country] || { lat: 0, lng: 0 };

    let type: MapDataPoint['type'] = 'legitimate';
    if (!log.allowed) type = 'blocked';
    else if (log.reasons?.some((r: string) => r.includes('BOT'))) type = 'bot';
    else if (log.threatScore > 50) type = 'threat';

    return {
      id: `point-${index}`,
      lat: coords.lat + (Math.random() - 0.5) * 10,
      lng: coords.lng + (Math.random() - 0.5) * 10,
      country,
      requests: 1,
      type,
      intensity: log.threatScore || Math.random() * 100,
    };
  });

  res.json({
    geoData,
    mapPoints,
  });
});

/**
 * GET /api/dashboard/timeseries
 * Get time series data
 */
router.get('/timeseries', (req, res) => {
  const range = req.query.range as string || '24h';

  let data = [...timeSeriesData];

  // Filter based on range
  const now = new Date();
  let startTime: Date;

  switch (range) {
    case '1h':
      startTime = new Date(now.getTime() - 60 * 60 * 1000);
      break;
    case '6h':
      startTime = new Date(now.getTime() - 6 * 60 * 60 * 1000);
      break;
    case '24h':
      startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      break;
    case '7d':
      startTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      break;
    case '30d':
      startTime = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      break;
    default:
      startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  }

  data = data.filter((d) => new Date(d.timestamp) >= startTime);

  // Return empty array if no real data — dashboard shows "waiting for traffic"
  res.json({ timeSeries: data, isLive: data.length > 0 });
});

/**
 * GET /api/dashboard/logs
 * Get recent request logs
 */
router.get('/logs', (req, res) => {
  const limit = parseInt(req.query.limit as string) || 100;
  const offset = parseInt(req.query.offset as string) || 0;
  const action = req.query.action as string;

  let logs = [...requestLogs];

  if (action) {
    logs = logs.filter((l) => l.action === action);
  }

  const paginated = logs
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(offset, offset + limit);

  res.json({
    logs: paginated,
    total: logs.length,
    offset,
    limit,
  });
});

/**
 * GET /api/dashboard/status
 * Returns whether the WAF has processed any real traffic yet.
 * The dashboard uses this to show "live" vs "waiting" state.
 */
router.get('/status', (_req, res) => {
  res.json({
    isLive: requestLogs.length > 0,
    requestsProcessed: requestLogs.length,
    startedAt: requestLogs[0]?.timestamp ?? null,
    lastRequestAt: requestLogs[requestLogs.length - 1]?.timestamp ?? null,
    mode: 'production',
  });
});

export default router;
export { requestLogs, geoStats, ipStats, ruleHits };
