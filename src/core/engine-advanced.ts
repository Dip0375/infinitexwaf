/**
 * Advanced WAF Engine with comprehensive security policies
 * Supports: GeoIP, Brute Force, DDoS, Bot Protection, Multiple Actions
 */

import { WAFRequest, WAFResult, RuleMatchResult } from './rules';
import {
  AdvancedWAFConfig,
  DEFAULT_ADVANCED_CONFIG,
  WAFAction,
  SQLI_PATTERNS,
  XSS_PATTERNS,
  ADVANCED_BOT_PATTERNS,
  KNOWN_TOR_EXIT_NODES,
  BOT_BEHAVIORAL_THRESHOLDS,
} from './rules-advanced';
import { threatIntelService } from '../threat-intel/service';
import * as geoip from 'geoip-lite';

// Result with action details
export interface AdvancedWAFResult extends WAFResult {
  action: WAFAction;
  challengeUrl?: string; // For CAPTCHA/JS challenges
  challengeToken?: string;
  sessionId?: string;
  geoCountry?: string;
  threatScore?: number; // 0-100 threat assessment
  reasons: string[]; // All triggered rules
}

// Rate limiting with burst detection
interface RateLimitEntry {
  count: number;
  firstRequest: number;
  burstCount: number;
  lastRequest: number;
  challengePassed: boolean;
  challengeExpiry: number;
}

// Brute force tracking
interface BruteForceEntry {
  attempts: number;
  firstAttempt: number;
  locked: boolean;
  lockExpiry: number;
  endpointAttempts: Map<string, number>;
}

// Behavioral tracking for DDoS/Bot detection
interface BehavioralProfile {
  requests: number[]; // Timestamps
  userAgents: Set<string>;
  countries: Set<string>;
  endpoints: Map<string, number>;
  anomalies: number;
  botScore: number;
  lastUpdated: number;
}

// Challenge session store
interface ChallengeSession {
  token: string;
  created: number;
  passed: boolean;
  ip: string;
  attempts: number;
}

// Data stores
const rateLimitStore = new Map<string, RateLimitEntry>();
const bruteForceStore = new Map<string, BruteForceEntry>();
const behavioralStore = new Map<string, BehavioralProfile>();
const challengeStore = new Map<string, ChallengeSession>();

// Known bad IP reputation (would sync from threat intelligence feeds)
const ipReputationStore = new Set<string>();

// GeoIP cache (would integrate with real GeoIP service)
const geoIpCache = new Map<string, string>();

export class AdvancedWAFEngine {
  private config: AdvancedWAFConfig;

  constructor(config: Partial<AdvancedWAFConfig> = {}) {
    this.config = { ...DEFAULT_ADVANCED_CONFIG, ...config };
    this.startCleanupInterval();
  }

  /**
   * Main request processing
   */
  public async processRequest(request: WAFRequest & { geoCountry?: string }): Promise<AdvancedWAFResult> {
    const reasons: string[] = [];
    let threatScore = 0;

    // 1. IP Blacklist Check (highest priority)
    if (this.isBlacklisted(request.clientIp)) {
      reasons.push('IP_BLACKLIST');
      return this.createResult('BLOCK', 403, 'IP Blacklisted', request, { ruleId: 'IP-BLK-001', severity: 'HIGH', reasons });
    }

    // 2. IP Whitelist Check (immediate allow)
    if (this.isWhitelisted(request.clientIp)) {
      return this.createResult('ALLOW', 200, 'IP Whitelisted', request, { reasons });
    }

    // 3. IP Reputation Check
    if (this.config.ipReputationBlock && this.hasBadReputation(request.clientIp)) {
      reasons.push('IP_BAD_REPUTATION');
      threatScore += 40;
      // Enrich with threat intel details
      const intel = threatIntelService.lookup(request.clientIp);
      if (intel.found) {
        reasons.push(`THREAT_INTEL:${intel.feeds.slice(0, 2).join(',')}`);
        threatScore = Math.min(100, threatScore + intel.confidence * 0.4);
        // Block immediately if confidence is very high
        if (intel.confidence >= 90) {
          const action = this.config.ipReputationAction;
          return this.createResult(action, this.getActionStatusCode(action, 403), 'IP blocked by threat intelligence', request, {
            ruleId: 'THREAT-INTEL-001',
            severity: 'HIGH',
            reasons,
            geoCountry: request.geoCountry,
            threatScore,
          });
        }
      }
    }

    // 4. GeoIP Checks
    const country = request.geoCountry || this.getGeoCountry(request.clientIp);
    if (country) {
      const managedCountries = this.config.geoRestrictionCountries.filter(Boolean);
      const blockedCountries = this.config.geoRestrictionEnabled && managedCountries.length > 0
        ? managedCountries
        : this.config.geoBlacklist;
      if (blockedCountries.includes(country)) {
        reasons.push(`GEO_BLACKLIST:${country}`);
        const action = this.config.geoRestrictionAction;
        return this.createResult(action, this.getActionStatusCode(action, 403), 'Geographic region blocked', request, {
          ruleId: 'GEO-001',
          severity: 'MEDIUM',
          reasons,
          geoCountry: country,
          threatScore,
        });
      }

      // Geo challenge (CAPTCHA required for certain countries)
      if (this.config.geoChallenge.includes(country)) {
        const hasPassedChallenge = this.hasValidChallenge(request.clientIp);
        if (!hasPassedChallenge) {
          reasons.push(`GEO_CHALLENGE:${country}`);
          return this.createChallengeResult(request, country, reasons);
        }
      }
    }

    // 5. Anonymous IP Protection (TOR/VPN/Proxy)
    const anonymousType = this.detectAnonymousIp(request.clientIp);
    if (anonymousType) {
      const shouldBlock =
        (anonymousType === 'TOR' && this.config.blockTor) ||
        (anonymousType === 'VPN' && this.config.blockVpn) ||
        (anonymousType === 'PROXY' && this.config.blockProxy) ||
        (anonymousType === 'HOSTING' && this.config.blockHosting);

      if (shouldBlock) {
        reasons.push(`ANONYMOUS_IP:${anonymousType}`);
        return this.createResult(this.config.anonymousIpAction, 403, `Anonymous IP detected (${anonymousType})`, request, {
          ruleId: 'ANON-001',
          severity: 'MEDIUM',
          reasons,
          geoCountry: country,
          threatScore,
        });
      }
    }

    // 6. HTTP Method Control
    const methodCheck = this.checkHttpMethod(request.method);
    if (methodCheck.blocked) {
      reasons.push(`METHOD_BLOCKED:${request.method}`);
      return this.createResult(this.config.methodAction, 405, `HTTP Method ${request.method} not allowed`, request, {
        ruleId: 'METH-001',
        severity: 'MEDIUM',
        reasons,
        geoCountry: country,
        threatScore,
      });
    }

    // 7. File Upload Protection
    const uploadCheck = this.checkFileUpload(request);
    if (uploadCheck.blocked) {
      reasons.push(`UPLOAD_BLOCKED:${uploadCheck.reason}`);
      return this.createResult(this.config.uploadAction, 400, `File upload blocked: ${uploadCheck.reason}`, request, {
        ruleId: 'UPLOAD-001',
        severity: 'HIGH',
        reasons,
        geoCountry: country,
        threatScore,
      });
    }

    // 8. Brute Force Protection (for sensitive endpoints)
    if (this.config.bruteForceEnabled && this.isBruteForceEndpoint(request.uri)) {
      const bruteForceResult = this.checkBruteForce(request.clientIp, request.uri);
      if (bruteForceResult.locked) {
        reasons.push('BRUTE_FORCE_PROTECTION');
        threatScore += 60;
        const action = this.config.adminProtectionAction;
        return this.createResult(action, this.getActionStatusCode(action, 429), 'Too many failed attempts', request, {
          ruleId: 'BRUTE-001',
          severity: 'HIGH',
          reasons,
          geoCountry: country,
          threatScore,
        });
      }
    }

    // 9. Rate Limiting
    if (this.config.rateLimitEnabled) {
      const rateLimitResult = this.checkRateLimit(request.clientIp, request);
      if (rateLimitResult.exceeded) {
        reasons.push('RATE_LIMIT_EXCEEDED');
        threatScore += 30;
        const action = this.config.rateLimitAction === 'BLOCK' ? 'RATE_LIMIT' : this.config.rateLimitAction;
        return this.createResult(action, 429, 'Rate limit exceeded', request, {
          ruleId: 'RATE-001',
          severity: 'MEDIUM',
          reasons,
          geoCountry: country,
          threatScore,
        });
      }
    }

    // 10. Layer 7 DDoS Protection
    if (this.config.ddosEnabled) {
      const ddosResult = this.checkDDoS(request, country);
      if (ddosResult.detected) {
        reasons.push(`DDOS_DETECTED:${ddosResult.reason}`);
        threatScore += 80;
        if (this.config.ddosChallengeMode) {
          return this.createChallengeResult(request, country, reasons);
        }
        return this.createResult('BLOCK', 429, 'DDoS detected', request, {
          ruleId: 'DDOS-001',
          severity: 'CRITICAL',
          reasons,
          geoCountry: country,
          threatScore,
        });
      }
    }

    // 11. Advanced Bot Protection
    if (this.config.botProtectionEnabled) {
      const botResult = this.checkBotProtection(request, country);
      if (botResult.isBot) {
        reasons.push(`BOT_DETECTED:${botResult.reason}`);
        threatScore += botResult.score;

        const threshold = BOT_BEHAVIORAL_THRESHOLDS[this.config.botProtectionLevel];
        const shouldAct = botResult.score >= threshold || botResult.reason === 'Known bot signature' || botResult.reason === 'Headless browser' || botResult.reason === 'Suspicious user agent';
        if (shouldAct) {
          const action = this.config.botProtectionAction;
          if (this.config.botJsChallenge && (action === 'CHALLENGE_JS' || action === 'BLOCK')) {
            return this.createChallengeResult(request, country, reasons);
          }
          return this.createResult(action, this.getActionStatusCode(action, 403), 'Bot detected', request, {
            ruleId: 'BOT-ADV-001',
            severity: 'MEDIUM',
            reasons,
            geoCountry: country,
            threatScore,
          });
        }
      }
    }

    // 12. SQL Injection
    if (this.config.sqliEnabled) {
      const sqliResult = this.checkSqlInjection(request);
      if (sqliResult.detected) {
        reasons.push(`SQL_INJECTION:${sqliResult.pattern}`);
        threatScore += 90;
        return this.createResult(this.config.sqliAction, 403, 'SQL Injection detected', request, {
          ruleId: 'SQLI-001',
          severity: 'CRITICAL',
          reasons,
          geoCountry: country,
          threatScore,
        });
      }
    }

    // 13. XSS Protection
    if (this.config.xssEnabled) {
      const xssResult = this.checkXss(request);
      if (xssResult.detected) {
        reasons.push(`XSS:${xssResult.pattern}`);
        threatScore += 85;
        return this.createResult(this.config.xssAction, 403, 'XSS detected', request, {
          ruleId: 'XSS-001',
          severity: 'CRITICAL',
          reasons,
          geoCountry: country,
          threatScore,
        });
      }
    }

    // 14. CSRF Protection
    if (this.config.csrfEnabled && this.requiresCsrfToken(request)) {
      const csrfResult = this.checkCsrfToken(request);
      if (!csrfResult.valid) {
        reasons.push('CSRF_TOKEN_INVALID');
        return this.createResult('BLOCK', 403, 'Invalid CSRF token', request, {
          ruleId: 'CSRF-001',
          severity: 'HIGH',
          reasons,
          geoCountry: country,
          threatScore,
        });
      }
    }

    // Request passed all checks
    this.updateBehavioralProfile(request, country);

    return this.createResult('ALLOW', 200, 'Request allowed', request, {
      reasons,
      geoCountry: country,
      threatScore,
    });
  }

  // === IP Checks ===

  private isWhitelisted(ip: string): boolean {
    return this.config.ipWhitelist.some((pattern) => this.ipMatches(ip, pattern));
  }

  private isBlacklisted(ip: string): boolean {
    return this.config.ipBlacklist.some((pattern) => this.ipMatches(ip, pattern));
  }

  private hasBadReputation(ip: string): boolean {
    // Check local reputation store first
    if (ipReputationStore.has(ip)) return true;
    // Check open-source threat intel feeds
    const result = threatIntelService.lookup(ip);
    return result.found;
  }

  private ipMatches(ip: string, pattern: string): boolean {
    if (ip === pattern) return true;
    if (pattern.includes('/')) return this.ipInCidr(ip, pattern);
    if (pattern.includes('*')) {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '\d+') + '$');
      return regex.test(ip);
    }
    return false;
  }

  private ipInCidr(ip: string, cidr: string): boolean {
    const [range, bits] = cidr.split('/');
    const mask = parseInt(bits, 10);
    const ipParts = ip.split('.').map(Number);
    const rangeParts = range.split('.').map(Number);
    const ipNum = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
    const rangeNum = (rangeParts[0] << 24) | (rangeParts[1] << 16) | (rangeParts[2] << 8) | rangeParts[3];
    const maskNum = ~((1 << (32 - mask)) - 1);
    return (ipNum & maskNum) === (rangeNum & maskNum);
  }

  // === GeoIP ===

  private getGeoCountry(ip: string): string | undefined {
    if (geoIpCache.has(ip)) return geoIpCache.get(ip);
    // Skip private/local IPs
    if (ip === 'unknown' || ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('192.168.')) {
      geoIpCache.set(ip, 'LOCAL');
      return 'LOCAL';
    }
    const geo = geoip.lookup(ip);
    if (geo && geo.country) {
      geoIpCache.set(ip, geo.country);
      return geo.country;
    }
    return undefined;
  }

  // === Anonymous IP Detection ===

  private detectAnonymousIp(ip: string): 'TOR' | 'VPN' | 'PROXY' | 'HOSTING' | null {
    // Check TOR exit nodes (static list)
    if (KNOWN_TOR_EXIT_NODES.some((range) => this.ipInCidr(ip, range))) {
      return 'TOR';
    }

    // Check threat intel feeds for category-specific classification
    const intel = threatIntelService.lookup(ip);
    if (intel.found) {
      if (intel.categories.includes('tor')) return 'TOR';
      if (intel.categories.includes('proxy') || intel.categories.includes('vpn')) return 'PROXY';
      if (intel.categories.includes('botnet') || intel.categories.includes('malware')) return 'HOSTING';
    }

    return null;
  }

  // === HTTP Method Control ===

  private checkHttpMethod(method: string): { blocked: boolean; reason?: string } {
    const upperMethod = method.toUpperCase();

    if (this.config.blockedMethods.includes(upperMethod)) {
      return { blocked: true, reason: 'Method explicitly blocked' };
    }

    if (!this.config.allowedMethods.includes(upperMethod)) {
      return { blocked: true, reason: 'Method not in allowed list' };
    }

    return { blocked: false };
  }

  // === File Upload Protection ===

  private checkFileUpload(request: WAFRequest): { blocked: boolean; reason?: string } {
    if (!this.config.uploadEnabled) return { blocked: false };

    // Check if this is a multipart/form-data upload
    const contentType = request.headers['content-type'];
    if (typeof contentType === 'string' && contentType.includes('multipart/form-data')) {
      // Check file size from content-length header
      const contentLength = request.headers['content-length'];
      if (contentLength) {
        const size = parseInt(Array.isArray(contentLength) ? contentLength[0] : contentLength, 10);
        if (size > this.config.uploadMaxSize) {
          return { blocked: true, reason: 'File size exceeds limit' };
        }
      }

      // Check for blocked extensions in the body
      if (request.body) {
        const body = request.body.toLowerCase();
        for (const ext of this.config.uploadBlockedExtensions) {
          const normalizedExt = ext.replace(/^\./, '');
          if (body.includes(`filename="${ext}"`) ||
              body.includes(`filename="test.${normalizedExt}"`) ||
              body.includes(`filename="${normalizedExt}"`) ||
              new RegExp(`filename=\\"[^\\"]+\\.${normalizedExt}\\"`, 'i').test(request.body)) {
            return { blocked: true, reason: `Blocked file extension: ${ext}` };
          }
        }
      }
    }

    return { blocked: false };
  }

  // === Brute Force Protection ===

  private isBruteForceEndpoint(uri: string): boolean {
    return this.config.bruteForceEndpoints.some((endpoint) => uri.includes(endpoint));
  }

  private checkBruteForce(ip: string, endpoint: string): { locked: boolean } {
    const now = Date.now();
    const entry = bruteForceStore.get(ip);

    if (entry) {
      // Check if locked
      if (entry.locked && now < entry.lockExpiry) {
        return { locked: true };
      }

      // Check window expiry
      if (now - entry.firstAttempt > this.config.bruteForceWindow * 1000) {
        // Reset
        entry.attempts = 1;
        entry.firstAttempt = now;
        entry.locked = false;
        entry.endpointAttempts.set(endpoint, 1);
      } else {
        // Increment attempts
        entry.attempts++;
        const endpointCount = entry.endpointAttempts.get(endpoint) || 0;
        entry.endpointAttempts.set(endpoint, endpointCount + 1);

        // Check threshold
        if (entry.attempts >= this.config.bruteForceThreshold) {
          entry.locked = true;
          entry.lockExpiry = now + this.config.bruteForceBlockDuration * 1000;
          return { locked: true };
        }
      }
    } else {
      bruteForceStore.set(ip, {
        attempts: 1,
        firstAttempt: now,
        locked: false,
        lockExpiry: 0,
        endpointAttempts: new Map([[endpoint, 1]]),
      });
    }

    return { locked: false };
  }

  // === Rate Limiting ===

  private checkRateLimit(ip: string, request: WAFRequest): { exceeded: boolean } {
    const now = Date.now();
    const entry = rateLimitStore.get(ip);

    if (entry) {
      // Check burst
      if (now - entry.lastRequest < 1000) {
        entry.burstCount++;
      } else {
        entry.burstCount = 0;
      }

      // Check if window expired
      if (now - entry.firstRequest > this.config.rateLimitWindow * 1000) {
        entry.count = 1;
        entry.firstRequest = now;
        entry.burstCount = 0;
      } else {
        entry.count++;
      }

      entry.lastRequest = now;

      // Check rate limit
      if (entry.count > this.config.rateLimitRequests ||
          entry.burstCount > this.config.rateLimitBurst) {
        return { exceeded: true };
      }
    } else {
      rateLimitStore.set(ip, {
        count: 1,
        firstRequest: now,
        burstCount: 0,
        lastRequest: now,
        challengePassed: false,
        challengeExpiry: 0,
      });
    }

    return { exceeded: false };
  }

  // === Layer 7 DDoS Protection ===

  private checkDDoS(request: WAFRequest, country?: string): { detected: boolean; reason?: string } {
    const profile = this.getBehavioralProfile(request.clientIp);
    const now = Date.now();
    const windowStart = now - 60000; // 1 minute window

    // Filter requests in current window
    const recentRequests = profile.requests.filter((t) => t > windowStart);
    profile.requests = recentRequests;

    const requestCount = recentRequests.length;

    // Check threshold
    if (requestCount > this.config.ddosRequestThreshold) {
      return { detected: true, reason: `High request count: ${requestCount}` };
    }

    // Check burst multiplier
    if (requestCount > this.config.ddosRequestThreshold * this.config.ddosBurstMultiplier) {
      return { detected: true, reason: 'Burst detected' };
    }

    // Check geo anomaly
    if (this.config.ddosGeoAnomaly && country && profile.countries.size > 0) {
      if (!profile.countries.has(country)) {
        profile.anomalies++;
        if (profile.anomalies > 5) {
          return { detected: true, reason: 'Geographic anomaly' };
        }
      }
    }

    return { detected: false };
  }

  // === Bot Protection ===

  private checkBotProtection(request: WAFRequest, country?: string): { isBot: boolean; score: number; reason?: string } {
    const userAgent = request.userAgent || '';
    let score = 0;

    // Check user agent against known bot patterns
    for (const pattern of ADVANCED_BOT_PATTERNS) {
      if (pattern.test(userAgent)) {
        score += 50;
        return { isBot: true, score, reason: 'Known bot signature' };
      }
    }

    // Check for missing/short user agent
    if (!userAgent || userAgent.length < 20) {
      score += 20;
    }

    // Suspicious bot-like user agents
    if (/bot|crawler|spider|scanner|slurp|preview|httpclient/i.test(userAgent)) {
      score += 25;
      return { isBot: true, score, reason: 'Suspicious user agent' };
    }

    // Check for headless indicators
    if (this.config.botBlockHeadless) {
      if (/HeadlessChrome|PhantomJS|Selenium|Puppeteer|Playwright/i.test(userAgent)) {
        score += 40;
        return { isBot: true, score, reason: 'Headless browser' };
      }
    }

    // Check behavioral profile
    const profile = this.getBehavioralProfile(request.clientIp);
    const now = Date.now();
    const recentRequests = profile.requests.filter((t) => t > now - 60000);

    if (recentRequests.length > this.config.botRatePerMinute) {
      score += 30;
    }

    // Check for consistent timing (bot-like behavior)
    if (recentRequests.length >= 5) {
      const intervals: number[] = [];
      for (let i = 1; i < recentRequests.length; i++) {
        intervals.push(recentRequests[i] - recentRequests[i - 1]);
      }
      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance = intervals.reduce((sum, int) => sum + Math.pow(int - avgInterval, 2), 0) / intervals.length;

      // Low variance indicates bot behavior
      if (variance < 100) {
        score += 25;
      }
    }

    profile.botScore = score;

    return { isBot: score > 0, score, reason: score > 0 ? 'Behavioral analysis' : undefined };
  }

  // === SQL Injection ===

  private checkSqlInjection(request: WAFRequest): { detected: boolean; pattern?: string } {
    const patterns = SQLI_PATTERNS[this.config.sqliLevel];
    const fields = this.getAllInputFields(request);

    for (const field of fields) {
      if (!field) continue;
      for (const pattern of patterns) {
        if (pattern.test(field)) {
          return { detected: true, pattern: pattern.toString() };
        }
      }
    }

    return { detected: false };
  }

  // === XSS Protection ===

  private checkXss(request: WAFRequest): { detected: boolean; pattern?: string } {
    const patterns = XSS_PATTERNS[this.config.xssLevel];
    const fields = this.getAllInputFields(request);

    for (const field of fields) {
      if (!field) continue;
      for (const pattern of patterns) {
        if (pattern.test(field)) {
          return { detected: true, pattern: pattern.toString() };
        }
      }
    }

    return { detected: false };
  }

  // === CSRF Protection ===

  private requiresCsrfToken(request: WAFRequest): boolean {
    const methodsRequiringCsrf = ['POST', 'PUT', 'PATCH', 'DELETE'];
    if (!methodsRequiringCsrf.includes(request.method.toUpperCase())) return false;

    if (this.config.csrfEndpoints.length === 0) return this.config.csrfTokenRequired;

    return this.config.csrfEndpoints.some((endpoint) => request.uri.includes(endpoint));
  }

  private checkCsrfToken(request: WAFRequest): { valid: boolean } {
    const header = request.headers['x-csrf-token'] || request.headers['x-xsrf-token'];
    const cookie = request.headers['cookie'];

    // Basic check - in production would verify token matches session
    if (!header) {
      return { valid: false };
    }

    return { valid: true };
  }

  // === Challenge/CAPTCHA ===

  private getActionStatusCode(action: string, fallback: number): number {
    return action === 'ALLOW' || action === 'LOGGED' || action === 'LOG' ? 200 : fallback;
  }

  private hasValidChallenge(ip: string): boolean {
    const session = challengeStore.get(ip);
    if (!session) return false;

    if (session.passed && Date.now() < session.created + this.config.challengePassDuration * 1000) {
      return true;
    }

    return false;
  }

  private createChallengeResult(request: WAFRequest, country?: string, reasons: string[] = []): AdvancedWAFResult {
    const token = this.generateChallengeToken(request.clientIp);

    return {
      allowed: false,
      action: 'CHALLENGE_JS',
      statusCode: 403,
      message: 'Please complete the security challenge',
      challengeToken: token,
      challengeUrl: `/waf/challenge?token=${token}`,
      geoCountry: country,
      threatScore: 50,
      reasons,
      blockedReason: 'Challenge required',
    };
  }

  private generateChallengeToken(ip: string): string {
    const token = Buffer.from(`${ip}:${Date.now()}:${Math.random()}`).toString('base64');
    challengeStore.set(ip, {
      token,
      created: Date.now(),
      passed: false,
      ip,
      attempts: 0,
    });
    return token;
  }

  // === Result Creation ===

  private createResult(
    action: WAFAction,
    statusCode: number,
    message: string,
    request: WAFRequest,
    options: {
      ruleId?: string;
      severity?: string;
      reasons: string[];
      geoCountry?: string;
      threatScore?: number;
    }
  ): AdvancedWAFResult {
    return {
      allowed: action === 'ALLOW' || action === 'LOGGED' || action === 'LOG',
      action,
      statusCode,
      message,
      ruleId: options.ruleId,
      severity: options.severity,
      blockedReason: action !== 'ALLOW' ? options.reasons.join(', ') : undefined,
      reasons: options.reasons,
      geoCountry: options.geoCountry,
      threatScore: options.threatScore ?? 0,
    };
  }

  // === Helpers ===

  private getAllInputFields(request: WAFRequest): string[] {
    const fields: string[] = [
      request.uri,
      request.queryString || '',
      request.body || '',
      request.userAgent || '',
    ];

    Object.values(request.headers).forEach((val) => {
      if (Array.isArray(val)) {
        fields.push(...val);
      } else {
        fields.push(val);
      }
    });

    return fields;
  }

  private getBehavioralProfile(ip: string): BehavioralProfile {
    if (!behavioralStore.has(ip)) {
      behavioralStore.set(ip, {
        requests: [],
        userAgents: new Set(),
        countries: new Set(),
        endpoints: new Map(),
        anomalies: 0,
        botScore: 0,
        lastUpdated: Date.now(),
      });
    }
    return behavioralStore.get(ip)!;
  }

  private updateBehavioralProfile(request: WAFRequest, country?: string): void {
    const profile = this.getBehavioralProfile(request.clientIp);

    profile.requests.push(Date.now());
    if (request.userAgent) profile.userAgents.add(request.userAgent);
    if (country) profile.countries.add(country);

    const endpointCount = profile.endpoints.get(request.uri) || 0;
    profile.endpoints.set(request.uri, endpointCount + 1);
    profile.lastUpdated = Date.now();
  }

  // === Cleanup ===

  private startCleanupInterval(): void {
    // Cleanup old entries every 10 minutes
    setInterval(() => {
      const now = Date.now();
      const maxAge = 3600000; // 1 hour

      // Cleanup rate limit store
      for (const [ip, entry] of rateLimitStore.entries()) {
        if (now - entry.firstRequest > maxAge) {
          rateLimitStore.delete(ip);
        }
      }

      // Cleanup brute force store
      for (const [ip, entry] of bruteForceStore.entries()) {
        if (now - entry.firstAttempt > maxAge) {
          bruteForceStore.delete(ip);
        }
      }

      // Cleanup behavioral store
      for (const [ip, profile] of behavioralStore.entries()) {
        if (now - profile.lastUpdated > maxAge) {
          behavioralStore.delete(ip);
        }
      }

      // Cleanup challenge store
      for (const [ip, session] of challengeStore.entries()) {
        if (now - session.created > maxAge) {
          challengeStore.delete(ip);
        }
      }
    }, 600000);
  }

  // === Configuration ===

  public updateConfig(newConfig: Partial<AdvancedWAFConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  public getConfig(): AdvancedWAFConfig {
    return { ...this.config };
  }

  // === Logging ===

  public logRequest(request: WAFRequest, result: AdvancedWAFResult): void {
    if (!this.config.logAllRequests && result.allowed) return;
    if (this.config.logBlockedOnly && result.allowed) return;

    const logEntry = {
      timestamp: new Date().toISOString(),
      clientIp: request.clientIp,
      method: request.method,
      uri: request.uri,
      userAgent: this.config.logSensitiveData ? '[REDACTED]' : request.userAgent,
      action: result.action,
      allowed: result.allowed,
      statusCode: result.statusCode,
      ruleId: result.ruleId,
      severity: result.severity,
      reasons: result.reasons,
      geoCountry: result.geoCountry,
      threatScore: result.threatScore,
    };

    if (this.config.logFormat === 'JSON') {
      console.log(JSON.stringify(logEntry));
    } else {
      console.log(`[${logEntry.timestamp}] ${logEntry.clientIp} ${logEntry.method} ${logEntry.uri} - Action: ${logEntry.action} - Reasons: ${logEntry.reasons.join(',')}`);
    }
  }
}

export const advancedWafEngine = new AdvancedWAFEngine();
