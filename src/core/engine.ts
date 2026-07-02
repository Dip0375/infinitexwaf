/**
 * WAF Core Engine - Request processing and rule evaluation
 */

import { WAFRequest, WAFResult, WAF_RULES, DEFAULT_ACTIVE_RULES, WAFRule } from './rules';

export interface RateLimitConfig {
  enabled: boolean;
  windowMs: number;
  maxRequests: number;
  blockDurationMs: number;
}

export interface WAFConfig {
  mode: 'BLOCK' | 'MONITOR' | 'COUNT';
  rules: string[]; // Rule IDs to enable
  rateLimit: RateLimitConfig;
  ipBlacklist: string[];
  ipWhitelist: string[];
  geoBlacklist: string[];
  customRules?: WAFRule[];
}

export const DEFAULT_CONFIG: WAFConfig = {
  mode: 'BLOCK',
  rules: DEFAULT_ACTIVE_RULES,
  rateLimit: {
    enabled: true,
    windowMs: 60000, // 1 minute
    maxRequests: 100,
    blockDurationMs: 300000, // 5 minutes
  },
  ipBlacklist: [],
  ipWhitelist: [],
  geoBlacklist: [],
};

// Simple in-memory rate limiting store
// In production, use Redis or DynamoDB for distributed deployments
interface RateLimitEntry {
  count: number;
  firstRequest: number;
  blocked: boolean;
  blockExpires: number;
}

const rateLimitStore = new Map<string, RateLimitEntry>();

export class WAFEngine {
  private config: WAFConfig;
  private activeRules: WAFRule[];

  constructor(config: Partial<WAFConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.activeRules = this.loadRules();
  }

  private loadRules(): WAFRule[] {
    const customRules = this.config.customRules || [];
    const builtInRules = WAF_RULES.filter((rule) =>
      this.config.rules.includes(rule.id)
    );
    return [...builtInRules, ...customRules];
  }

  /**
   * Process a request through the WAF
   */
  public processRequest(request: WAFRequest): WAFResult {
    // Check IP whitelist first
    if (this.isWhitelisted(request.clientIp)) {
      return {
        allowed: true,
        statusCode: 200,
        message: 'Request allowed (whitelisted)',
      };
    }

    // Check IP blacklist
    if (this.isBlacklisted(request.clientIp)) {
      return this.createBlockResult('IP-001', 'Blacklisted IP', 'HIGH');
    }

    // Check rate limiting
    if (this.config.rateLimit.enabled) {
      const rateLimitResult = this.checkRateLimit(request.clientIp);
      if (rateLimitResult) {
        return rateLimitResult;
      }
    }

    // Run security rules
    for (const rule of this.activeRules) {
      if (!rule.enabled) continue;

      try {
        const match = rule.match(request);
        if (match.matched) {
          return this.createBlockResult(rule.id, match.reason || rule.name, rule.severity);
        }
      } catch (error) {
        console.error(`Rule ${rule.id} error:`, error);
      }
    }

    // Request passed all checks
    return {
      allowed: true,
      statusCode: 200,
      message: 'Request allowed',
    };
  }

  /**
   * Check if an IP is whitelisted
   */
  private isWhitelisted(ip: string): boolean {
    return this.config.ipWhitelist.some((pattern) =>
      this.ipMatches(ip, pattern)
    );
  }

  /**
   * Check if an IP is blacklisted
   */
  private isBlacklisted(ip: string): boolean {
    return this.config.ipBlacklist.some((pattern) =>
      this.ipMatches(ip, pattern)
    );
  }

  /**
   * Check if IP matches a pattern (supports CIDR notation)
   */
  private ipMatches(ip: string, pattern: string): boolean {
    // Direct match
    if (ip === pattern) return true;

    // CIDR match
    if (pattern.includes('/')) {
      return this.ipInCidr(ip, pattern);
    }

    // Wildcard match (e.g., "192.168.1.*")
    if (pattern.includes('*')) {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '\\d+') + '$');
      return regex.test(ip);
    }

    return false;
  }

  /**
   * Check if IP is in CIDR range
   */
  private ipInCidr(ip: string, cidr: string): boolean {
    const [range, bits] = cidr.split('/');
    const mask = parseInt(bits, 10);
    const ipParts = ip.split('.').map(Number);
    const rangeParts = range.split('.').map(Number);

    const ipNum = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
    const rangeNum =
      (rangeParts[0] << 24) | (rangeParts[1] << 16) | (rangeParts[2] << 8) | rangeParts[3];
    const maskNum = ~((1 << (32 - mask)) - 1);

    return (ipNum & maskNum) === (rangeNum & maskNum);
  }

  /**
   * Check rate limiting for an IP
   */
  private checkRateLimit(ip: string): WAFResult | null {
    const now = Date.now();
    const entry = rateLimitStore.get(ip);

    if (entry) {
      // Check if still blocked
      if (entry.blocked) {
        if (now < entry.blockExpires) {
          return this.createBlockResult(
            'RATE-001',
            'Rate limit exceeded',
            'MEDIUM',
            429
          );
        } else {
          // Unblock
          entry.blocked = false;
          entry.count = 0;
        }
      }

      // Check if window expired
      if (now - entry.firstRequest > this.config.rateLimit.windowMs) {
        entry.count = 1;
        entry.firstRequest = now;
      } else {
        entry.count++;

        // Check if over limit
        if (entry.count > this.config.rateLimit.maxRequests) {
          entry.blocked = true;
          entry.blockExpires = now + this.config.rateLimit.blockDurationMs;
          return this.createBlockResult(
            'RATE-001',
            'Rate limit exceeded',
            'MEDIUM',
            429
          );
        }
      }
    } else {
      rateLimitStore.set(ip, {
        count: 1,
        firstRequest: now,
        blocked: false,
        blockExpires: 0,
      });
    }

    return null;
  }

  /**
   * Create a block result based on mode
   */
  private createBlockResult(
    ruleId: string,
    reason: string,
    severity: string,
    statusCode: number = 403
  ): WAFResult {
    switch (this.config.mode) {
      case 'COUNT':
        // Log but allow
        console.log(`[WAF COUNT] Rule ${ruleId}: ${reason} (${severity})`);
        return {
          allowed: true,
          statusCode: 200,
          message: 'Request allowed (COUNT mode)',
          ruleId,
          severity,
        };

      case 'MONITOR':
        // Add header but allow
        return {
          allowed: true,
          statusCode: 200,
          message: 'Request allowed (MONITOR mode)',
          ruleId,
          severity,
          blockedReason: `${ruleId}: ${reason}`,
        };

      case 'BLOCK':
      default:
        return {
          allowed: false,
          statusCode,
          message: 'Request blocked',
          ruleId,
          severity,
          blockedReason: `${ruleId}: ${reason}`,
        };
    }
  }

  /**
   * Update configuration
   */
  public updateConfig(newConfig: Partial<WAFConfig>): void {
    this.config = { ...this.config, ...newConfig };
    this.activeRules = this.loadRules();
  }

  /**
   * Get current configuration
   */
  public getConfig(): WAFConfig {
    return { ...this.config };
  }

  /**
   * Clear rate limit store (for testing)
   */
  public clearRateLimits(): void {
    rateLimitStore.clear();
  }
}

// Export singleton instance
export const wafEngine = new WAFEngine();
