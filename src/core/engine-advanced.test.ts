/**
 * Advanced WAF Engine Tests
 * Comprehensive test suite for all protection features
 */

import { AdvancedWAFEngine, AdvancedWAFResult } from './engine-advanced';
import { AdvancedWAFConfig, DEFAULT_ADVANCED_CONFIG } from './rules-advanced';

describe('AdvancedWAFEngine', () => {
  let waf: AdvancedWAFEngine;

  beforeEach(() => {
    waf = new AdvancedWAFEngine();
  });

  function createRequest(overrides: any = {}): any {
    return {
      method: 'GET',
      uri: '/',
      headers: {},
      queryString: '',
      body: '',
      clientIp: '192.168.1.100',
      userAgent: 'Mozilla/5.0 (compatible; Test/1.0)',
      timestamp: Date.now(),
      ...overrides,
    };
  }

  describe('IP Whitelist/Blacklist', () => {
    it('should allow whitelisted IPs', async () => {
      waf.updateConfig({ ipWhitelist: ['192.168.1.100'] });

      const req = createRequest({ clientIp: '192.168.1.100' });
      const result = await waf.processRequest(req);

      expect(result.action).toBe('ALLOW');
    });

    it('should block blacklisted IPs', async () => {
      waf.updateConfig({ ipBlacklist: ['10.0.0.5'] });

      const req = createRequest({ clientIp: '10.0.0.5' });
      const result = await waf.processRequest(req);

      expect(result.action).toBe('BLOCK');
      expect(result.reasons).toContain('IP_BLACKLIST');
    });

    it('should support CIDR notation', async () => {
      waf.updateConfig({ ipBlacklist: ['192.168.0.0/24'] });

      const req = createRequest({ clientIp: '192.168.0.50' });
      const result = await waf.processRequest(req);

      expect(result.action).toBe('BLOCK');
    });
  });

  describe('GeoIP Filtering', () => {
    it('should block requests from blacklisted countries', async () => {
      waf.updateConfig({ geoBlacklist: ['CN'], anonymousIpAction: 'BLOCK' });

      const req = createRequest({ geoCountry: 'CN' });
      const result = await waf.processRequest(req);

      expect(result.action).toBe('BLOCK');
      expect(result.reasons).toContain('GEO_BLACKLIST:CN');
    });

    it('should challenge requests from geo-challenge countries', async () => {
      waf.updateConfig({
        geoChallenge: ['XX'],
        anonymousIpAction: 'CHALLENGE_JS'
      });

      const req = createRequest({ geoCountry: 'XX' });
      const result = await waf.processRequest(req);

      expect(result.action).toBe('CHALLENGE_JS');
    });
  });

  describe('HTTP Method Control', () => {
    it('should block forbidden HTTP methods', async () => {
      waf.updateConfig({ blockedMethods: ['TRACE'] });

      const req = createRequest({ method: 'TRACE' });
      const result = await waf.processRequest(req);

      expect(result.action).toBe('BLOCK');
      expect(result.reasons).toContain('METHOD_BLOCKED:TRACE');
    });
  });

  describe('Managed rule actions', () => {
    it('should honor configured geo restriction action for selected countries', async () => {
      waf.updateConfig({
        geoRestrictionEnabled: true,
        geoRestrictionCountries: ['CN'],
        geoRestrictionAction: 'LOGGED',
      });

      const req = createRequest({ geoCountry: 'CN' });
      const result = await waf.processRequest(req);

      expect(result.action).toBe('LOGGED');
      expect(result.allowed).toBe(true);
      expect(result.reasons).toContain('GEO_BLACKLIST:CN');
    });

    it('should honor configured bot protection action for managed bots', async () => {
      waf.updateConfig({
        botProtectionEnabled: true,
        botProtectionLevel: 'HIGH',
        botProtectionAction: 'LOGGED',
      });

      const req = createRequest({ userAgent: 'sqlmap/1.0' });
      const result = await waf.processRequest(req);

      expect(result.action).toBe('LOGGED');
      expect(result.allowed).toBe(true);
    });

    it('should block methods not in allowed list', async () => {
      const req = createRequest({ method: 'INVALID' });
      const result = await waf.processRequest(req);

      expect(result.action).toBe('BLOCK');
    });
  });

  describe('SQL Injection Protection', () => {
    it('should block SQL injection in query string', async () => {
      const req = createRequest({
        uri: '/users',
        queryString: "id=1' OR '1'='1",
      });

      const result = await waf.processRequest(req);

      expect(result.action).toBe('BLOCK');
      expect(result.reasons.some(r => r.includes('SQL_INJECTION'))).toBe(true);
    });

    it('should block SQL injection in body', async () => {
      const req = createRequest({
        method: 'POST',
        body: "{\"username\": \"admin'--\"}",
      });

      const result = await waf.processRequest(req);

      expect(result.action).toBe('BLOCK');
    });

    it('should use different detection levels', async () => {
      waf.updateConfig({ sqliLevel: 'STRICT' });

      // More aggressive detection in STRICT mode
      const req = createRequest({
        queryString: "q=1 UNION SELECT * FROM users",
      });

      const result = await waf.processRequest(req);
      expect(result.action).toBe('BLOCK');
    });
  });

  describe('XSS Protection', () => {
    it('should block script tags', async () => {
      const req = createRequest({
        queryString: 'q=<script>alert(1)</script>',
      });

      const result = await waf.processRequest(req);

      expect(result.action).toBe('BLOCK');
      expect(result.reasons.some(r => r.includes('XSS'))).toBe(true);
    });

    it('should block javascript: protocol', async () => {
      const req = createRequest({
        queryString: 'url=javascript:alert(1)',
      });

      const result = await waf.processRequest(req);

      expect(result.action).toBe('BLOCK');
    });
  });

  describe('Bot Protection', () => {
    it('should detect known bad bots', async () => {
      const req = createRequest({
        userAgent: 'sqlmap/1.0',
      });

      const result = await waf.processRequest(req);

      // Should trigger bot detection
      expect(result.threatScore).toBeGreaterThan(0);
    });

    it('should challenge suspicious user agents', async () => {
      waf.updateConfig({
        botProtectionLevel: 'HIGH',
        botJsChallenge: true,
      });

      const req = createRequest({
        userAgent: 'Mozilla/5.0 (compatible; SomeBot/1.0)',
        headers: {
          'accept': '*/*',
          'accept-language': '',
        },
      });

      const result = await waf.processRequest(req);

      // High level should be more aggressive
      expect(result.threatScore).toBeGreaterThan(0);
    });
  });

  describe('Rate Limiting', () => {
    it('should block requests exceeding rate limit', async () => {
      waf.updateConfig({
        rateLimitEnabled: true,
        rateLimitRequests: 5,
        rateLimitWindow: 60,
        rateLimitBurst: 5,
      });

      const ip = '192.168.1.200';

      // Make 6 requests
      for (let i = 0; i < 5; i++) {
        const req = createRequest({ clientIp: ip });
        const result = await waf.processRequest(req);
        expect(result.action).toBe('ALLOW');
      }

      // 6th request should be rate limited
      const req = createRequest({ clientIp: ip });
      const result = await waf.processRequest(req);

      expect(result.action).toBe('RATE_LIMIT');
      expect(result.reasons).toContain('RATE_LIMIT_EXCEEDED');
    });
  });

  describe('Brute Force Protection', () => {
    it('should detect brute force attempts', async () => {
      waf.updateConfig({
        bruteForceEnabled: true,
        bruteForceThreshold: 3,
        bruteForceWindow: 300,
        bruteForceEndpoints: ['/login'],
      });

      const ip = '192.168.1.201';

      // Simulate 3 requests to /login
      for (let i = 0; i < 2; i++) {
        const req = createRequest({ clientIp: ip, uri: '/login' });
        const result = await waf.processRequest(req);
        expect(result.action).toBe('ALLOW');
      }

      // 3rd request should trigger brute force protection
      const req = createRequest({ clientIp: ip, uri: '/login' });
      const result = await waf.processRequest(req);

      expect(result.action).toBe('BLOCK');
      expect(result.reasons).toContain('BRUTE_FORCE_PROTECTION');
    });
  });

  describe('File Upload Protection', () => {
    it('should block dangerous file extensions', async () => {
      const req = createRequest({
        method: 'POST',
        headers: {
          'content-type': 'multipart/form-data; boundary=----WebKitFormBoundary',
          'content-length': '1000',
        },
        body: '------WebKitFormBoundary\r\nContent-Disposition: form-data; name="file"; filename="test.php"\r\n\r\ncontent\r\n------WebKitFormBoundary--',
      });

      const result = await waf.processRequest(req);

      expect(result.action).toBe('BLOCK');
      expect(result.reasons.some(r => r.includes('UPLOAD_BLOCKED'))).toBe(true);
    });
  });

  describe('CSRF Protection', () => {
    it('should require CSRF token on protected endpoints', async () => {
      waf.updateConfig({
        csrfEnabled: true,
        csrfTokenRequired: true,
        csrfEndpoints: ['/api/update'],
      });

      const req = createRequest({
        method: 'POST',
        uri: '/api/update',
        headers: {},
      });

      const result = await waf.processRequest(req);

      expect(result.action).toBe('BLOCK');
      expect(result.reasons).toContain('CSRF_TOKEN_INVALID');
    });
  });

  describe('DDoS Protection', () => {
    it('should detect high request rates', async () => {
      waf.updateConfig({
        ddosEnabled: true,
        ddosRequestThreshold: 10,
        ddosBurstMultiplier: 2,
      });

      const ip = '192.168.1.202';

      // Simulate many rapid requests
      for (let i = 0; i < 15; i++) {
        const req = createRequest({
          clientIp: ip,
          timestamp: Date.now(),
        });
        await waf.processRequest(req);
      }

      // Next request should trigger DDoS protection
      const req = createRequest({ clientIp: ip });
      const result = await waf.processRequest(req);

      expect(result.reasons.some(r => r.includes('DDOS'))).toBe(true);
    });
  });

  describe('Threat Scoring', () => {
    it('should calculate threat scores', async () => {
      const req = createRequest({
        queryString: "id=1' OR '1'='1",
      });

      const result = await waf.processRequest(req);

      expect(result.threatScore).toBeGreaterThan(50);
    });

    it('should return low score for normal requests', async () => {
      const req = createRequest({
        uri: '/api/users',
        queryString: 'page=1',
      });

      const result = await waf.processRequest(req);

      expect(result.action).toBe('ALLOW');
      expect(result.threatScore).toBe(0);
    });
  });

  describe('Logging', () => {
    it('should log blocked requests', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

      const req = createRequest({
        queryString: "q=1' OR '1'='1",
      });

      waf.logRequest(req, {
        action: 'BLOCK',
        allowed: false,
        statusCode: 403,
        message: 'Blocked',
        reasons: ['SQL_INJECTION'],
        threatScore: 90,
      } as AdvancedWAFResult);

      expect(consoleSpy).toHaveBeenCalled();

      consoleSpy.mockRestore();
    });
  });

  describe('Configuration Updates', () => {
    it('should support dynamic configuration updates', () => {
      const newConfig: Partial<AdvancedWAFConfig> = { sqliLevel: 'STRICT' };
      waf.updateConfig(newConfig);

      const config = waf.getConfig();
      expect(config.sqliLevel).toBe('STRICT');
    });
  });
});
