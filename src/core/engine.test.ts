/**
 * WAF Engine Tests
 */

import { WAFEngine } from './engine';
import { WAFRequest } from './rules';

describe('WAFEngine', () => {
  let waf: WAFEngine;

  beforeEach(() => {
    waf = new WAFEngine({ mode: 'BLOCK' });
    waf.clearRateLimits();
  });

  function createRequest(overrides: Partial<WAFRequest> = {}): WAFRequest {
    return {
      method: 'GET',
      uri: '/',
      headers: {},
      clientIp: '192.168.1.1',
      timestamp: Date.now(),
      ...overrides,
    };
  }

  describe('SQL Injection', () => {
    it('should block SQL injection in query string', () => {
      const req = createRequest({
        uri: '/users',
        queryString: "id=1' OR '1'='1",
      });

      const result = waf.processRequest(req);

      expect(result.allowed).toBe(false);
      expect(result.ruleId).toBe('SQLI-001');
      expect(result.statusCode).toBe(403);
    });

    it('should block SQL injection in body', () => {
      const req = createRequest({
        method: 'POST',
        uri: '/login',
        body: JSON.stringify({ username: "admin'--" }),
      });

      const result = waf.processRequest(req);

      expect(result.allowed).toBe(false);
      expect(result.ruleId).toBe('SQLI-001');
    });

    it('should allow normal requests', () => {
      const req = createRequest({
        uri: '/users',
        queryString: 'id=123',
      });

      const result = waf.processRequest(req);

      expect(result.allowed).toBe(true);
    });
  });

  describe('XSS', () => {
    it('should block script tags', () => {
      const req = createRequest({
        uri: '/search',
        queryString: 'q=<script>alert(1)</script>',
      });

      const result = waf.processRequest(req);

      expect(result.allowed).toBe(false);
      expect(result.ruleId).toBe('XSS-001');
    });

    it('should block javascript: protocol', () => {
      const req = createRequest({
        uri: '/redirect',
        queryString: 'url=javascript:alert(1)',
      });

      const result = waf.processRequest(req);

      expect(result.allowed).toBe(false);
      expect(result.ruleId).toBe('XSS-001');
    });
  });

  describe('Path Traversal', () => {
    it('should block directory traversal', () => {
      const req = createRequest({
        uri: '/files/../../../etc/passwd',
      });

      const result = waf.processRequest(req);

      expect(result.allowed).toBe(false);
      expect(result.ruleId).toBe('PT-001');
    });

    it('should block encoded traversal', () => {
      const req = createRequest({
        uri: '/files/..%2f..%2fetc%2fpasswd',
      });

      const result = waf.processRequest(req);

      expect(result.allowed).toBe(false);
      expect(result.ruleId).toBe('PT-001');
    });
  });

  describe('Command Injection', () => {
    it('should block command injection', () => {
      const req = createRequest({
        method: 'POST',
        uri: '/exec',
        body: JSON.stringify({ cmd: 'ls -la; rm -rf /' }),
      });

      const result = waf.processRequest(req);

      expect(result.allowed).toBe(false);
      expect(result.ruleId).toBe('CMDI-001');
    });
  });

  describe('IP Whitelist/Blacklist', () => {
    it('should allow whitelisted IPs', () => {
      waf.updateConfig({ ipWhitelist: ['192.168.1.100'] });

      const req = createRequest({
        clientIp: '192.168.1.100',
        uri: '/users?id=1\' OR \'1\'=\'1',
      });

      const result = waf.processRequest(req);

      expect(result.allowed).toBe(true);
    });

    it('should block blacklisted IPs', () => {
      waf.updateConfig({ ipBlacklist: ['10.0.0.5'] });

      const req = createRequest({ clientIp: '10.0.0.5' });

      const result = waf.processRequest(req);

      expect(result.allowed).toBe(false);
      expect(result.ruleId).toBe('IP-001');
    });

    it('should support CIDR notation', () => {
      waf.updateConfig({ ipBlacklist: ['10.0.0.0/24'] });

      const req = createRequest({ clientIp: '10.0.0.50' });

      const result = waf.processRequest(req);

      expect(result.allowed).toBe(false);
    });
  });

  describe('Rate Limiting', () => {
    it('should block requests over rate limit', () => {
      waf.updateConfig({
        rateLimit: {
          enabled: true,
          windowMs: 60000,
          maxRequests: 5,
          blockDurationMs: 300000,
        },
      });

      // Make 6 requests
      for (let i = 0; i < 5; i++) {
        const result = waf.processRequest(createRequest());
        expect(result.allowed).toBe(true);
      }

      // 6th request should be blocked
      const result = waf.processRequest(createRequest());
      expect(result.allowed).toBe(false);
      expect(result.ruleId).toBe('RATE-001');
      expect(result.statusCode).toBe(429);
    });
  });

  describe('Operation Modes', () => {
    it('MONITOR mode should add headers but allow', () => {
      waf.updateConfig({ mode: 'MONITOR' });

      const req = createRequest({
        uri: '/users?id=1\' OR \'1\'=\'1',
      });

      const result = waf.processRequest(req);

      expect(result.allowed).toBe(true);
      expect(result.blockedReason).toContain('SQL Injection');
    });

    it('COUNT mode should log but allow', () => {
      waf.updateConfig({ mode: 'COUNT' });

      const req = createRequest({
        uri: '/users?id=1\' OR \'1\'=\'1',
      });

      const result = waf.processRequest(req);

      expect(result.allowed).toBe(true);
    });
  });

  describe('Bot Detection', () => {
    it('should block known malicious user agents', () => {
      const req = createRequest({
        headers: { 'user-agent': 'sqlmap/1.0' },
      });

      const result = waf.processRequest(req);

      expect(result.allowed).toBe(false);
      expect(result.ruleId).toBe('BOT-001');
    });
  });
});
