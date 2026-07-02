/**
 * WAF Rule Engine - OWASP Top 10 Protection
 * Core detection patterns and rules
 */

export interface WAFRule {
  id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  enabled: boolean;
  match: (request: WAFRequest) => RuleMatchResult;
}

export interface WAFRequest {
  method: string;
  uri: string;
  headers: Record<string, string | string[]>;
  queryString?: string;
  body?: string;
  clientIp: string;
  userAgent?: string;
  timestamp: number;
}

export interface RuleMatchResult {
  matched: boolean;
  reason?: string;
  matchedValue?: string;
}

export interface WAFResult {
  allowed: boolean;
  statusCode: number;
  message: string;
  ruleId?: string;
  severity?: string;
  blockedReason?: string;
}

// SQL Injection patterns
const SQLI_PATTERNS = [
  /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
  /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
  /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
  /((\%27)|(\'))union/i,
  /exec(\s|\+)+(s|x)p\w+/i,
  /UNION\s+SELECT/i,
  /INSERT\s+INTO/i,
  /DELETE\s+FROM/i,
  /DROP\s+TABLE/i,
  /script\s*>/i,
];

// XSS patterns
const XSS_PATTERNS = [
  /((\%3C)|<)[^\n]+((\%3E)|>)/i,
  /((\%3C)|<)\/script/i,
  /((\%3C)|<)\s*script\s*/i,
  /javascript:/i,
  /on\w+\s*=/i,
  /alert\s*\(/i,
  /document\.cookie/i,
  /<iframe/i,
  /<object/i,
  /<embed/i,
];

// Path traversal patterns
const PATH_TRAVERSAL_PATTERNS = [
  /\.\.\//,
  /\.\.\\/,
  /\.\.\/%2f/i,
  /%2e%2e%2f/i,
  /%252e%252e%252f/i,
  /\.\.\/%252f/i,
  /etc\/passwd/i,
  /etc\/shadow/i,
  /windows\/win\.ini/i,
  /boot\.ini/i,
];

// Command injection patterns
const CMD_INJECTION_PATTERNS = [
  /[;|`&$]+\s*\w+/i,
  /\b(cat|ls|pwd|whoami|id|uname|nc|netcat|wget|curl)\b/i,
  /`[^`]+`/,
  /\$\([^)]+\)/,
  /\|\s*(sh|bash|cmd|powershell)/i,
  /;\s*rm\s+/i,
  />\s*\//i,
];

// NoSQL injection patterns
const NOSQLI_PATTERNS = [
  /\$where:/i,
  /\$ne:/i,
  /\$gt:/i,
  /\$lt:/i,
  /\$regex:/i,
  /\$in:/i,
  /\{.*\$ne.*\}/i,
];

// File upload attack patterns
const FILE_UPLOAD_PATTERNS = [
  /\.php[0-9]*$/i,
  /\.asp[x]?$/i,
  /\.jsp[x]?$/i,
  /\.exe$/i,
  /\.sh$/i,
  /\.bat$/i,
  /\.cmd$/i,
  /\.ps1$/i,
];

// SSRF patterns
const SSRF_PATTERNS = [
  /http:\/\/169\.254\.169\.254/i,
  /http:\/\/localhost/i,
  /http:\/\/127\.\d+\.\d+\.\d+/i,
  /http:\/\/0\.0\.0\.0/i,
  /http:\/\/\[::1\]/i,
  /file:\/\//i,
  /gopher:\/\//i,
  /ftp:\/\//i,
];

// Bot/scanner user agents
const BAD_USER_AGENTS = [
  /sqlmap/i,
  /nikto/i,
  /nmap/i,
  /masscan/i,
  /zgrab/i,
  /gobuster/i,
  /dirbuster/i,
  /wfuzz/i,
  /burp/i,
  /metasploit/i,
  /nessus/i,
  /openvas/i,
];

function createPatternRule(
  id: string,
  name: string,
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
  description: string,
  patterns: RegExp[],
  checkFields: (req: WAFRequest) => string[]
): WAFRule {
  return {
    id,
    name,
    severity,
    description,
    enabled: true,
    match: (request: WAFRequest): RuleMatchResult => {
      const fields = checkFields(request);
      for (const field of fields) {
        if (!field) continue;
        for (const pattern of patterns) {
          if (pattern.test(field)) {
            return {
              matched: true,
              reason: `${name} detected`,
              matchedValue: field.substring(0, 100),
            };
          }
        }
      }
      return { matched: false };
    },
  };
}

function getAllInputFields(req: WAFRequest): string[] {
  const fields: string[] = [
    req.uri,
    req.queryString || '',
    req.body || '',
    req.userAgent || '',
  ];
  // Add all header values
  Object.values(req.headers).forEach((val) => {
    if (Array.isArray(val)) {
      fields.push(...val);
    } else {
      fields.push(val);
    }
  });
  return fields;
}

function getQueryAndBody(req: WAFRequest): string[] {
  return [req.queryString || '', req.body || ''];
}

// Define all WAF rules
export const WAF_RULES: WAFRule[] = [
  // SQL Injection
  createPatternRule(
    'SQLI-001',
    'SQL Injection',
    'CRITICAL',
    'Detects SQL injection attempts',
    SQLI_PATTERNS,
    getAllInputFields
  ),

  // XSS
  createPatternRule(
    'XSS-001',
    'Cross-Site Scripting',
    'CRITICAL',
    'Detects XSS attack patterns',
    XSS_PATTERNS,
    getAllInputFields
  ),

  // Path Traversal
  createPatternRule(
    'PT-001',
    'Path Traversal',
    'HIGH',
    'Detects directory traversal attempts',
    PATH_TRAVERSAL_PATTERNS,
    getAllInputFields
  ),

  // Command Injection
  createPatternRule(
    'CMDI-001',
    'Command Injection',
    'CRITICAL',
    'Detects command injection attempts',
    CMD_INJECTION_PATTERNS,
    getAllInputFields
  ),

  // NoSQL Injection
  createPatternRule(
    'NOSQLI-001',
    'NoSQL Injection',
    'CRITICAL',
    'Detects NoSQL injection attempts',
    NOSQLI_PATTERNS,
    getQueryAndBody
  ),

  // SSRF
  createPatternRule(
    'SSRF-001',
    'Server-Side Request Forgery',
    'HIGH',
    'Detects SSRF attempts',
    SSRF_PATTERNS,
    getAllInputFields
  ),

  // Bad User Agents
  {
    id: 'BOT-001',
    name: 'Malicious Scanner/Bot',
    severity: 'MEDIUM',
    description: 'Blocks known malicious scanners and bots',
    enabled: true,
    match: (request: WAFRequest): RuleMatchResult => {
      const ua = request.userAgent || '';
      for (const pattern of BAD_USER_AGENTS) {
        if (pattern.test(ua)) {
          return {
            matched: true,
            reason: 'Malicious scanner detected',
            matchedValue: ua,
          };
        }
      }
      return { matched: false };
    },
  },

  // Method validation
  {
    id: 'METH-001',
    name: 'Invalid HTTP Method',
    severity: 'MEDIUM',
    description: 'Blocks invalid or dangerous HTTP methods',
    enabled: true,
    match: (request: WAFRequest): RuleMatchResult => {
      const validMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
      if (!validMethods.includes(request.method.toUpperCase())) {
        return {
          matched: true,
          reason: `Invalid method: ${request.method}`,
        };
      }
      return { matched: false };
    },
  },

  // Content-Type validation for POST/PUT
  {
    id: 'CT-001',
    name: 'Missing Content-Type',
    severity: 'LOW',
    description: 'Warns on POST/PUT without Content-Type',
    enabled: false, // Disabled by default - can be noisy
    match: (request: WAFRequest): RuleMatchResult => {
      const methodsRequiringContentType = ['POST', 'PUT', 'PATCH'];
      if (methodsRequiringContentType.includes(request.method.toUpperCase())) {
        const contentType = request.headers['content-type'];
        if (!contentType) {
          return {
            matched: true,
            reason: 'POST/PUT without Content-Type header',
          };
        }
      }
      return { matched: false };
    },
  },

  // Null byte injection
  createPatternRule(
    'NULL-001',
    'Null Byte Injection',
    'HIGH',
    'Detects null byte injection attempts',
    [/%00/, /\x00/],
    getAllInputFields
  ),
];

// Default rules that are active
export const DEFAULT_ACTIVE_RULES = [
  'SQLI-001',
  'XSS-001',
  'PT-001',
  'CMDI-001',
  'NOSQLI-001',
  'SSRF-001',
  'BOT-001',
  'METH-001',
  'NULL-001',
];
