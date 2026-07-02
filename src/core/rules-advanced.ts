/**
 * Advanced WAF Rules Engine
 * Comprehensive security policies with multiple action types
 */

import { WAFRequest, WAFRule, RuleMatchResult, WAFResult } from './rules';

export type WAFAction =
  | 'ALLOW'
  | 'BLOCK'
  | 'LOG'
  | 'LOGGED'
  | 'CAPTCHA'
  | 'CHALLENGE_JS'
  | 'RATE_LIMIT'
  | 'DROP'
  | 'REDIRECT';

export interface AdvancedWAFConfig {
  // GeoIP
  geoBlacklist: string[]; // Country codes: 'CN', 'RU', etc.
  geoWhitelist: string[];
  geoChallenge: string[]; // Countries requiring CAPTCHA
  geoRestrictionEnabled: boolean;
  geoRestrictionCountries: string[];
  geoRestrictionAction: WAFAction;

  // IP Sets
  ipWhitelist: string[]; // Supports CIDR: '10.0.0.0/24'
  ipBlacklist: string[];
  ipReputationBlock: boolean; // Block known bad IPs
  ipReputationAction: WAFAction;

  // Rate Limiting
  rateLimitEnabled: boolean;
  rateLimitRequests: number; // Requests per window
  rateLimitWindow: number; // Window in seconds
  rateLimitBurst: number; // Burst tolerance
  rateLimitAction: WAFAction;

  // Brute Force Protection
  bruteForceEnabled: boolean;
  bruteForceThreshold: number; // Failed attempts before block
  bruteForceWindow: number; // Window in seconds
  bruteForceBlockDuration: number; // Block duration in seconds
  bruteForceEndpoints: string[]; // Sensitive endpoints: ['/login', '/admin']
  adminProtectionAction: WAFAction;

  // HTTP Method Control
  allowedMethods: string[];
  blockedMethods: string[];
  methodAction: WAFAction;

  // File Upload Protection
  uploadEnabled: boolean;
  uploadMaxSize: number; // Bytes
  uploadAllowedExtensions: string[];
  uploadBlockedExtensions: string[];
  uploadScanContent: boolean; // Basic content scanning
  uploadMimeTypeValidation: boolean;
  uploadAction: WAFAction;

  // Anonymous IP Protection
  blockTor: boolean;
  blockVpn: boolean;
  blockProxy: boolean;
  blockHosting: boolean; // Block cloud/hosting providers
  anonymousIpAction: WAFAction;

  // Advanced Bot Protection
  botProtectionEnabled: boolean;
  botProtectionAction: WAFAction;
  botProtectionLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'AGGRESSIVE';
  botJsChallenge: boolean; // JavaScript challenge for suspicious bots
  botFingerprint: boolean; // Browser fingerprinting
  botBehavioral: boolean; // Behavioral analysis
  botBlockHeadless: boolean; // Block headless browsers
  botRatePerMinute: number; // Max requests per minute for bots

  // Layer 7 DDoS Protection
  ddosEnabled: boolean;
  ddosRequestThreshold: number; // Requests per second threshold
  ddosBurstMultiplier: number; // Multiplier for burst detection
  ddosBlockDuration: number; // Block duration
  ddosChallengeMode: boolean; // Use challenges instead of blocks
  ddosGeoAnomaly: boolean; // Detect geographic anomalies
  ddosUAAnomaly: boolean; // Detect user agent anomalies

  // SQL Injection (Enhanced)
  sqliEnabled: boolean;
  sqliAction: WAFAction;
  sqliLevel: 'BASIC' | 'MODERATE' | 'STRICT';

  // XSS Protection
  xssEnabled: boolean;
  xssAction: WAFAction;
  xssLevel: 'BASIC' | 'MODERATE' | 'STRICT';

  // CSRF Protection
  csrfEnabled: boolean;
  csrfTokenRequired: boolean;
  csrfEndpoints: string[]; // Endpoints requiring CSRF tokens

  // Logging
  logAllRequests: boolean;
  logBlockedOnly: boolean;
  logFormat: 'JSON' | 'COMMON' | 'COMBINED';
  logSensitiveData: boolean; // Mask sensitive data in logs

  // Challenge/CAPTCHA
  captchaProvider: 'RECAPTCHA_V2' | 'RECAPTCHA_V3' | 'HCAPTCHA' | 'CUSTOM';
  captchaSiteKey?: string;
  captchaSecretKey?: string;
  challengePassDuration: number; // How long challenge passes last (seconds)
}

export const DEFAULT_ADVANCED_CONFIG: AdvancedWAFConfig = {
  // GeoIP
  geoBlacklist: [],
  geoWhitelist: [],
  geoChallenge: [],
  geoRestrictionEnabled: true,
  geoRestrictionCountries: [],
  geoRestrictionAction: 'BLOCK',

  // IP Sets
  ipWhitelist: ['127.0.0.1/32'],
  ipBlacklist: [],
  ipReputationBlock: true,
  ipReputationAction: 'BLOCK',

  // Rate Limiting
  rateLimitEnabled: true,
  rateLimitRequests: 100,
  rateLimitWindow: 60,
  rateLimitBurst: 150,
  rateLimitAction: 'BLOCK',

  // Brute Force
  bruteForceEnabled: true,
  bruteForceThreshold: 5,
  bruteForceWindow: 300,
  bruteForceBlockDuration: 3600,
  bruteForceEndpoints: ['/login', '/auth', '/admin', '/wp-login.php', '/api/auth'],
  adminProtectionAction: 'BLOCK',

  // HTTP Methods
  allowedMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'],
  blockedMethods: ['TRACE', 'TRACK', 'CONNECT', 'PROPFIND', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'PURGE'],
  methodAction: 'BLOCK',

  // File Upload
  uploadEnabled: true,
  uploadMaxSize: 10 * 1024 * 1024, // 10MB
  uploadAllowedExtensions: ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx', '.txt'],
  uploadBlockedExtensions: ['.php', '.php3', '.php4', '.php5', '.phtml', '.asp', '.aspx', '.jsp', '.jspx', '.war', '.jar', '.sh', '.bash', '.exe', '.dll', '.bat', '.cmd', '.ps1', '.py', '.rb', '.pl'],
  uploadScanContent: true,
  uploadMimeTypeValidation: true,
  uploadAction: 'BLOCK',

  // Anonymous IPs
  blockTor: false,
  blockVpn: false,
  blockProxy: false,
  blockHosting: false,
  anonymousIpAction: 'CHALLENGE_JS',

  // Bot Protection
  botProtectionEnabled: true,
  botProtectionAction: 'BLOCK',
  botProtectionLevel: 'MEDIUM',
  botJsChallenge: true,
  botFingerprint: true,
  botBehavioral: true,
  botBlockHeadless: false,
  botRatePerMinute: 60,

  // DDoS Protection
  ddosEnabled: true,
  ddosRequestThreshold: 1000,
  ddosBurstMultiplier: 3,
  ddosBlockDuration: 300,
  ddosChallengeMode: true,
  ddosGeoAnomaly: true,
  ddosUAAnomaly: true,

  // SQL Injection
  sqliEnabled: true,
  sqliAction: 'BLOCK',
  sqliLevel: 'MODERATE',

  // XSS
  xssEnabled: true,
  xssAction: 'BLOCK',
  xssLevel: 'MODERATE',

  // CSRF
  csrfEnabled: false,
  csrfTokenRequired: false,
  csrfEndpoints: [],

  // Logging
  logAllRequests: false,
  logBlockedOnly: true,
  logFormat: 'JSON',
  logSensitiveData: false,

  // CAPTCHA
  captchaProvider: 'RECAPTCHA_V3',
  challengePassDuration: 3600,
};

// Known TOR exit nodes (subset - in production, sync from official list)
const KNOWN_TOR_EXIT_NODES: string[] = [
  '185.220.101.0/24',
  '199.249.230.0/24',
  '162.247.72.0/24',
  '51.15.0.0/16',
  '185.220.100.0/24',
];

// Known VPN/Proxy ranges (common public VPN providers)
const KNOWN_VPN_RANGES: string[] = [
  '10.0.0.0/8',     // Example - would need real data
];

// Known cloud/hosting provider ranges for blocking (suspicious traffic sources)
const HOSTING_PROVIDER_RANGES: string[] = [
  // These would be populated with actual hosting provider IP ranges
];

// Advanced SQL Injection patterns by level
const SQLI_PATTERNS = {
  BASIC: [
    /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
    /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
    /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
    /UNION\s+SELECT/i,
    /INSERT\s+INTO/i,
    /DELETE\s+FROM/i,
    /DROP\s+TABLE/i,
  ],
  MODERATE: [
    /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
    /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
    /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
    /UNION\s+SELECT/i,
    /INSERT\s+INTO/i,
    /DELETE\s+FROM/i,
    /DROP\s+TABLE/i,
    /exec\s*\(/i,
    /EXEC\s*\(/i,
    /SELECT\s+.*\s+FROM/i,
    /UPDATE\s+.*\s+SET/i,
    /(\b|\s)OR\s+\d+=\d+/i,
  ],
  STRICT: [
    // All MODERATE patterns plus:
    /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
    /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
    /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i,
    /UNION\s+SELECT/i,
    /INSERT\s+INTO/i,
    /DELETE\s+FROM/i,
    /DROP\s+TABLE/i,
    /exec\s*\(/i,
    /EXEC\s*\(/i,
    /SELECT\s+.*\s+FROM/i,
    /UPDATE\s+.*\s+SET/i,
    /(\b|\s)OR\s+\d+=\d+/i,
    /\bsleep\s*\(/i,
    /\bbenchmark\s*\(/i,
    /\bpg_sleep\s*\(/i,
    /WAITFOR\s+DELAY/i,
    /\bload_file\s*\(/i,
    /\boutfile\s+/i,
    /\bdumpfile\s+/i,
    /\binformation_schema\b/i,
    /\bsysobjects\b/i,
    /\bsyscolumns\b/i,
    /\binto\s+outfile/i,
    /\binto\s+dumpfile/i,
    /\bunion\s+select\s+.*\s+from\s+information_schema/i,
  ],
};

// XSS patterns by level
const XSS_PATTERNS = {
  BASIC: [
    /<script[^>]*>.*?<\/script>/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /<iframe/i,
    /<object/i,
  ],
  MODERATE: [
    /<script[^>]*>.*?<\/script>/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /<iframe/i,
    /<object/i,
    /<embed/i,
    /data:text\/html/i,
    /alert\s*\(/i,
    /confirm\s*\(/i,
    /prompt\s*\(/i,
    /document\.cookie/i,
    /document\.location/i,
    /window\.location/i,
  ],
  STRICT: [
    // All MODERATE patterns plus:
    /<[^>]+\s+on\w+\s*=/i,
    /expression\s*\(/i,
    /eval\s*\(/i,
    /Function\s*\(/i,
    /setTimeout\s*\(/i,
    /setInterval\s*\(/i,
    /location\.href/i,
    /location\.replace/i,
    /<[^>]+\s+style\s*=\s*["'][^"']*expression/i,
    /atob\s*\(/i,
    /btoa\s*\(/i,
    /unescape\s*\(/i,
    /decodeURIComponent\s*\(/i,
    /String\.fromCharCode/i,
  ],
};

// Advanced bot detection patterns
const ADVANCED_BOT_PATTERNS = [
  // Known bad bots
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
  /acunetix/i,
  /appscan/i,
  /arachni/i,
  /beef/i,
  /brutus/i,
  /cain/i,
  /cisco-torch/i,
  /crunch/i,
  /darknode/i,
  /davoset/i,
  /doser/i,
  /exploitdb/i,
  /fimap/i,
  /grabber/i,
  /havij/i,
  /jbrofuzz/i,
  /jsql/i,
  /loic/i,
  /nessus/i,
  /netsparker/i,
  /pangolin/i,
  /paros/i,
  /ratproxy/i,
  /scapy/i,
  /skipfish/i,
  /slowloris/i,
  /slurp/i,
  /sqlninja/i,
  /vega/i,
  /w3af/i,
  /webinspect/i,
  /whisker/i,
  /wpscan/i,
  /xsser/i,
  /zap/i,
  // Headless browser indicators (if enabled)
  /HeadlessChrome/i,
  /PhantomJS/i,
  /Selenium/i,
  /Puppeteer/i,
  /Playwright/i,
];

// Behavioral scoring thresholds
const BOT_BEHAVIORAL_THRESHOLDS = {
  LOW: 30,
  MEDIUM: 50,
  HIGH: 70,
  AGGRESSIVE: 90,
};

// Export all constants and patterns
export {
  KNOWN_TOR_EXIT_NODES,
  KNOWN_VPN_RANGES,
  HOSTING_PROVIDER_RANGES,
  SQLI_PATTERNS,
  XSS_PATTERNS,
  ADVANCED_BOT_PATTERNS,
  BOT_BEHAVIORAL_THRESHOLDS,
};
