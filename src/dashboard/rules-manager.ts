/**
 * InfiniteX WAF Rules Manager
 * Runtime enable/disable of built-in rules + full CRUD for custom rules
 */

import { WAFRule, WAFRequest, RuleMatchResult, WAF_RULES } from '../core/rules';

export type RuleAction = 'BLOCK' | 'LOG' | 'LOGGED' | 'ALLOW' | 'CHALLENGE';
export type RuleTarget = 'uri' | 'query' | 'body' | 'headers' | 'user_agent' | 'ip' | 'all';
export type MatchType = 'regex' | 'contains' | 'starts_with' | 'ends_with' | 'exact' | 'ip_cidr';

// ── Managed Rule Configuration (AWS WAF-style) ────────────────────────────────
export type WAFAction = 'ALLOW' | 'BLOCK' | 'LOG' | 'LOGGED' | 'CHALLENGE';

export interface ManagedRuleConfig {
  action?: WAFAction;
  geoCountries?: string[];
  adminEndpoints?: string[];
  botLevel?: 'LOW' | 'MEDIUM' | 'HIGH' | 'AGGRESSIVE';
  botBlockHeadless?: boolean;
  rateLimitRequests?: number;
  rateLimitWindow?: number;
  rateLimitBurst?: number;
  sqliLevel?: 'BASIC' | 'MODERATE' | 'STRICT';
  xssLevel?: 'BASIC' | 'MODERATE' | 'STRICT';
  blockTor?: boolean;
  blockVpn?: boolean;
  blockProxy?: boolean;
  blockHosting?: boolean;
  ipReputationEnabled?: boolean;
  csrfEnabled?: boolean;
  csrfEndpoints?: string[];
  uploadAllowedExtensions?: string[];
  uploadBlockedExtensions?: string[];
  uploadMaxSize?: number;
  allowedMethods?: string[];
  blockedMethods?: string[];
}

export const DEFAULT_MANAGED_CONFIGS: Record<string, ManagedRuleConfig> = {
  'CORE-001': { action: 'BLOCK' },
  'GEO-001': { action: 'BLOCK', geoCountries: [] },
  'METH-001': { action: 'BLOCK', adminEndpoints: ['/login', '/auth', '/admin', '/wp-login.php', '/api/auth'] },
  'SQLI-001': { action: 'BLOCK', sqliLevel: 'MODERATE' },
  'BOT-001':  { action: 'BLOCK', botLevel: 'MEDIUM', botBlockHeadless: false },
  'RATE-001': { action: 'BLOCK', rateLimitRequests: 100, rateLimitWindow: 60, rateLimitBurst: 150 },
  'ANON-001': { action: 'CHALLENGE', blockTor: false, blockVpn: false, blockProxy: false, blockHosting: false },
  'NOSQLI-001': { action: 'BLOCK' },
  'NULL-001': { action: 'BLOCK' },
  'CT-001':   { action: 'BLOCK' },
  'THREAT-INTEL-001': { action: 'BLOCK', ipReputationEnabled: true },
};

// ── Sub-Rule Definitions (individual rules within each managed rule group) ────
export interface ManagedSubRuleDef {
  id: string;
  name: string;
  description: string;
  label: string;
  defaultAction: WAFAction;
  scope?: string;
}

export interface ManagedSubRuleState {
  enabled: boolean;
  action?: WAFAction;
  deleted?: boolean;
}

export interface ManagedRuleGroupWithSubRules {
  groupId: string;
  groupName: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  rules: ManagedSubRuleDef[];
}

export const MANAGED_RULE_GROUPS: ManagedRuleGroupWithSubRules[] = [
  {
    groupId: 'CORE-001',
    groupName: 'InfiniteXManagedCoreRuleSets',
    description: 'AWS WAF Core Rule Set (CRS) — basic security protections aligned with AWSManagedRulesCommonRuleSet',
    severity: 'CRITICAL',
    rules: [
      { id: 'NoUserAgent_HEADER', name: 'NoUserAgent_HEADER', description: 'Block requests missing User-Agent header', label: 'infx:managed:core-rule-set:NoUserAgent_Header', defaultAction: 'BLOCK', scope: 'header' },
      { id: 'BadBots_HEADER', name: 'BadBots_HEADER', description: 'Block known bad bot User-Agent strings (nessus, nmap, etc.)', label: 'infx:managed:core-rule-set:BadBots_Header', defaultAction: 'BLOCK', scope: 'header' },
      { id: 'SizeRestrictions_QUERYSTRING', name: 'SizeRestrictions_QUERYSTRING', description: 'Block URI query strings over 2,048 bytes', label: 'infx:managed:core-rule-set:SizeRestrictions_QueryString', defaultAction: 'BLOCK', scope: 'query' },
      { id: 'SizeRestrictions_BODY', name: 'SizeRestrictions_BODY', description: 'Block request bodies over 8,192 bytes', label: 'infx:managed:core-rule-set:SizeRestrictions_Body', defaultAction: 'BLOCK', scope: 'body' },
      { id: 'SizeRestrictions_URIPATH', name: 'SizeRestrictions_URIPATH', description: 'Block URI paths over 1,024 bytes', label: 'infx:managed:core-rule-set:SizeRestrictions_URIPath', defaultAction: 'BLOCK', scope: 'uri' },
      { id: 'SizeRestrictions_COOKIE', name: 'SizeRestrictions_COOKIE', description: 'Block cookie headers over 10,240 bytes', label: 'infx:managed:core-rule-set:SizeRestrictions_Cookie', defaultAction: 'BLOCK', scope: 'cookie' },
      { id: 'EC2MetaDataSSRF_BODY', name: 'EC2MetaDataSSRF_BODY', description: 'Block EC2 metadata SSRF attempts in request body', label: 'infx:managed:core-rule-set:EC2MetaDataSSRF_Body', defaultAction: 'BLOCK', scope: 'body' },
      { id: 'EC2MetaDataSSRF_COOKIE', name: 'EC2MetaDataSSRF_COOKIE', description: 'Block EC2 metadata SSRF attempts in cookies', label: 'infx:managed:core-rule-set:EC2MetaDataSSRF_Cookie', defaultAction: 'BLOCK', scope: 'cookie' },
      { id: 'EC2MetaDataSSRF_URIPATH', name: 'EC2MetaDataSSRF_URIPATH', description: 'Block EC2 metadata SSRF attempts in URI path', label: 'infx:managed:core-rule-set:EC2MetaDataSSRF_URIPath', defaultAction: 'BLOCK', scope: 'uri' },
      { id: 'EC2MetaDataSSRF_QUERYARGUMENTS', name: 'EC2MetaDataSSRF_QUERYARGUMENTS', description: 'Block EC2 metadata SSRF attempts in query arguments', label: 'infx:managed:core-rule-set:EC2MetaDataSSRF_QueryArguments', defaultAction: 'BLOCK', scope: 'query' },
      { id: 'GenericLFI_QUERYARGUMENTS', name: 'GenericLFI_QUERYARGUMENTS', description: 'Block LFI path traversal in query arguments (e.g. ../../)', label: 'infx:managed:core-rule-set:GenericLFI_QueryArguments', defaultAction: 'BLOCK', scope: 'query' },
      { id: 'GenericLFI_URIPATH', name: 'GenericLFI_URIPATH', description: 'Block LFI path traversal in URI path', label: 'infx:managed:core-rule-set:GenericLFI_URIPath', defaultAction: 'BLOCK', scope: 'uri' },
      { id: 'GenericLFI_BODY', name: 'GenericLFI_BODY', description: 'Block LFI path traversal in request body', label: 'infx:managed:core-rule-set:GenericLFI_Body', defaultAction: 'BLOCK', scope: 'body' },
      { id: 'RestrictedExtensions_URIPATH', name: 'RestrictedExtensions_URIPATH', description: 'Block system file extensions in URI path (.log, .ini, etc.)', label: 'infx:managed:core-rule-set:RestrictedExtensions_URIPath', defaultAction: 'BLOCK', scope: 'uri' },
      { id: 'RestrictedExtensions_QUERYARGUMENTS', name: 'RestrictedExtensions_QUERYARGUMENTS', description: 'Block system file extensions in query arguments', label: 'infx:managed:core-rule-set:RestrictedExtensions_QueryArguments', defaultAction: 'BLOCK', scope: 'query' },
      { id: 'GenericRFI_QUERYARGUMENTS', name: 'GenericRFI_QUERYARGUMENTS', description: 'Block RFI attempts in query arguments (http://, ftp://)', label: 'infx:managed:core-rule-set:GenericRFI_QueryArguments', defaultAction: 'BLOCK', scope: 'query' },
      { id: 'GenericRFI_BODY', name: 'GenericRFI_BODY', description: 'Block RFI attempts in request body', label: 'infx:managed:core-rule-set:GenericRFI_Body', defaultAction: 'BLOCK', scope: 'body' },
      { id: 'GenericRFI_URIPATH', name: 'GenericRFI_URIPATH', description: 'Block RFI attempts in URI path', label: 'infx:managed:core-rule-set:GenericRFI_URIPath', defaultAction: 'BLOCK', scope: 'uri' },
      { id: 'CrossSiteScripting_COOKIE', name: 'CrossSiteScripting_COOKIE', description: 'Block XSS in cookie values', label: 'infx:managed:core-rule-set:CrossSiteScripting_Cookie', defaultAction: 'BLOCK', scope: 'cookie' },
      { id: 'CrossSiteScripting_QUERYARGUMENTS', name: 'CrossSiteScripting_QUERYARGUMENTS', description: 'Block XSS in query argument values', label: 'infx:managed:core-rule-set:CrossSiteScripting_QueryArguments', defaultAction: 'BLOCK', scope: 'query' },
      { id: 'CrossSiteScripting_BODY', name: 'CrossSiteScripting_BODY', description: 'Block XSS in request body payloads', label: 'infx:managed:core-rule-set:CrossSiteScripting_Body', defaultAction: 'BLOCK', scope: 'body' },
      { id: 'CrossSiteScripting_URIPATH', name: 'CrossSiteScripting_URIPATH', description: 'Block XSS in URI path', label: 'infx:managed:core-rule-set:CrossSiteScripting_URIPath', defaultAction: 'BLOCK', scope: 'uri' },
    ],
  },
  {
    groupId: 'SQLI-001',
    groupName: 'InfiniteXManagedSQLiRuleSets',
    description: 'Managed SQL injection protection aligned with AWS WAF managed rule groups',
    severity: 'CRITICAL',
    rules: [
      { id: 'SQLi_BODY', name: 'SQLi_BODY', description: 'Detect SQL injection in request body', label: 'infx:managed:sqli-rule-set:SQLi_Body', defaultAction: 'BLOCK', scope: 'body' },
      { id: 'SQLi_QUERYARGUMENTS', name: 'SQLi_QUERYARGUMENTS', description: 'Detect SQL injection in query parameters', label: 'infx:managed:sqli-rule-set:SQLi_QueryArguments', defaultAction: 'BLOCK', scope: 'query' },
      { id: 'SQLi_URIPATH', name: 'SQLi_URIPATH', description: 'Detect SQL injection in URI path', label: 'infx:managed:sqli-rule-set:SQLi_URIPath', defaultAction: 'BLOCK', scope: 'uri' },
      { id: 'SQLi_COOKIE', name: 'SQLi_COOKIE', description: 'Detect SQL injection in cookie values', label: 'infx:managed:sqli-rule-set:SQLi_Cookie', defaultAction: 'BLOCK', scope: 'cookie' },
    ],
  },
  {
    groupId: 'ANON-001',
    groupName: 'InfiniteXManagedAnonymousRuleSets',
    description: 'Managed anonymous IP protection for VPN, proxy and TOR traffic',
    severity: 'MEDIUM',
    rules: [
      { id: 'ANON_TOR', name: 'ANON_TOR', description: 'Block TOR exit node traffic', label: 'infx:managed:anon-rule-set:ANON_TOR', defaultAction: 'CHALLENGE', scope: 'ip' },
      { id: 'ANON_VPN', name: 'ANON_VPN', description: 'Block VPN provider traffic', label: 'infx:managed:anon-rule-set:ANON_VPN', defaultAction: 'CHALLENGE', scope: 'ip' },
      { id: 'ANON_PROXY', name: 'ANON_PROXY', description: 'Block public proxy traffic', label: 'infx:managed:anon-rule-set:ANON_PROXY', defaultAction: 'CHALLENGE', scope: 'ip' },
      { id: 'ANON_HOSTING', name: 'ANON_HOSTING', description: 'Block hosting provider traffic', label: 'infx:managed:anon-rule-set:ANON_HOSTING', defaultAction: 'CHALLENGE', scope: 'ip' },
    ],
  },
];

export interface CustomRuleCondition {
  target: RuleTarget;
  matchType: MatchType;
  value: string;
  negate?: boolean;
}

export interface CustomRule {
  id: string;
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  action: RuleAction;
  enabled: boolean;
  priority: number;           // lower = evaluated first
  conditions: CustomRuleCondition[];
  conditionLogic: 'AND' | 'OR';
  tags: string[];
  createdAt: string;
  updatedAt: string;
  hitCount: number;
}

// ── Serialisable view of a built-in rule (no function refs) ──────────────────
export interface BuiltInRuleView {
  id: string;
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  enabled: boolean;
  category: string;
  isBuiltIn: true;
  hitCount: number;
}

const CATEGORY_MAP: Record<string, string> = {
  'SQLI-001':  'Injection',
  'BOT-001':   'Bot',
  'METH-001':  'Protocol',
  'CT-001':    'Protocol',
  'NULL-001':  'Injection',
  'NOSQLI-001':'Injection',
};

// ── In-memory state ───────────────────────────────────────────────────────────
const builtInState = new Map<string, { enabled: boolean; hitCount: number }>(
  WAF_RULES.map((r) => [r.id, { enabled: r.enabled, hitCount: 0 }])
);

const customRules = new Map<string, CustomRule>();

// ── Managed rule configs (per-rule-group settings like AWS managed rule groups) ──
const managedRuleConfigs = new Map<string, ManagedRuleConfig>(
  Object.entries(DEFAULT_MANAGED_CONFIGS).map(([id, c]) => [id, { ...c }])
);

// ── Sub-rule state (per-sub-rule enabled/action/deleted within each managed group) ──
const subRuleState = new Map<string, ManagedSubRuleState>();

// Initialize sub-rule state from definitions
for (const group of MANAGED_RULE_GROUPS) {
  for (const rule of group.rules) {
    subRuleState.set(rule.id, { enabled: true, action: undefined, deleted: false });
  }
}

// ── Hit counter (called by engine) ───────────────────────────────────────────
export function recordRuleHit(ruleId: string): void {
  if (builtInState.has(ruleId)) {
    builtInState.get(ruleId)!.hitCount++;
  } else if (customRules.has(ruleId)) {
    customRules.get(ruleId)!.hitCount++;
  }
}

// ── Built-in rule management ──────────────────────────────────────────────────
export function getBuiltInRules(): BuiltInRuleView[] {
  return WAF_RULES.map((r) => {
    const state = builtInState.get(r.id) ?? { enabled: r.enabled, hitCount: 0 };
    return {
      id: r.id,
      name: r.name,
      description: r.description,
      severity: r.severity,
      enabled: state.enabled,
      category: CATEGORY_MAP[r.id] ?? 'General',
      isBuiltIn: true as const,
      hitCount: state.hitCount,
    };
  });
}

export function setBuiltInRuleEnabled(id: string, enabled: boolean): boolean {
  if (!builtInState.has(id)) return false;
  builtInState.get(id)!.enabled = enabled;
  return true;
}

export function isBuiltInRuleEnabled(id: string): boolean {
  return builtInState.get(id)?.enabled ?? false;
}

// ── Custom rule management ────────────────────────────────────────────────────
export function getCustomRules(): CustomRule[] {
  return Array.from(customRules.values()).sort((a, b) => a.priority - b.priority);
}

export function getCustomRule(id: string): CustomRule | undefined {
  return customRules.get(id);
}

export function createCustomRule(data: Omit<CustomRule, 'id' | 'createdAt' | 'updatedAt' | 'hitCount'>): CustomRule {
  const rule: CustomRule = {
    ...data,
    id: `CUSTOM-${Date.now()}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    hitCount: 0,
  };
  customRules.set(rule.id, rule);
  return rule;
}

export function updateCustomRule(id: string, data: Partial<Omit<CustomRule, 'id' | 'createdAt' | 'hitCount'>>): CustomRule | null {
  const existing = customRules.get(id);
  if (!existing) return null;
  const updated: CustomRule = { ...existing, ...data, id, updatedAt: new Date().toISOString() };
  customRules.set(id, updated);
  return updated;
}

export function deleteCustomRule(id: string): boolean {
  return customRules.delete(id);
}

export function toggleCustomRule(id: string, enabled: boolean): boolean {
  const rule = customRules.get(id);
  if (!rule) return false;
  rule.enabled = enabled;
  rule.updatedAt = new Date().toISOString();
  return true;
}

// ── Managed rule config management ────────────────────────────────────────────
export function getManagedRuleConfigs(): Record<string, ManagedRuleConfig> {
  const result: Record<string, ManagedRuleConfig> = {};
  for (const [id, config] of managedRuleConfigs.entries()) {
    result[id] = { ...config };
  }
  return result;
}

export function getManagedRuleConfig(ruleId: string): ManagedRuleConfig | undefined {
  const config = managedRuleConfigs.get(ruleId);
  return config ? { ...config } : undefined;
}

export function updateManagedRuleConfig(
  ruleId: string,
  patch: Partial<ManagedRuleConfig>
): ManagedRuleConfig | null {
  const existing = managedRuleConfigs.get(ruleId);
  if (!existing) return null;
  const updated: ManagedRuleConfig = { ...existing, ...patch };
  managedRuleConfigs.set(ruleId, updated);
  return { ...updated };
}

// ── Sub-rule management (individual rules within managed rule groups) ─────────
export function getSubRuleStates(): Record<string, ManagedSubRuleState> {
  const result: Record<string, ManagedSubRuleState> = {};
  for (const [id, state] of subRuleState.entries()) {
    result[id] = { ...state };
  }
  return result;
}

export function updateSubRuleState(ruleId: string, patch: Partial<ManagedSubRuleState>): ManagedSubRuleState | null {
  const existing = subRuleState.get(ruleId);
  if (!existing) return null;
  const updated: ManagedSubRuleState = { ...existing, ...patch };
  subRuleState.set(ruleId, updated);
  return { ...updated };
}

export function deleteSubRule(ruleId: string): boolean {
  const existing = subRuleState.get(ruleId);
  if (!existing) return false;
  existing.deleted = true;
  existing.enabled = false;
  return true;
}

export function restoreSubRule(ruleId: string): boolean {
  const existing = subRuleState.get(ruleId);
  if (!existing) return false;
  existing.deleted = false;
  existing.enabled = true;
  return true;
}

export function getRuleGroupsWithSubRules(): ManagedRuleGroupWithSubRules[] {
  return MANAGED_RULE_GROUPS.map((group) => ({
    ...group,
    rules: group.rules.map((rule) => {
      const state = subRuleState.get(rule.id);
      return state?.deleted
        ? { ...rule, name: `${rule.name}`, description: rule.description, label: rule.label, defaultAction: rule.defaultAction, scope: rule.scope, deleted: true }
        : rule;
    }).filter((r) => !(r as any).deleted),
  }));
}

// ── Custom rule evaluator (used by engine) ────────────────────────────────────
export function evaluateCustomRule(rule: CustomRule, request: WAFRequest): RuleMatchResult {
  const results = rule.conditions.map((cond) => matchCondition(cond, request));
  const matched = rule.conditionLogic === 'AND'
    ? results.every(Boolean)
    : results.some(Boolean);

  if (matched) {
    return { matched: true, reason: `Custom rule: ${rule.name}` };
  }
  return { matched: false };
}

function matchCondition(cond: CustomRuleCondition, req: WAFRequest): boolean {
  const values = getTargetValues(cond.target, req);
  const result = values.some((v) => applyMatch(cond.matchType, v, cond.value));
  return cond.negate ? !result : result;
}

function getTargetValues(target: RuleTarget, req: WAFRequest): string[] {
  switch (target) {
    case 'uri':        return [req.uri];
    case 'query':      return [req.queryString ?? ''];
    case 'body':       return [req.body ?? ''];
    case 'user_agent': return [req.userAgent ?? ''];
    case 'ip':         return [req.clientIp];
    case 'headers':    return Object.values(req.headers).flat();
    case 'all':
    default:
      return [req.uri, req.queryString ?? '', req.body ?? '', req.userAgent ?? '',
              ...Object.values(req.headers).flat()];
  }
}

function applyMatch(type: MatchType, value: string, pattern: string): boolean {
  try {
    switch (type) {
      case 'regex':       return new RegExp(pattern, 'i').test(value);
      case 'contains':    return value.toLowerCase().includes(pattern.toLowerCase());
      case 'starts_with': return value.toLowerCase().startsWith(pattern.toLowerCase());
      case 'ends_with':   return value.toLowerCase().endsWith(pattern.toLowerCase());
      case 'exact':       return value.toLowerCase() === pattern.toLowerCase();
      case 'ip_cidr':     return ipInCidr(value, pattern);
      default:            return false;
    }
  } catch {
    return false;
  }
}

function ipInCidr(ip: string, cidr: string): boolean {
  try {
    const [range, bits] = cidr.split('/');
    const mask = parseInt(bits, 10);
    const toNum = (s: string) => s.split('.').reduce((acc, o) => (acc << 8) + parseInt(o, 10), 0) >>> 0;
    const maskNum = (0xffffffff << (32 - mask)) >>> 0;
    return (toNum(ip) & maskNum) === (toNum(range) & maskNum);
  } catch {
    return false;
  }
}
