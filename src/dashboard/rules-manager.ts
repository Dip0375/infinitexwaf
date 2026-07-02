/**
 * InfiniteX WAF Rules Manager
 * Runtime enable/disable of built-in rules + full CRUD for custom rules
 */

import { WAFRule, WAFRequest, RuleMatchResult, WAF_RULES } from '../core/rules';

export type RuleAction = 'BLOCK' | 'LOG' | 'LOGGED' | 'ALLOW' | 'CHALLENGE';
export type RuleTarget = 'uri' | 'query' | 'body' | 'headers' | 'user_agent' | 'ip' | 'all';
export type MatchType = 'regex' | 'contains' | 'starts_with' | 'ends_with' | 'exact' | 'ip_cidr';

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
  'XSS-001':   'XSS',
  'PT-001':    'Traversal',
  'CMDI-001':  'Injection',
  'NOSQLI-001':'Injection',
  'SSRF-001':  'SSRF',
  'BOT-001':   'Bot',
  'METH-001':  'Protocol',
  'CT-001':    'Protocol',
  'NULL-001':  'Injection',
};

// ── In-memory state ───────────────────────────────────────────────────────────
const builtInState = new Map<string, { enabled: boolean; hitCount: number }>(
  WAF_RULES.map((r) => [r.id, { enabled: r.enabled, hitCount: 0 }])
);

const customRules = new Map<string, CustomRule>();

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
