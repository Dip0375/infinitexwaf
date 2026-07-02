/**
 * Universal WAF - Main Exports
 */

export { WAFEngine, WAFConfig, RateLimitConfig, DEFAULT_CONFIG } from './core/engine';
export { WAFRule, WAFRequest, WAFResult, RuleMatchResult, WAF_RULES, DEFAULT_ACTIVE_RULES } from './core/rules';

// Default export is the engine
export { WAFEngine as default } from './core/engine';
