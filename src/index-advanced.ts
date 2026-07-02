/**
 * Universal WAF - Advanced Features
 * Main exports for enhanced protection capabilities
 */

export { AdvancedWAFEngine, AdvancedWAFResult } from './core/engine-advanced';
export {
  AdvancedWAFConfig,
  DEFAULT_ADVANCED_CONFIG,
  WAFAction,
  SQLI_PATTERNS,
  XSS_PATTERNS,
  ADVANCED_BOT_PATTERNS,
  BOT_BEHAVIORAL_THRESHOLDS,
} from './core/rules-advanced';

// Re-export base types for compatibility
export { WAFRequest, WAFResult, WAFRule, RuleMatchResult } from './core/rules';

// Default export
export { AdvancedWAFEngine as default } from './core/engine-advanced';
