/**
 * InfiniteX Dashboard API Routes
 * Alert and Export management endpoints
 */

import express from 'express';
import { alertManager, SMTPEmailSender } from './alerts';
import { getExportLogger, ExportConfig } from './export-logger';
import {
  getBuiltInRules, setBuiltInRuleEnabled,
  getCustomRules, getCustomRule, createCustomRule, updateCustomRule,
  deleteCustomRule, toggleCustomRule,
  getManagedRuleConfigs, getManagedRuleConfig, updateManagedRuleConfig,
  getRuleGroupsWithSubRules, getSubRuleStates, updateSubRuleState, deleteSubRule, restoreSubRule,
} from './rules-manager';

const router = express.Router();

// ===== WAF RULES ROUTES =====

/** GET /api/rules/builtin — list all built-in rules with live state */
router.get('/rules/builtin', (_req, res) => {
  res.json({ rules: getBuiltInRules() });
});

/** PATCH /api/rules/builtin/:id — enable or disable a built-in rule */
router.patch('/rules/builtin/:id', (req, res) => {
  const { id } = req.params;
  const { enabled } = req.body;
  if (typeof enabled !== 'boolean') {
    return res.status(400).json({ success: false, error: '`enabled` must be boolean' });
  }
  const ok = setBuiltInRuleEnabled(id, enabled);
  if (!ok) return res.status(404).json({ success: false, error: 'Rule not found' });
  res.json({ success: true, id, enabled });
});

/** GET /api/rules/custom — list all custom rules */
router.get('/rules/custom', (_req, res) => {
  res.json({ rules: getCustomRules() });
});

/** GET /api/rules/custom/:id — get single custom rule */
router.get('/rules/custom/:id', (req, res) => {
  const rule = getCustomRule(req.params.id);
  if (!rule) return res.status(404).json({ success: false, error: 'Rule not found' });
  res.json({ rule });
});

/** POST /api/rules/custom — create custom rule */
router.post('/rules/custom', (req, res) => {
  const { name, description, severity, action, enabled, priority, conditions, conditionLogic, tags } = req.body;
  if (!name || !conditions?.length) {
    return res.status(400).json({ success: false, error: 'name and conditions are required' });
  }
  const rule = createCustomRule({
    name, description: description ?? '', severity: severity ?? 'MEDIUM',
    action: action ?? 'BLOCK', enabled: enabled ?? true,
    priority: priority ?? 100, conditions, conditionLogic: conditionLogic ?? 'AND',
    tags: tags ?? [],
  });
  res.status(201).json({ success: true, rule });
});

/** PUT /api/rules/custom/:id — update custom rule */
router.put('/rules/custom/:id', (req, res) => {
  const updated = updateCustomRule(req.params.id, req.body);
  if (!updated) return res.status(404).json({ success: false, error: 'Rule not found' });
  res.json({ success: true, rule: updated });
});

/** PATCH /api/rules/custom/:id — toggle enabled */
router.patch('/rules/custom/:id', (req, res) => {
  const { enabled } = req.body;
  if (typeof enabled !== 'boolean') {
    return res.status(400).json({ success: false, error: '`enabled` must be boolean' });
  }
  const ok = toggleCustomRule(req.params.id, enabled);
  if (!ok) return res.status(404).json({ success: false, error: 'Rule not found' });
  res.json({ success: true, id: req.params.id, enabled });
});

/** DELETE /api/rules/custom/:id — delete custom rule */
router.delete('/rules/custom/:id', (req, res) => {
  const ok = deleteCustomRule(req.params.id);
  if (!ok) return res.status(404).json({ success: false, error: 'Rule not found' });
  res.json({ success: true });
});

// ===== MANAGED RULE CONFIG ROUTES (AWS WAF-style rule group parameters) =====

/** GET /api/rules/managed-config — get all managed rule configurations */
router.get('/rules/managed-config', (_req, res) => {
  res.json({ configs: getManagedRuleConfigs() });
});

/** GET /api/rules/managed-config/:ruleId — get single managed rule config */
router.get('/rules/managed-config/:ruleId', (req, res) => {
  const config = getManagedRuleConfig(req.params.ruleId);
  if (!config) return res.status(404).json({ success: false, error: 'Rule not found' });
  res.json({ config });
});

/** PATCH /api/rules/managed-config/:ruleId — update managed rule config */
router.patch('/rules/managed-config/:ruleId', (req, res) => {
  const updated = updateManagedRuleConfig(req.params.ruleId, req.body);
  if (!updated) return res.status(404).json({ success: false, error: 'Rule not found' });
  res.json({ success: true, config: updated });
});

// ===== SUB-RULE ROUTES (individual rules within managed rule groups) ==========

/** GET /api/rules/sub-rules — get all rule groups with their sub-rules + state */
router.get('/rules/sub-rules', (_req, res) => {
  res.json({
    groups: getRuleGroupsWithSubRules(),
    states: getSubRuleStates(),
  });
});

/** PATCH /api/rules/sub-rules/:ruleId — update sub-rule state */
router.patch('/rules/sub-rules/:ruleId', (req, res) => {
  const updated = updateSubRuleState(req.params.ruleId, req.body);
  if (!updated) return res.status(404).json({ success: false, error: 'Sub-rule not found' });
  res.json({ success: true, state: updated });
});

/** DELETE /api/rules/sub-rules/:ruleId — soft-delete a sub-rule */
router.delete('/rules/sub-rules/:ruleId', (req, res) => {
  const ok = deleteSubRule(req.params.ruleId);
  if (!ok) return res.status(404).json({ success: false, error: 'Sub-rule not found' });
  res.json({ success: true });
});

/** POST /api/rules/sub-rules/:ruleId/restore — restore a deleted sub-rule */
router.post('/rules/sub-rules/:ruleId/restore', (req, res) => {
  const ok = restoreSubRule(req.params.ruleId);
  if (!ok) return res.status(404).json({ success: false, error: 'Sub-rule not found' });
  res.json({ success: true });
});

// ===== ALERT ROUTES =====

/**
 * GET /api/alerts/rules
 * Get all alert rules
 */
router.get('/alerts/rules', (req, res) => {
  const rules = alertManager.getRules();
  res.json({ rules });
});

/**
 * POST /api/alerts/rules
 * Create new alert rule
 */
router.post('/alerts/rules', (req, res) => {
  const rule = {
    id: `rule-${Date.now()}`,
    ...req.body,
    lastTriggered: undefined,
  };

  alertManager.addRule(rule);
  res.status(201).json({ success: true, rule });
});

/**
 * PUT /api/alerts/rules/:id
 * Update alert rule
 */
router.put('/alerts/rules/:id', (req, res) => {
  const { id } = req.params;
  alertManager.addRule({ ...req.body, id });
  res.json({ success: true });
});

/**
 * DELETE /api/alerts/rules/:id
 * Delete alert rule
 */
router.delete('/alerts/rules/:id', (req, res) => {
  const { id } = req.params;
  alertManager.removeRule(id);
  res.json({ success: true });
});

/**
 * GET /api/alerts/history
 * Get alert history
 */
router.get('/alerts/history', (req, res) => {
  const limit = parseInt(req.query.limit as string) || 100;
  const history = alertManager.getAlertHistory(limit);
  res.json({ alerts: history });
});

/**
 * POST /api/alerts/test
 * Test alert configuration
 */
router.post('/alerts/test', async (req, res) => {
  const { emailConfig, recipients } = req.body;

  try {
    // Create temporary sender
    const sender = new SMTPEmailSender(emailConfig);

    await sender.send({
      to: recipients,
      subject: '[InfiniteX] Test Alert',
      html: '<h1>This is a test alert from InfiniteX WAF</h1>',
      text: 'This is a test alert from InfiniteX WAF',
    });

    res.json({ success: true, message: 'Test email sent' });
  } catch (error) {
    res.status(500).json({ success: false, error: String(error) });
  }
});

// ===== EXPORT ROUTES =====

/**
 * GET /api/export/config
 * Get export configuration
 */
router.get('/export/config', (req, res) => {
  const logger = getExportLogger();
  res.json({ config: logger.getStats() });
});

/**
 * POST /api/export/config
 * Update export configuration
 */
router.post('/export/config', (req, res) => {
  const config: ExportConfig = req.body;
  // Would update the export logger with new config
  res.json({ success: true, config });
});

/**
 * POST /api/export/force
 * Force immediate export
 */
router.post('/export/force', async (req, res) => {
  const logger = getExportLogger();
  await logger.forceExport();
  res.json({ success: true, message: 'Export initiated' });
});

/**
 * GET /api/export/status
 * Get export status
 */
router.get('/export/status', (req, res) => {
  const logger = getExportLogger();
  const stats = logger.getStats();
  res.json({
    lastExport: stats.lastExport,
    buffered: stats.buffered,
  });
});

// ===== SETTINGS ROUTES =====

/**
 * GET /api/settings
 * Get all settings
 */
router.get('/settings', (req, res) => {
  res.json({
    general: {
      theme: 'dark',
      refreshInterval: 30,
      timezone: 'UTC',
    },
    notifications: {
      emailEnabled: false,
      slackEnabled: false,
      webhookEnabled: false,
    },
    export: {
      enabled: false,
      type: 'local',
      format: 'json',
    },
  });
});

/**
 * POST /api/settings
 * Update settings
 */
router.post('/settings', (req, res) => {
  // Would save settings
  res.json({ success: true, settings: req.body });
});

export default router;
