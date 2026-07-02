/**
 * InfiniteX WAF — Development API Server
 * Runs on :3000, serves all /api/* routes with seeded mock data.
 * The Vite dashboard on :3001 proxies /api → here.
 *
 * Start with:  npm run dev:server
 */

import express from 'express';
import cors from 'cors';

const app = express();
app.use(cors());
app.use(express.json());

const RULE_DEFS = [
  { ruleId:'SQLI-001', name:'SQL Injection',              category:'Injection', severity:'CRITICAL' },
  { ruleId:'XSS-001',  name:'Cross-Site Scripting',       category:'XSS',       severity:'CRITICAL' },
  { ruleId:'PT-001',   name:'Path Traversal',             category:'Traversal', severity:'HIGH'     },
  { ruleId:'CMDI-001', name:'Command Injection',          category:'Injection', severity:'CRITICAL' },
  { ruleId:'NOSQLI-001',name:'NoSQL Injection',           category:'Injection', severity:'CRITICAL' },
  { ruleId:'SSRF-001', name:'Server-Side Request Forgery',category:'SSRF',      severity:'HIGH'     },
  { ruleId:'BOT-001',  name:'Malicious Bot',              category:'Bot',       severity:'MEDIUM'   },
  { ruleId:'RATE-001', name:'Rate Limit Exceeded',        category:'Rate Limit',severity:'MEDIUM'   },
  { ruleId:'NULL-001', name:'Null Byte Injection',        category:'Injection', severity:'HIGH'     },
  { ruleId:'METH-001', name:'Invalid HTTP Method',        category:'Protocol',  severity:'MEDIUM'   },
];

// ── In-memory state — starts EMPTY on server, fills with real traffic ─────────
const NOW = Date.now();

// Time series — empty, filled by real WAF requests
const timeSeries: any[] = [];

// Geo stats — empty
const geoStats: any[] = [];

// Top lists — all empty
const topIPs: any[] = [];
const topRules: any[] = [];
const topUserAgents: any[] = [];
const topPaths: any[] = [];
const topCountries: any[] = [];

// Metrics
const totalReqs  = 0;
const totalBlock = 0;
const totalBot   = 0;
const totalLog   = 0;

// Map points — empty
const mapPoints: any[] = [];

// Distribution — empty
const distribution: any[] = [];

// Alert history — empty
const alertHistory: any[] = [];

// Built-in rules state — all enabled by default, zero hits
const builtInState: Record<string, { enabled: boolean; hitCount: number }> = {};
RULE_DEFS.forEach((r) => { builtInState[r.ruleId] = { enabled: true, hitCount: 0 }; });
builtInState['CT-001'] = { enabled: false, hitCount: 0 };

const BUILTIN_META: Record<string, { description: string; category: string }> = {
  'SQLI-001':  { description: 'Detects SQL injection attempts in all input fields', category: 'Injection' },
  'XSS-001':   { description: 'Detects cross-site scripting attack patterns',       category: 'XSS'       },
  'PT-001':    { description: 'Detects directory traversal attempts',               category: 'Traversal' },
  'CMDI-001':  { description: 'Detects OS command injection attempts',              category: 'Injection' },
  'NOSQLI-001':{ description: 'Detects NoSQL operator injection in query/body',     category: 'Injection' },
  'SSRF-001':  { description: 'Detects server-side request forgery attempts',       category: 'SSRF'      },
  'BOT-001':   { description: 'Blocks known malicious scanners and bots',           category: 'Bot'       },
  'RATE-001':  { description: 'Blocks IPs exceeding the configured request rate',   category: 'Rate Limit'},
  'NULL-001':  { description: 'Detects null byte injection attempts',               category: 'Injection' },
  'METH-001':  { description: 'Blocks invalid or dangerous HTTP methods',           category: 'Protocol'  },
  'CT-001':    { description: 'Warns on POST/PUT without Content-Type header',      category: 'Protocol'  },
};

// Custom rules store
const customRules: any[] = [];

// Alert rules store
const alertRules: any[] = [];

// ── API Routes ────────────────────────────────────────────────────────────────

// Health
app.get('/api/health', (_req, res) => {
  res.json({ status: 'healthy', service: 'InfiniteX WAF (dev)', version: '2.0.0', timestamp: new Date().toISOString() });
});

// Status — dev server always reports isLive:false so banner shows correctly
app.get('/api/dashboard/status', (_req, res) => {
  res.json({
    isLive: false,
    requestsProcessed: 0,
    startedAt: null,
    lastRequestAt: null,
    mode: 'development',
  });
});

// Dashboard metrics
app.get('/api/dashboard/metrics', (_req, res) => {
  const total   = timeSeries.reduce((s, t) => s + t.total, 0);
  const blocked = timeSeries.reduce((s, t) => s + t.blocked, 0);
  const bot     = timeSeries.reduce((s, t) => s + t.bot, 0);
  const allowed = total - blocked;
  res.json({
    metrics: { total, blocked, allowed, logged: totalLog, bot, legitimate: allowed - bot, timestamp: new Date().toISOString() },
    topCountries, topIPs, topRules, topUserAgents, topPaths, distribution,
  });
});

// Geo
app.get('/api/dashboard/geo', (_req, res) => {
  res.json({ geoData: geoStats, mapPoints });
});

// Time series
app.get('/api/dashboard/timeseries', (req, res) => {
  const range = (req.query.range as string) || '24h';
  const hours: Record<string, number> = { '1h':1, '6h':6, '24h':24, '7d':168, '30d':720 };
  const keep = hours[range] ?? 24;
  res.json({ timeSeries: timeSeries.slice(-keep) });
});

// Logs — returns empty on server (real logs come from api.ts in production)
app.get('/api/dashboard/logs', (_req, res) => {
  res.json({ logs: [], total: 0, offset: 0, limit: 50 });
});

// ── Rules routes ──────────────────────────────────────────────────────────────

app.get('/api/rules/builtin', (_req, res) => {
  const rules = RULE_DEFS.map((r) => ({
    id: r.ruleId, name: r.name, isBuiltIn: true,
    description: BUILTIN_META[r.ruleId]?.description ?? '',
    category:    BUILTIN_META[r.ruleId]?.category    ?? 'General',
    severity:    r.severity,
    enabled:     builtInState[r.ruleId]?.enabled ?? true,
    hitCount:    builtInState[r.ruleId]?.hitCount ?? 0,
  }));
  // Add CT-001 which isn't in RULE_DEFS
  rules.push({ id:'CT-001', name:'Missing Content-Type', isBuiltIn:true, description: BUILTIN_META['CT-001'].description, category:'Protocol', severity:'LOW', enabled:false, hitCount:0 });
  res.json({ rules });
});

app.patch('/api/rules/builtin/:id', (req, res) => {
  const { id } = req.params;
  const { enabled } = req.body;
  if (!builtInState[id]) builtInState[id] = { enabled: true, hitCount: 0 };
  builtInState[id].enabled = enabled;
  res.json({ success: true, id, enabled });
});

app.get('/api/rules/custom', (_req, res) => res.json({ rules: customRules }));

app.get('/api/rules/custom/:id', (req, res) => {
  const rule = customRules.find((r) => r.id === req.params.id);
  if (!rule) return res.status(404).json({ success: false, error: 'Not found' });
  res.json({ rule });
});

app.post('/api/rules/custom', (req, res) => {
  const rule = {
    ...req.body,
    id: `CUSTOM-${Date.now()}-${Math.random().toString(36).slice(2,7).toUpperCase()}`,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    hitCount: 0,
  };
  customRules.push(rule);
  res.status(201).json({ success: true, rule });
});

app.put('/api/rules/custom/:id', (req, res) => {
  const idx = customRules.findIndex((r) => r.id === req.params.id);
  if (idx === -1) return res.status(404).json({ success: false, error: 'Not found' });
  customRules[idx] = { ...customRules[idx], ...req.body, id: req.params.id, updatedAt: new Date().toISOString() };
  res.json({ success: true, rule: customRules[idx] });
});

app.patch('/api/rules/custom/:id', (req, res) => {
  const rule = customRules.find((r) => r.id === req.params.id);
  if (!rule) return res.status(404).json({ success: false, error: 'Not found' });
  rule.enabled = req.body.enabled;
  rule.updatedAt = new Date().toISOString();
  res.json({ success: true, id: req.params.id, enabled: rule.enabled });
});

app.delete('/api/rules/custom/:id', (req, res) => {
  const idx = customRules.findIndex((r) => r.id === req.params.id);
  if (idx === -1) return res.status(404).json({ success: false, error: 'Not found' });
  customRules.splice(idx, 1);
  res.json({ success: true });
});

// ── Alert routes ──────────────────────────────────────────────────────────────

app.get('/api/alerts/rules',    (_req, res) => res.json({ rules: alertRules }));
app.get('/api/alerts/history',  (_req, res) => res.json({ alerts: alertHistory }));

app.post('/api/alerts/rules', (req, res) => {
  const rule = { id: `rule-${Date.now()}`, ...req.body };
  alertRules.push(rule);
  res.status(201).json({ success: true, rule });
});

app.put('/api/alerts/rules/:id', (req, res) => {
  const idx = alertRules.findIndex((r) => r.id === req.params.id);
  if (idx !== -1) alertRules[idx] = { ...req.body, id: req.params.id };
  res.json({ success: true });
});

app.delete('/api/alerts/rules/:id', (req, res) => {
  const idx = alertRules.findIndex((r) => r.id === req.params.id);
  if (idx !== -1) alertRules.splice(idx, 1);
  res.json({ success: true });
});

app.post('/api/alerts/test', (_req, res) => {
  res.json({ success: true, message: 'Test email sent (dev mode — no real email)' });
});

// ── Export / Settings routes ──────────────────────────────────────────────────

app.get('/api/export/config',  (_req, res) => res.json({ config: { enabled: false, type: 'local', format: 'json', interval: 'hour' } }));
app.post('/api/export/config', (req, res)  => res.json({ success: true, config: req.body }));
app.post('/api/export/force',  (_req, res) => res.json({ success: true, message: 'Export initiated (dev mode)' }));
app.get('/api/export/status',  (_req, res) => res.json({ lastExport: new Date().toISOString(), buffered: 0 }));

app.get('/api/settings',  (_req, res) => res.json({ general: { theme:'dark', refreshInterval:30, timezone:'UTC' }, notifications: { emailEnabled:false }, export: { enabled:false } }));
app.post('/api/settings', (req, res)  => res.json({ success: true, settings: req.body }));

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = 3000;
app.listen(PORT, () => {
  console.log('');
  console.log('  ╔══════════════════════════════════════════════════╗');
  console.log('  ║   🛡️  InfiniteX WAF — Dev API Server              ║');
  console.log('  ╠══════════════════════════════════════════════════╣');
  console.log(`  ║   API:       http://localhost:${PORT}                 ║`);
  console.log(`  ║   Dashboard: http://localhost:3001               ║`);
  console.log(`  ║   Health:    http://localhost:${PORT}/api/health      ║`);
  console.log('  ║                                                  ║');
  console.log('  ║   Live traffic simulation active (every 5s)     ║');
  console.log('  ╚══════════════════════════════════════════════════╝');
  console.log('');
});
