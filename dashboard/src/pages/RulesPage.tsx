import { useState, useEffect, useCallback } from 'react';
import {
  Shield, Plus, Trash2, Edit2, ToggleLeft, ToggleRight,
  ChevronDown, ChevronUp, Search, Filter, Copy, AlertTriangle,
  CheckCircle, Lock, Zap, RefreshCw, X, Info,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { useAudit } from '../hooks/useAudit';

// ── Types (mirror backend) ────────────────────────────────────────────────────
type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
type RuleAction = 'BLOCK' | 'LOG' | 'LOGGED' | 'ALLOW' | 'CHALLENGE';
type RuleTarget = 'uri' | 'query' | 'body' | 'headers' | 'user_agent' | 'ip' | 'all';
type MatchType = 'regex' | 'contains' | 'starts_with' | 'ends_with' | 'exact' | 'ip_cidr';
type ConditionLogic = 'AND' | 'OR';

interface Condition { target: RuleTarget; matchType: MatchType; value: string; negate: boolean; }

interface BuiltInRule {
  id: string; name: string; description: string;
  severity: Severity; enabled: boolean; category: string;
  isBuiltIn: true; hitCount: number;
}

interface CustomRule {
  id: string; name: string; description: string;
  severity: Severity; action: RuleAction; enabled: boolean;
  priority: number; conditions: Condition[]; conditionLogic: ConditionLogic;
  tags: string[]; createdAt: string; updatedAt: string; hitCount: number;
}

// ── Constants ─────────────────────────────────────────────────────────────────
const SEV_STYLE: Record<Severity, string> = {
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
  HIGH:     'text-orange-400 bg-orange-500/10 border-orange-500/30',
  MEDIUM:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  LOW:      'text-green-400 bg-green-500/10 border-green-500/30',
};
const ACTION_STYLE: Record<RuleAction, string> = {
  BLOCK:     'text-red-400 bg-red-500/10',
  LOG:       'text-yellow-400 bg-yellow-500/10',
  LOGGED:    'text-blue-400 bg-blue-500/10',
  ALLOW:     'text-green-400 bg-green-500/10',
  CHALLENGE: 'text-purple-400 bg-purple-500/10',
};
const TARGETS: RuleTarget[] = ['all','uri','query','body','headers','user_agent','ip'];
const MATCH_TYPES: MatchType[] = ['contains','regex','starts_with','ends_with','exact','ip_cidr'];

const EMPTY_CONDITION: Condition = { target: 'all', matchType: 'contains', value: '', negate: false };
const EMPTY_FORM = {
  name: '', description: '', severity: 'MEDIUM' as Severity,
  action: 'BLOCK' as RuleAction, enabled: true, priority: 100,
  conditionLogic: 'AND' as ConditionLogic, conditions: [{ ...EMPTY_CONDITION }], tags: [] as string[],
};

// ── Small shared components ───────────────────────────────────────────────────
function SevBadge({ s }: { s: Severity }) {
  return <span className={`text-xs px-2 py-0.5 rounded border font-medium ${SEV_STYLE[s]}`}>{s}</span>;
}
function ActionBadge({ a }: { a: RuleAction }) {
  return <span className={`text-xs px-2 py-0.5 rounded font-medium ${ACTION_STYLE[a]}`}>{a}</span>;
}
function Toggle({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) {
  return (
    <button onClick={() => onChange(!on)} className="shrink-0" aria-label="toggle rule">
      {on
        ? <ToggleRight className="w-8 h-8 text-cyan-400" />
        : <ToggleLeft  className="w-8 h-8 text-gray-600" />}
    </button>
  );
}
function SelectField({ label, value, onChange, options }: {
  label: string; value: string; onChange: (v: string) => void; options: string[];
}) {
  return (
    <div>
      <label className="text-xs text-gray-500 block mb-1">{label}</label>
      <select value={value} onChange={(e) => onChange(e.target.value)}
        className="w-full bg-gray-800 border border-gray-700 rounded-lg px-2 py-1.5 text-sm text-white focus:outline-none focus:border-cyan-500">
        {options.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
    </div>
  );
}

// ── Built-in rule row ─────────────────────────────────────────────────────────
function BuiltInRow({ rule, onToggle }: { rule: BuiltInRule; onToggle: (id: string, v: boolean) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`border rounded-xl transition-all ${rule.enabled ? 'border-gray-700 bg-gray-900/40' : 'border-gray-800 bg-gray-900/20 opacity-60'}`}>
      <div className="flex items-center gap-3 px-4 py-3">
        <Toggle on={rule.enabled} onChange={(v) => onToggle(rule.id, v)} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-white">{rule.name}</span>
            <SevBadge s={rule.severity} />
            <span className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded">{rule.id}</span>
            <span className="text-xs bg-gray-800 text-gray-500 px-2 py-0.5 rounded">{rule.category}</span>
          </div>
          <p className="text-xs text-gray-500 mt-0.5 truncate">{rule.description}</p>
        </div>
        <div className="flex items-center gap-4 shrink-0">
          <div className="text-right hidden sm:block">
            <p className="text-sm font-semibold text-white">{rule.hitCount.toLocaleString()}</p>
            <p className="text-xs text-gray-600">hits</p>
          </div>
          <div className="flex items-center gap-1">
            <Lock className="w-3 h-3 text-gray-600" />
            <span className="text-xs text-gray-600">built-in</span>
          </div>
          <button onClick={() => setOpen((o) => !o)} className="text-gray-500 hover:text-white p-1">
            {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>
      {open && (
        <div className="px-4 pb-4 pt-1 border-t border-gray-800 grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm">
          <div className="bg-gray-800/50 rounded-lg p-3">
            <p className="text-xs text-gray-500 mb-1">Rule ID</p>
            <p className="text-white font-mono">{rule.id}</p>
          </div>
          <div className="bg-gray-800/50 rounded-lg p-3">
            <p className="text-xs text-gray-500 mb-1">Category</p>
            <p className="text-white">{rule.category}</p>
          </div>
          <div className="bg-gray-800/50 rounded-lg p-3">
            <p className="text-xs text-gray-500 mb-1">Total Hits</p>
            <p className="text-cyan-400 font-semibold">{rule.hitCount.toLocaleString()}</p>
          </div>
          <div className="sm:col-span-3 bg-gray-800/50 rounded-lg p-3">
            <p className="text-xs text-gray-500 mb-1">Description</p>
            <p className="text-gray-300">{rule.description}</p>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Custom rule row ───────────────────────────────────────────────────────────
function CustomRow({ rule, onToggle, onEdit, onDelete, onDuplicate }: {
  rule: CustomRule;
  onToggle: (id: string, v: boolean) => void;
  onEdit: (rule: CustomRule) => void;
  onDelete: (id: string) => void;
  onDuplicate: (rule: CustomRule) => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`border rounded-xl transition-all ${rule.enabled ? 'border-cyan-900/50 bg-gray-900/40' : 'border-gray-800 bg-gray-900/20 opacity-60'}`}>
      <div className="flex items-center gap-3 px-4 py-3">
        <Toggle on={rule.enabled} onChange={(v) => onToggle(rule.id, v)} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-white">{rule.name}</span>
            <SevBadge s={rule.severity} />
            <ActionBadge a={rule.action} />
            <span className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded font-mono">{rule.id}</span>
            {rule.tags.map((t) => (
              <span key={t} className="text-xs bg-cyan-500/10 text-cyan-400 px-2 py-0.5 rounded">{t}</span>
            ))}
          </div>
          <p className="text-xs text-gray-500 mt-0.5 truncate">{rule.description || 'No description'}</p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <div className="text-right hidden sm:block">
            <p className="text-sm font-semibold text-white">{rule.hitCount.toLocaleString()}</p>
            <p className="text-xs text-gray-600">hits</p>
          </div>
          <span className="text-xs text-gray-600 hidden sm:block">P{rule.priority}</span>
          <div className="flex items-center gap-1">
            <button onClick={() => onDuplicate(rule)} title="Duplicate" className="p-1.5 hover:bg-gray-800 rounded-lg text-gray-500 hover:text-white transition-colors">
              <Copy className="w-3.5 h-3.5" />
            </button>
            <button onClick={() => onEdit(rule)} title="Edit" className="p-1.5 hover:bg-gray-800 rounded-lg text-gray-500 hover:text-white transition-colors">
              <Edit2 className="w-3.5 h-3.5" />
            </button>
            <button onClick={() => onDelete(rule.id)} title="Delete" className="p-1.5 hover:bg-red-500/10 rounded-lg text-gray-500 hover:text-red-400 transition-colors">
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
          <button onClick={() => setOpen((o) => !o)} className="text-gray-500 hover:text-white p-1">
            {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>
      {open && (
        <div className="px-4 pb-4 pt-1 border-t border-gray-800 space-y-3">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm">
            <div className="bg-gray-800/50 rounded-lg p-3">
              <p className="text-xs text-gray-500 mb-1">Action</p>
              <ActionBadge a={rule.action} />
            </div>
            <div className="bg-gray-800/50 rounded-lg p-3">
              <p className="text-xs text-gray-500 mb-1">Priority</p>
              <p className="text-white">{rule.priority}</p>
            </div>
            <div className="bg-gray-800/50 rounded-lg p-3">
              <p className="text-xs text-gray-500 mb-1">Logic</p>
              <p className="text-white">{rule.conditionLogic}</p>
            </div>
            <div className="bg-gray-800/50 rounded-lg p-3">
              <p className="text-xs text-gray-500 mb-1">Conditions</p>
              <p className="text-white">{rule.conditions.length}</p>
            </div>
          </div>
          <div className="space-y-2">
            <p className="text-xs text-gray-500 uppercase tracking-wider">Conditions ({rule.conditionLogic})</p>
            {rule.conditions.map((c, i) => (
              <div key={i} className="flex items-center gap-2 bg-gray-800/50 rounded-lg px-3 py-2 text-xs font-mono flex-wrap">
                {c.negate && <span className="text-red-400">NOT</span>}
                <span className="text-cyan-400">{c.target}</span>
                <span className="text-gray-500">{c.matchType}</span>
                <span className="text-yellow-300 bg-gray-900 px-2 py-0.5 rounded">{c.value}</span>
              </div>
            ))}
          </div>
          <div className="flex gap-4 text-xs text-gray-600">
            <span>Created: {new Date(rule.createdAt).toLocaleString()}</span>
            <span>Updated: {new Date(rule.updatedAt).toLocaleString()}</span>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Rule Form Modal ───────────────────────────────────────────────────────────
function RuleFormModal({ initial, onSave, onClose }: {
  initial?: CustomRule | null;
  onSave: (data: typeof EMPTY_FORM) => void;
  onClose: () => void;
}) {
  const [form, setForm] = useState<typeof EMPTY_FORM>(
    initial
      ? { name: initial.name, description: initial.description, severity: initial.severity,
          action: initial.action, enabled: initial.enabled, priority: initial.priority,
          conditionLogic: initial.conditionLogic, conditions: initial.conditions.map((c) => ({ ...c })),
          tags: [...initial.tags] }
      : { ...EMPTY_FORM, conditions: [{ ...EMPTY_CONDITION }] }
  );
  const [tagInput, setTagInput] = useState('');
  const [testInput, setTestInput] = useState('');
  const [testResult, setTestResult] = useState<null | boolean>(null);

  function setField<K extends keyof typeof EMPTY_FORM>(k: K, v: typeof EMPTY_FORM[K]) {
    setForm((f) => ({ ...f, [k]: v }));
  }

  function addCondition() {
    setField('conditions', [...form.conditions, { ...EMPTY_CONDITION }]);
  }
  function removeCondition(i: number) {
    setField('conditions', form.conditions.filter((_, idx) => idx !== i));
  }
  function updateCondition(i: number, patch: Partial<Condition>) {
    const next = form.conditions.map((c, idx) => idx === i ? { ...c, ...patch } : c);
    setField('conditions', next);
  }
  function addTag() {
    const t = tagInput.trim();
    if (t && !form.tags.includes(t)) setField('tags', [...form.tags, t]);
    setTagInput('');
  }

  function testRule() {
    if (!testInput || !form.conditions.length) return;
    // Simple client-side test against 'contains' / 'regex' for preview
    const hit = form.conditions.some((c) => {
      try {
        if (c.matchType === 'regex') return new RegExp(c.value, 'i').test(testInput);
        if (c.matchType === 'contains') return testInput.toLowerCase().includes(c.value.toLowerCase());
        if (c.matchType === 'exact') return testInput.toLowerCase() === c.value.toLowerCase();
        if (c.matchType === 'starts_with') return testInput.toLowerCase().startsWith(c.value.toLowerCase());
        if (c.matchType === 'ends_with') return testInput.toLowerCase().endsWith(c.value.toLowerCase());
        return false;
      } catch { return false; }
    });
    setTestResult(hit);
  }

  function submit() {
    if (!form.name.trim()) { toast.error('Rule name is required'); return; }
    if (!form.conditions.length) { toast.error('Add at least one condition'); return; }
    if (form.conditions.some((c) => !c.value.trim())) { toast.error('All conditions need a value'); return; }
    onSave(form);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-2xl w-full max-w-2xl max-h-[92vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-gray-800 shrink-0">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            <Zap className="w-5 h-5 text-cyan-400" />
            {initial ? 'Edit Custom Rule' : 'Create Custom Rule'}
          </h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white p-1"><X className="w-5 h-5" /></button>
        </div>

        <div className="overflow-y-auto flex-1 p-5 space-y-5">
          {/* Basic info */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="sm:col-span-2">
              <label className="text-xs text-gray-500 block mb-1">Rule Name *</label>
              <input value={form.name} onChange={(e) => setField('name', e.target.value)}
                placeholder="e.g. Block Admin Brute Force"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500" />
            </div>
            <div className="sm:col-span-2">
              <label className="text-xs text-gray-500 block mb-1">Description</label>
              <input value={form.description} onChange={(e) => setField('description', e.target.value)}
                placeholder="What does this rule protect against?"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500" />
            </div>
            <SelectField label="Severity" value={form.severity} onChange={(v) => setField('severity', v as Severity)} options={['CRITICAL','HIGH','MEDIUM','LOW']} />
            <SelectField label="Action" value={form.action} onChange={(v) => setField('action', v as RuleAction)} options={['BLOCK','LOG','LOGGED','ALLOW','CHALLENGE']} />
            <div>
              <label className="text-xs text-gray-500 block mb-1">Priority (lower = first)</label>
              <input type="number" value={form.priority} onChange={(e) => setField('priority', +e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500" />
            </div>
            <SelectField label="Condition Logic" value={form.conditionLogic} onChange={(v) => setField('conditionLogic', v as ConditionLogic)} options={['AND','OR']} />
          </div>

          {/* Conditions */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <p className="text-xs text-gray-500 uppercase tracking-wider">
                Conditions — match {form.conditionLogic === 'AND' ? 'ALL' : 'ANY'}
              </p>
              <button onClick={addCondition}
                className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 px-2 py-1 rounded-lg hover:bg-cyan-500/10 transition-colors">
                <Plus className="w-3 h-3" /> Add condition
              </button>
            </div>
            <div className="space-y-2">
              {form.conditions.map((cond, i) => (
                <div key={i} className="grid grid-cols-[1fr_1fr_1fr_auto_auto] gap-2 items-end bg-gray-800/50 rounded-xl p-3">
                  <SelectField label="Target" value={cond.target} onChange={(v) => updateCondition(i, { target: v as RuleTarget })} options={TARGETS} />
                  <SelectField label="Match" value={cond.matchType} onChange={(v) => updateCondition(i, { matchType: v as MatchType })} options={MATCH_TYPES} />
                  <div>
                    <label className="text-xs text-gray-500 block mb-1">Value *</label>
                    <input value={cond.value} onChange={(e) => updateCondition(i, { value: e.target.value })}
                      placeholder={cond.matchType === 'regex' ? '/pattern/i' : 'match value'}
                      className="w-full bg-gray-900 border border-gray-700 rounded-lg px-2 py-1.5 text-sm text-white font-mono placeholder-gray-600 focus:outline-none focus:border-cyan-500" />
                  </div>
                  <div className="flex flex-col items-center gap-1 pb-0.5">
                    <label className="text-xs text-gray-500">NOT</label>
                    <input type="checkbox" checked={cond.negate} onChange={(e) => updateCondition(i, { negate: e.target.checked })}
                      className="w-4 h-4 accent-cyan-500" />
                  </div>
                  <button onClick={() => removeCondition(i)} disabled={form.conditions.length === 1}
                    className="pb-0.5 text-gray-600 hover:text-red-400 disabled:opacity-30 transition-colors">
                    <X className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Tags */}
          <div>
            <label className="text-xs text-gray-500 block mb-2">Tags</label>
            <div className="flex gap-2 mb-2">
              <input value={tagInput} onChange={(e) => setTagInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && addTag()}
                placeholder="e.g. custom, brute-force"
                className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500" />
              <button onClick={addTag} className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 hover:text-white">Add</button>
            </div>
            <div className="flex flex-wrap gap-1">
              {form.tags.map((t) => (
                <span key={t} className="flex items-center gap-1 text-xs bg-cyan-500/10 text-cyan-400 px-2 py-0.5 rounded-full">
                  {t}
                  <button onClick={() => setField('tags', form.tags.filter((x) => x !== t))} className="hover:text-red-400">×</button>
                </span>
              ))}
            </div>
          </div>

          {/* Live test */}
          <div className="bg-gray-800/50 rounded-xl p-4 border border-gray-700">
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-1">
              <Info className="w-3 h-3" /> Test Rule (client-side preview)
            </p>
            <div className="flex gap-2">
              <input value={testInput} onChange={(e) => { setTestInput(e.target.value); setTestResult(null); }}
                placeholder="Paste a sample URI, payload, or user-agent to test"
                className="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white font-mono placeholder-gray-600 focus:outline-none focus:border-cyan-500" />
              <button onClick={testRule} className="px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm hover:bg-cyan-500/30 transition-colors">
                Test
              </button>
            </div>
            {testResult !== null && (
              <div className={`mt-2 flex items-center gap-2 text-sm ${testResult ? 'text-red-400' : 'text-green-400'}`}>
                {testResult
                  ? <><AlertTriangle className="w-4 h-4" /> Rule MATCHES — would {form.action}</>
                  : <><CheckCircle className="w-4 h-4" /> No match — request would pass</>}
              </div>
            )}
          </div>

          {/* Enable toggle */}
          <div className="flex items-center gap-3">
            <input type="checkbox" id="rule-enabled" checked={form.enabled} onChange={(e) => setField('enabled', e.target.checked)} className="w-4 h-4 accent-cyan-500" />
            <label htmlFor="rule-enabled" className="text-sm text-gray-300">Enable rule immediately after saving</label>
          </div>
        </div>

        {/* Footer */}
        <div className="p-5 border-t border-gray-800 flex gap-3 justify-end shrink-0">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors">Cancel</button>
          <button onClick={submit} className="px-5 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-xl text-sm font-medium transition-colors">
            {initial ? 'Save Changes' : 'Create Rule'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Static built-in rule definitions (always shown, state synced from API) ───
const BUILTIN_RULES_STATIC: BuiltInRule[] = [
  { id: 'SQLI-001',   name: 'InfiniteXManagedSQLiRuleSets',   description: 'Managed SQL injection protection aligned with AWS WAF managed rule groups', category: 'InfiniteXManagedRuleSets', severity: 'CRITICAL', enabled: true,  isBuiltIn: true, hitCount: 0 },
  { id: 'XSS-001',    name: 'InfiniteXManagedOWASPRuleSets',  description: 'Managed OWASP Top 10 protection for common web attacks',                category: 'InfiniteXManagedRuleSets', severity: 'CRITICAL', enabled: true,  isBuiltIn: true, hitCount: 0 },
  { id: 'PT-001',     name: 'InfiniteXManagedPathTraversalRuleSets', description: 'Managed traversal protection for path traversal and directory traversal attempts', category: 'InfiniteXManagedRuleSets', severity: 'HIGH', enabled: true,  isBuiltIn: true, hitCount: 0 },
  { id: 'CMDI-001',   name: 'InfiniteXManagedCommandInjectionRuleSets', description: 'Managed command injection protection for shell and code execution payloads', category: 'InfiniteXManagedRuleSets', severity: 'CRITICAL', enabled: true,  isBuiltIn: true, hitCount: 0 },
  { id: 'NOSQLI-001', name: 'InfiniteXManagedNoSQLRuleSets',   description: 'Managed NoSQL injection protection for database operators',              category: 'InfiniteXManagedRuleSets', severity: 'CRITICAL', enabled: true,  isBuiltIn: true, hitCount: 0 },
  { id: 'SSRF-001',   name: 'InfiniteXManagedSSRFRuleSets',   description: 'Managed SSRF protection for internal service access attempts',          category: 'InfiniteXManagedRuleSets', severity: 'HIGH', enabled: true,  isBuiltIn: true, hitCount: 0 },
  { id: 'BOT-001',    name: 'InfiniteXManagedBotProtectionRuleSets', description: 'Managed bot and scanner protection with configurable actions',      category: 'InfiniteXManagedRuleSets', severity: 'MEDIUM', enabled: true,  isBuiltIn: true, hitCount: 0 },
  { id: 'RATE-001',   name: 'InfiniteXManagedRateLimitRuleSets', description: 'Managed rate limiting rules for burst and abuse prevention',         category: 'InfiniteXManagedRuleSets', severity: 'MEDIUM', enabled: true,  isBuiltIn: true, hitCount: 0 },
  { id: 'NULL-001',   name: 'InfiniteXManagedNullByteRuleSets', description: 'Managed null-byte injection protection for binary payloads',        category: 'InfiniteXManagedRuleSets', severity: 'HIGH', enabled: true,  isBuiltIn: true, hitCount: 0 },
  { id: 'METH-001',   name: 'InfiniteXManagedAdminProtectionRuleSets', description: 'Managed admin protection for sensitive endpoints and invalid method traffic', category: 'InfiniteXManagedRuleSets', severity: 'MEDIUM', enabled: true,  isBuiltIn: true, hitCount: 0 },
  { id: 'CT-001',     name: 'InfiniteXManagedContentTypeRuleSets', description: 'Managed content-type validation for stricter protocol enforcement', category: 'InfiniteXManagedRuleSets', severity: 'LOW', enabled: false, isBuiltIn: true, hitCount: 0 },
  { id: 'GEO-001',    name: 'InfiniteXManagedGeoRestrictionRuleSets', description: 'Managed geo restriction rules that can block or log selected country traffic', category: 'InfiniteXManagedRuleSets', severity: 'MEDIUM', enabled: true,  isBuiltIn: true, hitCount: 0 },
  { id: 'ANON-001',   name: 'InfiniteXManagedAnonymousRuleSets', description: 'Managed anonymous IP protection for VPN, proxy and TOR traffic', category: 'InfiniteXManagedRuleSets', severity: 'MEDIUM', enabled: true,  isBuiltIn: true, hitCount: 0 },
  { id: 'THREAT-INTEL-001', name: 'InfiniteXManagedIPReputationRuleSets', description: 'Managed IP reputation enforcement for known hostile source IPs', category: 'InfiniteXManagedRuleSets', severity: 'HIGH', enabled: true, isBuiltIn: true, hitCount: 0 },
];
export function RulesPage() {
  const [builtIn, setBuiltIn] = useState<BuiltInRule[]>([]);
  const [custom, setCustom] = useState<CustomRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<'builtin' | 'custom'>('builtin');
  const [search, setSearch] = useState('');
  const [filterSev, setFilterSev] = useState<Severity | 'ALL'>('ALL');
  const [filterEnabled, setFilterEnabled] = useState<'ALL' | 'ON' | 'OFF'>('ALL');
  const [showForm, setShowForm] = useState(false);
  const [editRule, setEditRule] = useState<CustomRule | null>(null);

  const audit = useAudit();

  const load = useCallback(async () => {
    // Always show static built-in rules immediately — no blank state
    setBuiltIn(BUILTIN_RULES_STATIC);
    try {
      const [b, c] = await Promise.all([
        fetch('/api/rules/builtin').then((r) => r.json()),
        fetch('/api/rules/custom').then((r) => r.json()),
      ]);
      // Merge live enabled/hitCount state from API onto static definitions
      const apiMap = new Map<string, { enabled: boolean; hitCount: number }>(
        (b.rules ?? []).map((r: BuiltInRule) => [r.id, { enabled: r.enabled, hitCount: r.hitCount }])
      );
      setBuiltIn(BUILTIN_RULES_STATIC.map((r) => {
        const live = apiMap.get(r.id);
        return live ? { ...r, enabled: live.enabled, hitCount: live.hitCount } : r;
      }));
      setCustom(c.rules ?? []);
    } catch {
      // API unreachable — static rules already shown with default state
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // ── Built-in toggle ──────────────────────────────────────────────────────
  async function toggleBuiltIn(id: string, enabled: boolean) {
    // Optimistic update — UI responds instantly even if API is slow
    setBuiltIn((prev) => prev.map((r) => r.id === id ? { ...r, enabled } : r));
    try {
      await fetch(`/api/rules/builtin/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });
      toast.success(`Rule ${id} ${enabled ? 'enabled' : 'disabled'}`);
      audit(enabled ? 'RULE_ENABLED' : 'RULE_DISABLED', `Built-in rule ${id} ${enabled ? 'enabled' : 'disabled'}`, enabled ? 'info' : 'warning');
    } catch {
      // Revert on failure
      setBuiltIn((prev) => prev.map((r) => r.id === id ? { ...r, enabled: !enabled } : r));
      toast.error('Failed to update rule — API unreachable');
    }
  }

  // ── Custom CRUD ──────────────────────────────────────────────────────────
  async function saveCustom(form: typeof EMPTY_FORM) {
    try {
      if (editRule) {
        const res = await fetch(`/api/rules/custom/${editRule.id}`, {
          method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form),
        });
        const data = await res.json();
        setCustom((prev) => prev.map((r) => r.id === editRule.id ? data.rule : r));
        toast.success('Rule updated');
        audit('RULE_UPDATED', `Custom rule updated: ${form.name}`, 'info');
      } else {
        const res = await fetch('/api/rules/custom', {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form),
        });
        const data = await res.json();
        setCustom((prev) => [...prev, data.rule]);
        toast.success('Custom rule created');
        audit('RULE_CREATED', `Custom rule created: ${form.name}`, 'info');
      }
      setShowForm(false); setEditRule(null);
    } catch { toast.error('Failed to save rule'); }
  }

  async function toggleCustom(id: string, enabled: boolean) {
    try {
      await fetch(`/api/rules/custom/${id}`, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }),
      });
      setCustom((prev) => prev.map((r) => r.id === id ? { ...r, enabled } : r));
      toast.success(`Rule ${enabled ? 'enabled' : 'disabled'}`);
    } catch { toast.error('Failed to update rule'); }
  }

  async function deleteCustom(id: string) {
    if (!confirm('Delete this rule?')) return;
    try {
      await fetch(`/api/rules/custom/${id}`, { method: 'DELETE' });
      setCustom((prev) => prev.filter((r) => r.id !== id));
      toast.success('Rule deleted');
      audit('RULE_DELETED', `Custom rule deleted: ${id}`, 'warning');
    } catch { toast.error('Failed to delete rule'); }
  }

  function duplicateCustom(rule: CustomRule) {
    setEditRule(null);
    setShowForm(true);
    // Pre-fill form with copy
    setTimeout(() => {
      setEditRule({ ...rule, id: '', name: `${rule.name} (copy)` } as any);
    }, 0);
  }

  // ── Filtering ────────────────────────────────────────────────────────────
  const filteredBuiltIn = builtIn.filter((r) => {
    const q = search.toLowerCase();
    if (q && !r.name.toLowerCase().includes(q) && !r.id.toLowerCase().includes(q)) return false;
    if (filterSev !== 'ALL' && r.severity !== filterSev) return false;
    if (filterEnabled === 'ON' && !r.enabled) return false;
    if (filterEnabled === 'OFF' && r.enabled) return false;
    return true;
  });

  const filteredCustom = custom.filter((r) => {
    const q = search.toLowerCase();
    if (q && !r.name.toLowerCase().includes(q) && !r.id.toLowerCase().includes(q) &&
        !r.tags.some((t) => t.toLowerCase().includes(q))) return false;
    if (filterSev !== 'ALL' && r.severity !== filterSev) return false;
    if (filterEnabled === 'ON' && !r.enabled) return false;
    if (filterEnabled === 'OFF' && r.enabled) return false;
    return true;
  });

  const enabledBuiltIn = builtIn.filter((r) => r.enabled).length;
  const enabledCustom  = custom.filter((r) => r.enabled).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-cyan-400" /> WAF Rules Console
          </h2>
          <p className="text-gray-400 text-sm mt-1">Enable / disable built-in rules and manage custom detection rules</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load} className="p-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white transition-colors" title="Refresh">
            <RefreshCw className="w-4 h-4" />
          </button>
          <button onClick={() => { setEditRule(null); setShowForm(true); }}
            className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-xl text-sm font-medium transition-colors">
            <Plus className="w-4 h-4" /> New Custom Rule
          </button>
        </div>
      </div>

      {/* Summary pills */}
      <div className="flex flex-wrap gap-3">
        {[
          { label: 'Built-in Rules', value: builtIn.length, color: 'text-white' },
          { label: 'Built-in Active', value: enabledBuiltIn, color: 'text-green-400' },
          { label: 'Custom Rules', value: custom.length, color: 'text-cyan-400' },
          { label: 'Custom Active', value: enabledCustom, color: 'text-cyan-400' },
          { label: 'Total Active', value: enabledBuiltIn + enabledCustom, color: 'text-yellow-400' },
        ].map((p) => (
          <div key={p.label} className="flex flex-col items-center bg-gray-900/50 border border-gray-800 rounded-xl px-4 py-2.5 min-w-[90px]">
            <span className={`text-xl font-bold ${p.color}`}>{p.value}</span>
            <span className="text-xs text-gray-500 mt-0.5 text-center">{p.label}</span>
          </div>
        ))}
      </div>

      {/* Search + filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="Search rules by name, ID or tag…"
            className="w-full bg-gray-900/50 border border-gray-800 rounded-xl pl-9 pr-4 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500" />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-500" />
          <select value={filterSev} onChange={(e) => setFilterSev(e.target.value as any)}
            className="bg-gray-900/50 border border-gray-800 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500">
            <option value="ALL">All Severities</option>
            {(['CRITICAL','HIGH','MEDIUM','LOW'] as Severity[]).map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={filterEnabled} onChange={(e) => setFilterEnabled(e.target.value as any)}
            className="bg-gray-900/50 border border-gray-800 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500">
            <option value="ALL">All States</option>
            <option value="ON">Enabled</option>
            <option value="OFF">Disabled</option>
          </select>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-800">
        {([
          { key: 'builtin', label: `Built-in Rules (${filteredBuiltIn.length})`, icon: Lock },
          { key: 'custom',  label: `Custom Rules (${filteredCustom.length})`,  icon: Zap  },
        ] as const).map(({ key, label, icon: Icon }) => (
          <button key={key} onClick={() => setTab(key)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm border-b-2 transition-all -mb-px ${
              tab === key ? 'border-cyan-400 text-cyan-400' : 'border-transparent text-gray-400 hover:text-white'
            }`}>
            <Icon className="w-4 h-4" />{label}
          </button>
        ))}
      </div>

      {/* Rule lists */}
      {loading ? (
        <div className="flex items-center justify-center py-16">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400" />
        </div>
      ) : tab === 'builtin' ? (
        <div className="space-y-2">
          {filteredBuiltIn.length === 0 && (
            <div className="text-center py-12 text-gray-500">No rules match your filters</div>
          )}
          {filteredBuiltIn.map((r) => (
            <BuiltInRow key={r.id} rule={r} onToggle={toggleBuiltIn} />
          ))}
        </div>
      ) : (
        <div className="space-y-2">
          {filteredCustom.length === 0 && (
            <div className="text-center py-12 space-y-3">
              <Shield className="w-12 h-12 text-gray-700 mx-auto" />
              <p className="text-gray-500">No custom rules yet</p>
              <button onClick={() => { setEditRule(null); setShowForm(true); }}
                className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-xl text-sm hover:bg-cyan-500/30 transition-colors">
                <Plus className="w-4 h-4" /> Create your first custom rule
              </button>
            </div>
          )}
          {filteredCustom.map((r) => (
            <CustomRow key={r.id} rule={r}
              onToggle={toggleCustom}
              onEdit={(rule) => { setEditRule(rule); setShowForm(true); }}
              onDelete={deleteCustom}
              onDuplicate={duplicateCustom}
            />
          ))}
        </div>
      )}

      {/* Form modal */}
      {showForm && (
        <RuleFormModal
          initial={editRule}
          onSave={saveCustom}
          onClose={() => { setShowForm(false); setEditRule(null); }}
        />
      )}
    </div>
  );
}
