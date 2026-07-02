import { useState, useEffect } from 'react';
import { AlertTriangle, Plus, Trash2, Bell, Mail, CheckCircle, XCircle, Edit2 } from 'lucide-react';
import toast from 'react-hot-toast';

interface AlertRule {
  id: string;
  name: string;
  enabled: boolean;
  type: 'rate_limit' | 'threat' | 'ddos' | 'bot' | 'error_rate' | 'custom';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  threshold: number;
  timeWindow: number;
  emailRecipients: string[];
  cooldownMinutes: number;
}

interface AlertEvent {
  id: string;
  ruleName: string;
  severity: string;
  timestamp: string;
  message: string;
  resolved: boolean;
}

const SEV_COLORS: Record<string, string> = {
  LOW: 'text-green-400 bg-green-500/10 border-green-500/30',
  MEDIUM: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  HIGH: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
};

const EMPTY_RULE: Omit<AlertRule, 'id'> = {
  name: '',
  enabled: true,
  type: 'threat',
  severity: 'HIGH',
  threshold: 50,
  timeWindow: 60,
  emailRecipients: [],
  cooldownMinutes: 15,
};

export function AlertsPage() {
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [history, setHistory] = useState<AlertEvent[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [editRule, setEditRule] = useState<AlertRule | null>(null);
  const [form, setForm] = useState(EMPTY_RULE);
  const [emailInput, setEmailInput] = useState('');
  const [testEmail, setTestEmail] = useState('');
  const [activeTab, setActiveTab] = useState<'rules' | 'history'>('rules');

  useEffect(() => {
    fetchRules();
    fetchHistory();
  }, []);

  async function fetchRules() {
    try {
      const res = await fetch('/api/alerts/rules');
      const data = await res.json();
      setRules(data.rules || []);
    } catch { /* use empty */ }
  }

  async function fetchHistory() {
    try {
      const res = await fetch('/api/alerts/history');
      const data = await res.json();
      setHistory(data.alerts || []);
    } catch { /* use empty */ }
  }

  async function saveRule() {
    if (!form.name.trim()) { toast.error('Rule name is required'); return; }
    if (form.emailRecipients.length === 0) { toast.error('Add at least one email recipient'); return; }

    try {
      const method = editRule ? 'PUT' : 'POST';
      const url = editRule ? `/api/alerts/rules/${editRule.id}` : '/api/alerts/rules';
      const body = editRule ? { ...form, id: editRule.id } : form;

      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (res.ok) {
        toast.success(editRule ? 'Alert rule updated' : 'Alert rule created');
        setShowForm(false);
        setEditRule(null);
        setForm(EMPTY_RULE);
        fetchRules();
      }
    } catch {
      toast.error('Failed to save rule');
    }
  }

  async function deleteRule(id: string) {
    try {
      await fetch(`/api/alerts/rules/${id}`, { method: 'DELETE' });
      toast.success('Rule deleted');
      fetchRules();
    } catch {
      toast.error('Failed to delete rule');
    }
  }

  async function sendTestEmail() {
    if (!testEmail) { toast.error('Enter an email address'); return; }
    try {
      const res = await fetch('/api/alerts/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipients: [testEmail], emailConfig: {} }),
      });
      const data = await res.json();
      if (data.success) toast.success('Test email sent');
      else toast.error('Failed to send test email');
    } catch {
      toast.error('Failed to send test email');
    }
  }

  function openEdit(rule: AlertRule) {
    setEditRule(rule);
    setForm({ ...rule });
    setShowForm(true);
  }

  function addEmail() {
    const email = emailInput.trim();
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      toast.error('Enter a valid email');
      return;
    }
    if (!form.emailRecipients.includes(email)) {
      setForm((f) => ({ ...f, emailRecipients: [...f.emailRecipients, email] }));
    }
    setEmailInput('');
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Alert Configuration</h2>
          <p className="text-gray-400 text-sm mt-1">Configure alert rules and email notifications</p>
        </div>
        <button
          onClick={() => { setEditRule(null); setForm(EMPTY_RULE); setShowForm(true); }}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-xl text-sm transition-colors"
        >
          <Plus className="w-4 h-4" /> New Alert Rule
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-gray-800 pb-0">
        {(['rules', 'history'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm capitalize border-b-2 transition-all -mb-px ${
              activeTab === tab
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            {tab === 'rules' ? 'Alert Rules' : 'Alert History'}
          </button>
        ))}
      </div>

      {activeTab === 'rules' && (
        <>
          {/* Test Email */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-5">
            <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
              <Mail className="w-4 h-4 text-cyan-400" /> Test Email Notification
            </h3>
            <div className="flex gap-3">
              <input
                type="email"
                value={testEmail}
                onChange={(e) => setTestEmail(e.target.value)}
                placeholder="test@example.com"
                className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
              />
              <button
                onClick={sendTestEmail}
                className="px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm hover:bg-cyan-500/30 transition-colors"
              >
                Send Test
              </button>
            </div>
          </div>

          {/* Rules List */}
          <div className="space-y-3">
            {rules.length === 0 && (
              <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-10 text-center">
                <Bell className="w-10 h-10 text-gray-600 mx-auto mb-3" />
                <p className="text-gray-400">No alert rules configured yet</p>
                <p className="text-gray-600 text-sm mt-1">Create a rule to start receiving notifications</p>
              </div>
            )}
            {rules.map((rule) => (
              <div key={rule.id} className="bg-gray-900/50 border border-gray-800 rounded-2xl p-5">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-3">
                    <div className={`mt-0.5 w-2 h-2 rounded-full ${rule.enabled ? 'bg-green-500' : 'bg-gray-600'}`} />
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="text-white font-medium">{rule.name}</p>
                        <span className={`text-xs px-2 py-0.5 rounded border ${SEV_COLORS[rule.severity]}`}>
                          {rule.severity}
                        </span>
                        <span className="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-400 capitalize">
                          {rule.type.replace('_', ' ')}
                        </span>
                      </div>
                      <p className="text-sm text-gray-400 mt-1">
                        Threshold: {rule.threshold} events in {rule.timeWindow}s · Cooldown: {rule.cooldownMinutes}min
                      </p>
                      <div className="flex flex-wrap gap-1 mt-2">
                        {rule.emailRecipients.map((email) => (
                          <span key={email} className="text-xs bg-gray-800 text-gray-300 px-2 py-0.5 rounded-full flex items-center gap-1">
                            <Mail className="w-3 h-3" /> {email}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button onClick={() => openEdit(rule)} className="p-2 hover:bg-gray-800 rounded-lg transition-colors text-gray-400 hover:text-white">
                      <Edit2 className="w-4 h-4" />
                    </button>
                    <button onClick={() => deleteRule(rule.id)} className="p-2 hover:bg-red-500/10 rounded-lg transition-colors text-gray-400 hover:text-red-400">
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {activeTab === 'history' && (
        <div className="space-y-3">
          {history.length === 0 && (
            <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-10 text-center">
              <AlertTriangle className="w-10 h-10 text-gray-600 mx-auto mb-3" />
              <p className="text-gray-400">No alerts triggered yet</p>
            </div>
          )}
          {history.map((event) => (
            <div key={event.id} className="bg-gray-900/50 border border-gray-800 rounded-2xl p-5">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3">
                  {event.resolved
                    ? <CheckCircle className="w-5 h-5 text-green-400 mt-0.5 shrink-0" />
                    : <XCircle className="w-5 h-5 text-red-400 mt-0.5 shrink-0" />
                  }
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="text-white font-medium">{event.ruleName}</p>
                      <span className={`text-xs px-2 py-0.5 rounded border ${SEV_COLORS[event.severity] || ''}`}>
                        {event.severity}
                      </span>
                    </div>
                    <p className="text-sm text-gray-400 mt-1">{event.message}</p>
                    <p className="text-xs text-gray-600 mt-1">{new Date(event.timestamp).toLocaleString()}</p>
                  </div>
                </div>
                <span className={`text-xs px-2 py-1 rounded ${event.resolved ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'}`}>
                  {event.resolved ? 'Resolved' : 'Active'}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Alert Rule Form Modal */}
      {showForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-gray-900 border border-gray-700 rounded-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-800 flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white">{editRule ? 'Edit Alert Rule' : 'New Alert Rule'}</h3>
              <button onClick={() => { setShowForm(false); setEditRule(null); }} className="text-gray-400 hover:text-white">
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="text-sm text-gray-400 block mb-1">Rule Name</label>
                <input
                  value={form.name}
                  onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                  placeholder="e.g. High Bot Traffic Alert"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm text-gray-400 block mb-1">Alert Type</label>
                  <select
                    value={form.type}
                    onChange={(e) => setForm((f) => ({ ...f, type: e.target.value as AlertRule['type'] }))}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="rate_limit">Rate Limit</option>
                    <option value="threat">Threat</option>
                    <option value="ddos">DDoS</option>
                    <option value="bot">Bot Traffic</option>
                    <option value="error_rate">Error Rate</option>
                    <option value="custom">Custom</option>
                  </select>
                </div>
                <div>
                  <label className="text-sm text-gray-400 block mb-1">Severity</label>
                  <select
                    value={form.severity}
                    onChange={(e) => setForm((f) => ({ ...f, severity: e.target.value as AlertRule['severity'] }))}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  >
                    <option value="LOW">Low</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="HIGH">High</option>
                    <option value="CRITICAL">Critical</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="text-sm text-gray-400 block mb-1">Threshold</label>
                  <input
                    type="number"
                    value={form.threshold}
                    onChange={(e) => setForm((f) => ({ ...f, threshold: +e.target.value }))}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="text-sm text-gray-400 block mb-1">Time Window (s)</label>
                  <input
                    type="number"
                    value={form.timeWindow}
                    onChange={(e) => setForm((f) => ({ ...f, timeWindow: +e.target.value }))}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="text-sm text-gray-400 block mb-1">Cooldown (min)</label>
                  <input
                    type="number"
                    value={form.cooldownMinutes}
                    onChange={(e) => setForm((f) => ({ ...f, cooldownMinutes: +e.target.value }))}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div>
                <label className="text-sm text-gray-400 block mb-1">Email Recipients</label>
                <div className="flex gap-2 mb-2">
                  <input
                    type="email"
                    value={emailInput}
                    onChange={(e) => setEmailInput(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && addEmail()}
                    placeholder="admin@example.com"
                    className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
                  />
                  <button onClick={addEmail} className="px-3 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-sm hover:bg-cyan-500/30">
                    Add
                  </button>
                </div>
                <div className="flex flex-wrap gap-2">
                  {form.emailRecipients.map((email) => (
                    <span key={email} className="flex items-center gap-1 text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded-full">
                      {email}
                      <button
                        onClick={() => setForm((f) => ({ ...f, emailRecipients: f.emailRecipients.filter((e) => e !== email) }))}
                        className="text-gray-500 hover:text-red-400 ml-1"
                      >×</button>
                    </span>
                  ))}
                </div>
              </div>

              <div className="flex items-center gap-3">
                <input
                  type="checkbox"
                  id="enabled"
                  checked={form.enabled}
                  onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
                  className="w-4 h-4 accent-cyan-500"
                />
                <label htmlFor="enabled" className="text-sm text-gray-300">Enable this rule</label>
              </div>
            </div>
            <div className="p-6 border-t border-gray-800 flex gap-3 justify-end">
              <button
                onClick={() => { setShowForm(false); setEditRule(null); }}
                className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={saveRule}
                className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-xl text-sm transition-colors"
              >
                {editRule ? 'Update Rule' : 'Create Rule'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
