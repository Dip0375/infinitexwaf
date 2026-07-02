import { useState, useEffect } from 'react';
import { useAuditLog, AuditEntry, AuditAction } from '../context/AuditLogContext';
import { useAuth } from '../context/AuthContext';
import {
  ClipboardList, Trash2, RefreshCw, Search, Filter,
  LogIn, LogOut, Shield, Bell, Settings, FileBarChart,
  Eye, AlertTriangle, Info, Clock, User,
} from 'lucide-react';

const ACTION_META: Record<AuditAction, { label: string; icon: any; color: string }> = {
  LOGIN:            { label: 'Login',            icon: LogIn,       color: 'text-green-400'  },
  LOGOUT:           { label: 'Logout',           icon: LogOut,      color: 'text-gray-400'   },
  RULE_ENABLED:     { label: 'Rule Enabled',     icon: Shield,      color: 'text-cyan-400'   },
  RULE_DISABLED:    { label: 'Rule Disabled',    icon: Shield,      color: 'text-yellow-400' },
  RULE_CREATED:     { label: 'Rule Created',     icon: Shield,      color: 'text-green-400'  },
  RULE_UPDATED:     { label: 'Rule Updated',     icon: Shield,      color: 'text-blue-400'   },
  RULE_DELETED:     { label: 'Rule Deleted',     icon: Shield,      color: 'text-red-400'    },
  ALERT_CREATED:    { label: 'Alert Created',    icon: Bell,        color: 'text-green-400'  },
  ALERT_DELETED:    { label: 'Alert Deleted',    icon: Bell,        color: 'text-red-400'    },
  ALERT_TESTED:     { label: 'Alert Tested',     icon: Bell,        color: 'text-blue-400'   },
  SETTINGS_UPDATED: { label: 'Settings Updated', icon: Settings,    color: 'text-purple-400' },
  EXPORT_TRIGGERED: { label: 'Export Triggered', icon: FileBarChart,color: 'text-cyan-400'   },
  REPORT_GENERATED: { label: 'Report Generated', icon: FileBarChart,color: 'text-cyan-400'   },
  PAGE_VIEWED:      { label: 'Page Viewed',      icon: Eye,         color: 'text-gray-400'   },
};

const SEV_STYLE: Record<AuditEntry['severity'], string> = {
  info:     'text-blue-400 bg-blue-500/10 border-blue-500/30',
  warning:  'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  critical: 'text-red-400 bg-red-500/10 border-red-500/30',
};

const SEV_ICON: Record<AuditEntry['severity'], any> = {
  info:     Info,
  warning:  AlertTriangle,
  critical: AlertTriangle,
};

const FLUSH_MS = 15 * 60 * 1000;

export function AuditLogPage() {
  const { entries, clear } = useAuditLog();
  const { user } = useAuth();
  const [search, setSearch] = useState('');
  const [filterSev, setFilterSev] = useState<AuditEntry['severity'] | 'all'>('all');
  const [filterAction, setFilterAction] = useState<string>('all');
  const [nextFlush, setNextFlush] = useState('');
  const [now, setNow] = useState(Date.now());

  // Tick every second for countdown + expiry bars
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  // Compute next flush time (15 min from page load, resets on clear)
  useEffect(() => {
    const target = Date.now() + FLUSH_MS;
    const tick = setInterval(() => {
      const remaining = target - Date.now();
      if (remaining <= 0) { setNextFlush('Flushing…'); return; }
      const m = Math.floor(remaining / 60000);
      const s = Math.floor((remaining % 60000) / 1000);
      setNextFlush(`${m}m ${String(s).padStart(2, '0')}s`);
    }, 1000);
    return () => clearInterval(tick);
  }, [entries.length === 0]); // reset when cleared

  const filtered = entries.filter((e) => {
    if (filterSev !== 'all' && e.severity !== filterSev) return false;
    if (filterAction !== 'all' && e.action !== filterAction) return false;
    const q = search.toLowerCase();
    if (q && !e.user.toLowerCase().includes(q) && !e.detail.toLowerCase().includes(q) && !e.action.toLowerCase().includes(q)) return false;
    return true;
  });

  const uniqueActions = [...new Set(entries.map((e) => e.action))];

  function timeAgo(iso: string) {
    const diff = now - new Date(iso).getTime();
    if (diff < 60000) return `${Math.floor(diff / 1000)}s ago`;
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    return new Date(iso).toLocaleTimeString();
  }

  function expiryPct(expiresAt: string) {
    const created = new Date(expiresAt).getTime() - FLUSH_MS;
    const total = FLUSH_MS;
    const elapsed = now - created;
    return Math.min(100, Math.round((elapsed / total) * 100));
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <ClipboardList className="w-6 h-6 text-cyan-400" /> Audit Log
          </h2>
          <p className="text-gray-400 text-sm mt-1">
            All console actions are logged here. Entries auto-flush every 15 minutes.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Countdown */}
          <div className="flex items-center gap-2 text-xs bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 px-3 py-2 rounded-xl">
            <Clock className="w-3.5 h-3.5" />
            Auto-flush in {nextFlush || '15m 00s'}
          </div>
          <button
            onClick={clear}
            className="flex items-center gap-2 px-3 py-2 bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 rounded-xl text-sm transition-colors"
          >
            <Trash2 className="w-4 h-4" /> Clear Now
          </button>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Total Entries', value: entries.length, color: 'text-white' },
          { label: 'Info',     value: entries.filter((e) => e.severity === 'info').length,     color: 'text-blue-400'   },
          { label: 'Warnings', value: entries.filter((e) => e.severity === 'warning').length,  color: 'text-yellow-400' },
          { label: 'Critical', value: entries.filter((e) => e.severity === 'critical').length, color: 'text-red-400'    },
        ].map((s) => (
          <div key={s.label} className="bg-gray-900/50 border border-gray-800 rounded-xl px-4 py-3 flex items-center gap-3">
            <span className={`text-2xl font-bold ${s.color}`}>{s.value}</span>
            <span className="text-xs text-gray-500">{s.label}</span>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search user, action, detail…"
            className="w-full bg-gray-900/50 border border-gray-800 rounded-xl pl-9 pr-4 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-500" />
          <select
            value={filterSev}
            onChange={(e) => setFilterSev(e.target.value as any)}
            className="bg-gray-900/50 border border-gray-800 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Severities</option>
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
          </select>
          <select
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            className="bg-gray-900/50 border border-gray-800 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Actions</option>
            {uniqueActions.map((a) => (
              <option key={a} value={a}>{ACTION_META[a]?.label ?? a}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Log table */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-2xl overflow-hidden">
        {/* Table header */}
        <div className="grid grid-cols-[140px_100px_120px_1fr_80px_90px] gap-3 px-4 py-3 border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
          <span>Timestamp</span>
          <span>User</span>
          <span>Action</span>
          <span>Detail</span>
          <span>Severity</span>
          <span>Expires</span>
        </div>

        <div className="divide-y divide-gray-800/60 max-h-[600px] overflow-y-auto">
          {filtered.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 text-gray-600 gap-3">
              <ClipboardList className="w-10 h-10" />
              <p className="text-sm">No audit entries yet</p>
              <p className="text-xs">Actions you take in the console will appear here</p>
            </div>
          )}
          {filtered.map((entry) => {
            const meta = ACTION_META[entry.action];
            const Icon = meta?.icon ?? Info;
            const SevIcon = SEV_ICON[entry.severity];
            const pct = expiryPct(entry.expiresAt);
            return (
              <div
                key={entry.id}
                className="grid grid-cols-[140px_100px_120px_1fr_80px_90px] gap-3 px-4 py-3 text-sm hover:bg-gray-800/20 transition-colors items-center"
              >
                {/* Timestamp */}
                <div>
                  <p className="text-white text-xs font-mono">{new Date(entry.timestamp).toLocaleTimeString()}</p>
                  <p className="text-gray-600 text-xs">{timeAgo(entry.timestamp)}</p>
                </div>

                {/* User */}
                <div className="flex items-center gap-1.5 min-w-0">
                  <User className="w-3 h-3 text-gray-500 shrink-0" />
                  <span className="text-gray-300 text-xs truncate">{entry.user}</span>
                </div>

                {/* Action */}
                <div className="flex items-center gap-1.5 min-w-0">
                  <Icon className={`w-3.5 h-3.5 shrink-0 ${meta?.color ?? 'text-gray-400'}`} />
                  <span className={`text-xs font-medium truncate ${meta?.color ?? 'text-gray-400'}`}>
                    {meta?.label ?? entry.action}
                  </span>
                </div>

                {/* Detail */}
                <p className="text-gray-400 text-xs truncate" title={entry.detail}>{entry.detail}</p>

                {/* Severity */}
                <span className={`text-xs px-2 py-0.5 rounded border w-fit ${SEV_STYLE[entry.severity]}`}>
                  {entry.severity}
                </span>

                {/* Expiry bar */}
                <div className="space-y-1">
                  <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${pct > 80 ? 'bg-red-500' : pct > 50 ? 'bg-yellow-500' : 'bg-cyan-500'}`}
                      style={{ width: `${100 - pct}%` }}
                    />
                  </div>
                  <p className="text-xs text-gray-600 text-right">
                    {Math.max(0, Math.round((new Date(entry.expiresAt).getTime() - now) / 60000))}m left
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Info note */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-4 text-xs text-gray-500 flex items-start gap-2">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <span>
          Audit entries are stored in memory only and auto-flush every 15 minutes. For persistent audit logging,
          enable log export to S3/Azure/GCS in Settings. Logged-in as <span className="text-cyan-400">{user?.username}</span> ({user?.role}).
        </span>
      </div>
    </div>
  );
}
