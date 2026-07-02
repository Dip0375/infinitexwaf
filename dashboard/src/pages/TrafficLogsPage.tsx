import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Activity, Search, Filter, RefreshCw, Pause, Play,
  ChevronDown, ChevronUp, Shield, CheckCircle, Bot,
  FileText, Globe, Clock, Download,
} from 'lucide-react';

interface LogEntry {
  timestamp: string;
  clientIp: string;
  method: string;
  uri: string;
  userAgent: string;
  action: string;
  allowed: boolean;
  ruleId: string | null;
  geoCountry: string | null;
  threatScore: number;
}

const ACTION_STYLE: Record<string, string> = {
  ALLOW: 'text-green-400 bg-green-500/10 border-green-500/30',
  BLOCK: 'text-red-400 bg-red-500/10 border-red-500/30',
  LOG:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  RATE_LIMIT: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  CHALLENGE_JS: 'text-purple-400 bg-purple-500/10 border-purple-500/30',
};

const METHOD_COLOR: Record<string, string> = {
  GET:    'text-cyan-400',
  POST:   'text-green-400',
  PUT:    'text-yellow-400',
  DELETE: 'text-red-400',
  PATCH:  'text-purple-400',
};

function ThreatBar({ score }: { score: number }) {
  const color = score >= 70 ? 'bg-red-500' : score >= 40 ? 'bg-yellow-500' : 'bg-green-500';
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-16 h-1.5 bg-gray-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs text-gray-500">{score}</span>
    </div>
  );
}

function LogRow({ entry }: { entry: LogEntry }) {
  const [open, setOpen] = useState(false);
  const style = ACTION_STYLE[entry.action] ?? 'text-gray-400 bg-gray-800 border-gray-700';

  return (
    <div className="border-b border-gray-800/60 hover:bg-gray-800/20 transition-colors">
      <div
        className="grid grid-cols-[160px_110px_60px_1fr_90px_80px_32px] gap-2 px-4 py-2.5 items-center cursor-pointer text-sm"
        onClick={() => setOpen((o) => !o)}
      >
        <span className="text-gray-400 font-mono text-xs">
          {new Date(entry.timestamp).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
        </span>
        <span className="text-gray-300 font-mono text-xs truncate">{entry.clientIp}</span>
        <span className={`text-xs font-bold ${METHOD_COLOR[entry.method] ?? 'text-gray-400'}`}>{entry.method}</span>
        <span className="text-white text-xs truncate font-mono" title={entry.uri}>{entry.uri}</span>
        <span className={`text-xs px-2 py-0.5 rounded border w-fit ${style}`}>{entry.action}</span>
        <ThreatBar score={entry.threatScore} />
        {open ? <ChevronUp className="w-3.5 h-3.5 text-gray-500" /> : <ChevronDown className="w-3.5 h-3.5 text-gray-500" />}
      </div>

      {open && (
        <div className="px-4 pb-4 grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
          {[
            { label: 'Full URI',      value: entry.uri,                    mono: true  },
            { label: 'User Agent',    value: entry.userAgent || '—',       mono: false },
            { label: 'Country',       value: entry.geoCountry || 'Unknown',mono: false },
            { label: 'Rule Triggered',value: entry.ruleId || 'None',       mono: true  },
            { label: 'Threat Score',  value: String(entry.threatScore),    mono: false },
            { label: 'Timestamp',     value: new Date(entry.timestamp).toLocaleString(), mono: false },
          ].map((f) => (
            <div key={f.label} className="bg-gray-800/50 rounded-lg p-2.5">
              <p className="text-gray-500 mb-0.5">{f.label}</p>
              <p className={`text-white break-all ${f.mono ? 'font-mono' : ''}`}>{f.value}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function TrafficLogsPage() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [paused, setPaused] = useState(false);
  const [search, setSearch] = useState('');
  const [filterAction, setFilterAction] = useState('all');
  const [page, setPage] = useState(0);
  const [lastRefresh, setLastRefresh] = useState(new Date());
  const intervalRef = useRef<NodeJS.Timeout | null>(null);
  const LIMIT = 100;

  const fetchLogs = useCallback(async (offset = 0) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ limit: String(LIMIT), offset: String(offset) });
      if (filterAction !== 'all') params.set('action', filterAction);
      const res = await fetch(`/api/dashboard/logs?${params}`);
      const data = await res.json();
      setLogs(data.logs ?? []);
      setTotal(data.total ?? 0);
      setLastRefresh(new Date());
    } catch { /* silent */ }
    finally { setLoading(false); }
  }, [filterAction]);

  // Auto-refresh every 10s unless paused
  useEffect(() => {
    fetchLogs(page * LIMIT);
    if (!paused) {
      intervalRef.current = setInterval(() => fetchLogs(page * LIMIT), 10_000);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [fetchLogs, paused, page]);

  // Filter client-side by search
  const filtered = logs.filter((l) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return l.clientIp.includes(q) || l.uri.toLowerCase().includes(q) ||
           (l.userAgent ?? '').toLowerCase().includes(q) ||
           (l.ruleId ?? '').toLowerCase().includes(q) ||
           (l.geoCountry ?? '').toLowerCase().includes(q);
  });

  const stats = {
    total: logs.length,
    allowed: logs.filter((l) => l.allowed).length,
    blocked: logs.filter((l) => !l.allowed).length,
    bot: logs.filter((l) => l.ruleId === 'BOT-001').length,
  };

  function exportCSV() {
    const headers = ['timestamp','clientIp','method','uri','action','ruleId','geoCountry','threatScore','userAgent'];
    const rows = filtered.map((l) => headers.map((h) => JSON.stringify((l as any)[h] ?? '')).join(','));
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `traffic-logs-${new Date().toISOString().slice(0,10)}.csv`;
    a.click(); URL.revokeObjectURL(url);
  }

  const totalPages = Math.ceil(total / LIMIT);

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Activity className="w-6 h-6 text-cyan-400" /> Traffic Logs
          </h2>
          <p className="text-gray-400 text-sm mt-1">
            Real-time WAF request log — auto-refreshes every 10 seconds
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500 flex items-center gap-1">
            <Clock className="w-3 h-3" /> {lastRefresh.toLocaleTimeString()}
          </span>
          <button
            onClick={() => setPaused((p) => !p)}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-sm border transition-colors ${
              paused
                ? 'bg-green-500/10 border-green-500/30 text-green-400 hover:bg-green-500/20'
                : 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/20'
            }`}
          >
            {paused ? <><Play className="w-3.5 h-3.5" /> Resume</> : <><Pause className="w-3.5 h-3.5" /> Pause</>}
          </button>
          <button
            onClick={() => fetchLogs(page * LIMIT)}
            className="p-2 rounded-xl bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={exportCSV}
            className="flex items-center gap-1.5 px-3 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-xl text-sm transition-colors"
          >
            <Download className="w-3.5 h-3.5" /> CSV
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Showing',  value: logs.length,    icon: FileText,     color: 'text-white'   },
          { label: 'Allowed',  value: stats.allowed,  icon: CheckCircle,  color: 'text-green-400' },
          { label: 'Blocked',  value: stats.blocked,  icon: Shield,       color: 'text-red-400'   },
          { label: 'Bot',      value: stats.bot,      icon: Bot,          color: 'text-purple-400' },
        ].map((s) => {
          const Icon = s.icon;
          return (
            <div key={s.label} className="bg-gray-900/50 border border-gray-800 rounded-xl px-4 py-3 flex items-center gap-3">
              <Icon className={`w-5 h-5 ${s.color} shrink-0`} />
              <div>
                <p className={`text-xl font-bold ${s.color}`}>{s.value}</p>
                <p className="text-xs text-gray-500">{s.label}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by IP, URI, rule, country, user agent…"
            className="w-full bg-gray-900/50 border border-gray-800 rounded-xl pl-9 pr-4 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-500" />
          <select
            value={filterAction}
            onChange={(e) => { setFilterAction(e.target.value); setPage(0); }}
            className="bg-gray-900/50 border border-gray-800 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Actions</option>
            <option value="ALLOW">Allow</option>
            <option value="BLOCK">Block</option>
            <option value="LOG">Log</option>
            <option value="RATE_LIMIT">Rate Limit</option>
          </select>
        </div>
      </div>

      {/* Log table */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-2xl overflow-hidden">
        {/* Column headers */}
        <div className="grid grid-cols-[160px_110px_60px_1fr_90px_80px_32px] gap-2 px-4 py-3 border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
          <span>Time</span>
          <span>Source IP</span>
          <span>Method</span>
          <span>URI</span>
          <span>Action</span>
          <span>Threat</span>
          <span />
        </div>

        <div className="max-h-[600px] overflow-y-auto">
          {loading && logs.length === 0 && (
            <div className="flex items-center justify-center py-16">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400" />
            </div>
          )}
          {!loading && filtered.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 text-gray-600 gap-3">
              <Activity className="w-10 h-10" />
              <p className="text-sm">No traffic logs yet</p>
              <p className="text-xs">Logs appear here as requests pass through the WAF</p>
            </div>
          )}
          {filtered.map((entry, i) => (
            <LogRow key={`${entry.timestamp}-${i}`} entry={entry} />
          ))}
        </div>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-sm text-gray-400">
          <span>{total.toLocaleString()} total entries</span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="px-3 py-1.5 bg-gray-800 rounded-lg disabled:opacity-40 hover:bg-gray-700 transition-colors"
            >
              ← Prev
            </button>
            <span className="text-gray-500">Page {page + 1} / {totalPages}</span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              className="px-3 py-1.5 bg-gray-800 rounded-lg disabled:opacity-40 hover:bg-gray-700 transition-colors"
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
