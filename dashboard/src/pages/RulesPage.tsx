import { useState, useEffect, useCallback } from 'react';
import {
  Shield, Plus, Trash2, Edit2, ToggleLeft, ToggleRight,
  ChevronDown, ChevronUp, Search, Filter, Copy, AlertTriangle,
  CheckCircle, Lock, Zap, RefreshCw, X, Info, Globe, Route,
  Server, Bot, Gauge, Eye, ShieldOff, Terminal, Network,
  Database, FileText, Settings, List,
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

// ── Managed Rule Config (AWS WAF-style rule group parameters) ─────────────────
type ManagedAction = 'ALLOW' | 'BLOCK' | 'LOG' | 'LOGGED' | 'CHALLENGE';
type SqliLevel = 'BASIC' | 'MODERATE' | 'STRICT';
type XssLevel = 'BASIC' | 'MODERATE' | 'STRICT';
type BotLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'AGGRESSIVE';

interface ManagedRuleConfig {
  action?: ManagedAction;
  geoCountries?: string[];
  adminEndpoints?: string[];
  botLevel?: BotLevel;
  botBlockHeadless?: boolean;
  rateLimitRequests?: number;
  rateLimitWindow?: number;
  rateLimitBurst?: number;
  sqliLevel?: SqliLevel;
  xssLevel?: XssLevel;
  blockTor?: boolean;
  blockVpn?: boolean;
  blockProxy?: boolean;
  blockHosting?: boolean;
  ipReputationEnabled?: boolean;
}

// ── Sub-Rule Types (individual rules within managed rule groups) ──────────────
interface SubRuleDef {
  id: string; name: string; description: string; label: string;
  defaultAction: ManagedAction; scope?: string;
}
interface SubRuleState { enabled: boolean; action?: ManagedAction; deleted?: boolean; }

const COUNTRY_LIST: { code: string; name: string }[] = [
  { code: 'AF', name: 'Afghanistan' }, { code: 'AL', name: 'Albania' },
  { code: 'DZ', name: 'Algeria' }, { code: 'AD', name: 'Andorra' },
  { code: 'AO', name: 'Angola' }, { code: 'AR', name: 'Argentina' },
  { code: 'AM', name: 'Armenia' }, { code: 'AU', name: 'Australia' },
  { code: 'AT', name: 'Austria' }, { code: 'AZ', name: 'Azerbaijan' },
  { code: 'BS', name: 'Bahamas' }, { code: 'BH', name: 'Bahrain' },
  { code: 'BD', name: 'Bangladesh' }, { code: 'BB', name: 'Barbados' },
  { code: 'BY', name: 'Belarus' }, { code: 'BE', name: 'Belgium' },
  { code: 'BZ', name: 'Belize' }, { code: 'BJ', name: 'Benin' },
  { code: 'BT', name: 'Bhutan' }, { code: 'BO', name: 'Bolivia' },
  { code: 'BA', name: 'Bosnia and Herzegovina' }, { code: 'BW', name: 'Botswana' },
  { code: 'BR', name: 'Brazil' }, { code: 'BN', name: 'Brunei' },
  { code: 'BG', name: 'Bulgaria' }, { code: 'BF', name: 'Burkina Faso' },
  { code: 'BI', name: 'Burundi' }, { code: 'KH', name: 'Cambodia' },
  { code: 'CM', name: 'Cameroon' }, { code: 'CA', name: 'Canada' },
  { code: 'CV', name: 'Cape Verde' }, { code: 'CF', name: 'Central African Republic' },
  { code: 'TD', name: 'Chad' }, { code: 'CL', name: 'Chile' },
  { code: 'CN', name: 'China' }, { code: 'CO', name: 'Colombia' },
  { code: 'KM', name: 'Comoros' }, { code: 'CG', name: 'Congo' },
  { code: 'CR', name: 'Costa Rica' }, { code: 'HR', name: 'Croatia' },
  { code: 'CU', name: 'Cuba' }, { code: 'CY', name: 'Cyprus' },
  { code: 'CZ', name: 'Czech Republic' }, { code: 'DK', name: 'Denmark' },
  { code: 'DJ', name: 'Djibouti' }, { code: 'DO', name: 'Dominican Republic' },
  { code: 'EC', name: 'Ecuador' }, { code: 'EG', name: 'Egypt' },
  { code: 'SV', name: 'El Salvador' }, { code: 'EE', name: 'Estonia' },
  { code: 'ET', name: 'Ethiopia' }, { code: 'FI', name: 'Finland' },
  { code: 'FR', name: 'France' }, { code: 'GA', name: 'Gabon' },
  { code: 'GM', name: 'Gambia' }, { code: 'GE', name: 'Georgia' },
  { code: 'DE', name: 'Germany' }, { code: 'GH', name: 'Ghana' },
  { code: 'GR', name: 'Greece' }, { code: 'GT', name: 'Guatemala' },
  { code: 'GN', name: 'Guinea' }, { code: 'GY', name: 'Guyana' },
  { code: 'HT', name: 'Haiti' }, { code: 'HN', name: 'Honduras' },
  { code: 'HK', name: 'Hong Kong' }, { code: 'HU', name: 'Hungary' },
  { code: 'IS', name: 'Iceland' }, { code: 'IN', name: 'India' },
  { code: 'ID', name: 'Indonesia' }, { code: 'IR', name: 'Iran' },
  { code: 'IQ', name: 'Iraq' }, { code: 'IE', name: 'Ireland' },
  { code: 'IL', name: 'Israel' }, { code: 'IT', name: 'Italy' },
  { code: 'JM', name: 'Jamaica' }, { code: 'JP', name: 'Japan' },
  { code: 'JO', name: 'Jordan' }, { code: 'KZ', name: 'Kazakhstan' },
  { code: 'KE', name: 'Kenya' }, { code: 'KP', name: 'North Korea' },
  { code: 'KR', name: 'South Korea' }, { code: 'KW', name: 'Kuwait' },
  { code: 'KG', name: 'Kyrgyzstan' }, { code: 'LA', name: 'Laos' },
  { code: 'LV', name: 'Latvia' }, { code: 'LB', name: 'Lebanon' },
  { code: 'LY', name: 'Libya' }, { code: 'LI', name: 'Liechtenstein' },
  { code: 'LT', name: 'Lithuania' }, { code: 'LU', name: 'Luxembourg' },
  { code: 'MO', name: 'Macau' }, { code: 'MK', name: 'North Macedonia' },
  { code: 'MG', name: 'Madagascar' }, { code: 'MW', name: 'Malawi' },
  { code: 'MY', name: 'Malaysia' }, { code: 'MV', name: 'Maldives' },
  { code: 'ML', name: 'Mali' }, { code: 'MT', name: 'Malta' },
  { code: 'MX', name: 'Mexico' }, { code: 'MD', name: 'Moldova' },
  { code: 'MC', name: 'Monaco' }, { code: 'MN', name: 'Mongolia' },
  { code: 'ME', name: 'Montenegro' }, { code: 'MA', name: 'Morocco' },
  { code: 'MZ', name: 'Mozambique' }, { code: 'MM', name: 'Myanmar' },
  { code: 'NA', name: 'Namibia' }, { code: 'NP', name: 'Nepal' },
  { code: 'NL', name: 'Netherlands' }, { code: 'NZ', name: 'New Zealand' },
  { code: 'NI', name: 'Nicaragua' }, { code: 'NE', name: 'Niger' },
  { code: 'NG', name: 'Nigeria' }, { code: 'NO', name: 'Norway' },
  { code: 'OM', name: 'Oman' }, { code: 'PK', name: 'Pakistan' },
  { code: 'PA', name: 'Panama' }, { code: 'PY', name: 'Paraguay' },
  { code: 'PE', name: 'Peru' }, { code: 'PH', name: 'Philippines' },
  { code: 'PL', name: 'Poland' }, { code: 'PT', name: 'Portugal' },
  { code: 'QA', name: 'Qatar' }, { code: 'RO', name: 'Romania' },
  { code: 'RU', name: 'Russia' }, { code: 'RW', name: 'Rwanda' },
  { code: 'SA', name: 'Saudi Arabia' }, { code: 'SN', name: 'Senegal' },
  { code: 'RS', name: 'Serbia' }, { code: 'SG', name: 'Singapore' },
  { code: 'SK', name: 'Slovakia' }, { code: 'SI', name: 'Slovenia' },
  { code: 'SO', name: 'Somalia' }, { code: 'ZA', name: 'South Africa' },
  { code: 'ES', name: 'Spain' }, { code: 'LK', name: 'Sri Lanka' },
  { code: 'SD', name: 'Sudan' }, { code: 'SE', name: 'Sweden' },
  { code: 'CH', name: 'Switzerland' }, { code: 'SY', name: 'Syria' },
  { code: 'TW', name: 'Taiwan' }, { code: 'TJ', name: 'Tajikistan' },
  { code: 'TZ', name: 'Tanzania' }, { code: 'TH', name: 'Thailand' },
  { code: 'TL', name: 'Timor-Leste' }, { code: 'TN', name: 'Tunisia' },
  { code: 'TR', name: 'Turkey' }, { code: 'TM', name: 'Turkmenistan' },
  { code: 'UG', name: 'Uganda' }, { code: 'UA', name: 'Ukraine' },
  { code: 'AE', name: 'United Arab Emirates' }, { code: 'GB', name: 'United Kingdom' },
  { code: 'US', name: 'United States' }, { code: 'UY', name: 'Uruguay' },
  { code: 'UZ', name: 'Uzbekistan' }, { code: 'VE', name: 'Venezuela' },
  { code: 'VN', name: 'Vietnam' }, { code: 'YE', name: 'Yemen' },
  { code: 'ZM', name: 'Zambia' }, { code: 'ZW', name: 'Zimbabwe' },
];

const MANAGED_ACTION_OPTIONS: ManagedAction[] = ['ALLOW', 'BLOCK', 'LOG', 'LOGGED', 'CHALLENGE']; 
const SQLI_LEVEL_OPTIONS: SqliLevel[] = ['BASIC', 'MODERATE', 'STRICT'];
const XSS_LEVEL_OPTIONS: XssLevel[] = ['BASIC', 'MODERATE', 'STRICT'];
const BOT_LEVEL_OPTIONS: BotLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'AGGRESSIVE'];

// Map each managed rule ID to its icon
const RULE_ICONS: Record<string, React.ComponentType<any>> = {
  'CORE-001': Shield, 'SQLI-001': Terminal,
  'BOT-001': Bot, 'RATE-001': Gauge, 'NULL-001': ShieldOff,
  'METH-001': Lock, 'CT-001': FileText, 'GEO-001': Globe,
  'ANON-001': Eye, 'THREAT-INTEL-001': Network, 'NOSQLI-001': Database,
};

const DEFAULT_MANAGED_CONFIGS: Record<string, ManagedRuleConfig> = {
  'GEO-001': { action: 'BLOCK', geoCountries: [] },
  'METH-001': { action: 'BLOCK', adminEndpoints: ['/login', '/auth', '/admin', '/wp-login.php', '/api/auth'] },
  'SQLI-001': { action: 'BLOCK', sqliLevel: 'MODERATE' },
  'BOT-001':  { action: 'BLOCK', botLevel: 'MEDIUM', botBlockHeadless: false },
  'RATE-001': { action: 'BLOCK', rateLimitRequests: 100, rateLimitWindow: 60, rateLimitBurst: 150 },
  'ANON-001': { action: 'CHALLENGE', blockTor: false, blockVpn: false, blockProxy: false, blockHosting: false },
  'CORE-001': { action: 'BLOCK' },
  'NOSQLI-001': { action: 'BLOCK' },
  'NULL-001': { action: 'BLOCK' },
  'CT-001':   { action: 'BLOCK' },
  'THREAT-INTEL-001': { action: 'BLOCK' },
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

// ── Managed Rule Config Sub-components ────────────────────────────────────────

function ActionSelect({ value, onChange }: { value: ManagedAction; onChange: (v: ManagedAction) => void }) {
  return (
    <div>
      <label className="text-xs text-gray-500 block mb-1.5">Override Action</label>
      <select value={value} onChange={(e) => onChange(e.target.value as ManagedAction)}
        className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500">
        {MANAGED_ACTION_OPTIONS.map((o) => (
          <option key={o} value={o}>{o}</option>
        ))}
      </select>
      <p className="text-xs text-gray-600 mt-1">Default action for this rule group</p>
    </div>
  );
}

function CountryMultiSelect({ selected, onChange }: { selected: string[]; onChange: (v: string[]) => void }) {
  const [search, setSearch] = useState('');
  const [open, setOpen] = useState(false);
  const filtered = COUNTRY_LIST.filter((c) =>
    c.name.toLowerCase().includes(search.toLowerCase()) || c.code.toLowerCase().includes(search.toLowerCase())
  );
  const toggle = (code: string) => {
    onChange(selected.includes(code) ? selected.filter((s) => s !== code) : [...selected, code]);
  };
  return (
    <div className="relative">
      <label className="text-xs text-gray-500 block mb-1.5">Restricted Countries</label>
      <button onClick={() => setOpen(!open)}
        className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-left text-white focus:outline-none focus:border-cyan-500">
        {selected.length === 0
          ? <span className="text-gray-500">Select countries to restrict…</span>
          : <span>{selected.length} country{selected.length !== 1 ? 'ies' : 'y'} selected</span>}
      </button>
      {open && (
        <div className="absolute z-20 mt-1 w-full bg-gray-800 border border-gray-700 rounded-xl shadow-xl max-h-72 flex flex-col">
          <div className="p-2 border-b border-gray-700">
            <input value={search} onChange={(e) => setSearch(e.target.value)}
              placeholder="Search countries…"
              className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-500 focus:outline-none" />
          </div>
          <div className="overflow-y-auto flex-1 p-1">
            {filtered.length === 0 && (
              <p className="text-gray-500 text-xs text-center py-3">No countries match</p>
            )}
            {filtered.map((c) => (
              <label key={c.code}
                className="flex items-center gap-2 px-3 py-1.5 hover:bg-gray-700/50 rounded-lg cursor-pointer text-sm">
                <input type="checkbox" checked={selected.includes(c.code)}
                  onChange={() => toggle(c.code)} className="w-4 h-4 accent-cyan-500 rounded" />
                <span className="text-gray-300 flex-1">{c.name}</span>
                <span className="text-gray-500 font-mono text-xs">{c.code}</span>
              </label>
            ))}
          </div>
        </div>
      )}
      {selected.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-2">
          {selected.map((code) => {
            const country = COUNTRY_LIST.find((c) => c.code === code);
            return (
              <span key={code}
                className="flex items-center gap-1 text-xs bg-red-500/10 text-red-400 px-2 py-0.5 rounded-full">
                {country ? country.name : code}
                <button onClick={() => toggle(code)} className="hover:text-white">×</button>
              </span>
            );
          })}
        </div>
      )}
      {open && <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />}
    </div>
  );
}

function PathListEditor({ paths, onChange }: { paths: string[]; onChange: (v: string[]) => void }) {
  const [input, setInput] = useState('');
  const add = () => {
    const p = input.trim();
    if (p && !paths.includes(p)) { onChange([...paths, p]); setInput(''); }
  };
  return (
    <div>
      <label className="text-xs text-gray-500 block mb-1.5">Protected Endpoint Paths</label>
      <div className="flex gap-2 mb-2">
        <input value={input} onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && add()}
          placeholder="/admin"
          className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white font-mono placeholder-gray-500 focus:outline-none focus:border-cyan-500" />
        <button onClick={add} className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm transition-colors">Add</button>
      </div>
      <div className="space-y-1">
        {paths.length === 0 && <p className="text-gray-600 text-xs">No endpoints configured</p>}
        {paths.map((p) => (
          <div key={p} className="flex items-center justify-between bg-gray-800/50 rounded-lg px-3 py-1.5 text-sm">
            <span className="text-cyan-400 font-mono">{p}</span>
            <button onClick={() => onChange(paths.filter((x) => x !== p))}
              className="text-gray-600 hover:text-red-400 transition-colors">
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function NumberInput({ label, value, onChange, min, max, hint }: {
  label: string; value: number; onChange: (v: number) => void; min?: number; max?: number; hint?: string;
}) {
  return (
    <div>
      <label className="text-xs text-gray-500 block mb-1">{label}</label>
      <input type="number" value={value} onChange={(e) => onChange(Math.max(min ?? 0, +e.target.value))}
        min={min} max={max}
        className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500" />
      {hint && <p className="text-xs text-gray-600 mt-0.5">{hint}</p>}
    </div>
  );
}

function ToggleSwitch({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center gap-3 cursor-pointer py-1.5">
      <div className={`relative w-10 h-5 rounded-full transition-colors ${checked ? 'bg-cyan-500' : 'bg-gray-700'}`}>
        <div className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${checked ? 'translate-x-5' : ''}`} />
      </div>
      <span className="text-sm text-gray-300">{label}</span>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="hidden" />
    </label>
  );
}

// ── Managed Config Panel ──────────────────────────────────────────────────────
function ManagedConfigPanel({ ruleId, config, onChange }: {
  ruleId: string; config: ManagedRuleConfig; onChange: (id: string, patch: Partial<ManagedRuleConfig>) => void;
}) {
  const desc = (id: string) => config.action ?? 'BLOCK';
  const set = (patch: Partial<ManagedRuleConfig>) => onChange(ruleId, patch);

  switch (ruleId) {
    case 'GEO-001':
      return (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <ActionSelect value={config.action ?? 'BLOCK'} onChange={(v) => set({ action: v })} />
          </div>
          <CountryMultiSelect selected={config.geoCountries ?? []} onChange={(v) => set({ geoCountries: v })} />
        </div>
      );

    case 'METH-001':
      return (
        <div className="space-y-4">
          <ActionSelect value={config.action ?? 'BLOCK'} onChange={(v) => set({ action: v })} />
          <PathListEditor paths={config.adminEndpoints ?? []} onChange={(v) => set({ adminEndpoints: v })} />
        </div>
      );

    case 'SQLI-001':
      return (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <ActionSelect value={config.action ?? 'BLOCK'} onChange={(v) => set({ action: v })} />
            <div>
              <label className="text-xs text-gray-500 block mb-1.5">Inspection Level</label>
              <select value={config.sqliLevel ?? 'MODERATE'} onChange={(e) => set({ sqliLevel: e.target.value as SqliLevel })}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500">
                {SQLI_LEVEL_OPTIONS.map((o) => <option key={o} value={o}>{o}</option>)}
              </select>
              <p className="text-xs text-gray-600 mt-1">Higher levels detect more but may increase false positives</p>
            </div>
          </div>
        </div>
      );

    case 'XSS-001':
      return (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <ActionSelect value={config.action ?? 'BLOCK'} onChange={(v) => set({ action: v })} />
            <div>
              <label className="text-xs text-gray-500 block mb-1.5">Inspection Level</label>
              <select value={config.xssLevel ?? 'MODERATE'} onChange={(e) => set({ xssLevel: e.target.value as XssLevel })}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500">
                {XSS_LEVEL_OPTIONS.map((o) => <option key={o} value={o}>{o}</option>)}
              </select>
              <p className="text-xs text-gray-600 mt-1">Higher levels detect more XSS vectors</p>
            </div>
          </div>
        </div>
      );

    case 'BOT-001':
      return (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <ActionSelect value={config.action ?? 'BLOCK'} onChange={(v) => set({ action: v })} />
            <div>
              <label className="text-xs text-gray-500 block mb-1.5">Protection Level</label>
              <select value={config.botLevel ?? 'MEDIUM'} onChange={(e) => set({ botLevel: e.target.value as BotLevel })}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500">
                {BOT_LEVEL_OPTIONS.map((o) => <option key={o} value={o}>{o}</option>)}
              </select>
            </div>
          </div>
          <ToggleSwitch label="Block headless browsers" checked={config.botBlockHeadless ?? false}
            onChange={(v) => set({ botBlockHeadless: v })} />
        </div>
      );

    case 'RATE-001':
      return (
        <div className="space-y-4">
          <ActionSelect value={config.action ?? 'BLOCK'} onChange={(v) => set({ action: v })} />
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <NumberInput label="Max Requests" value={config.rateLimitRequests ?? 100}
              onChange={(v) => set({ rateLimitRequests: v })} min={1} hint="Requests per window" />
            <NumberInput label="Window (seconds)" value={config.rateLimitWindow ?? 60}
              onChange={(v) => set({ rateLimitWindow: v })} min={1} hint="Time window" />
            <NumberInput label="Burst Limit" value={config.rateLimitBurst ?? 150}
              onChange={(v) => set({ rateLimitBurst: v })} min={1} hint="Burst tolerance" />
          </div>
        </div>
      );

    case 'ANON-001':
      return (
        <div className="space-y-4">
          <ActionSelect value={config.action ?? 'CHALLENGE'} onChange={(v) => set({ action: v })} />
          <div className="space-y-1">
            <p className="text-xs text-gray-500 mb-1">Block anonymous traffic types</p>
            <ToggleSwitch label="Block TOR exit nodes" checked={config.blockTor ?? false}
              onChange={(v) => set({ blockTor: v })} />
            <ToggleSwitch label="Block VPN providers" checked={config.blockVpn ?? false}
              onChange={(v) => set({ blockVpn: v })} />
            <ToggleSwitch label="Block public proxies" checked={config.blockProxy ?? false}
              onChange={(v) => set({ blockProxy: v })} />
            <ToggleSwitch label="Block hosting providers" checked={config.blockHosting ?? false}
              onChange={(v) => set({ blockHosting: v })} />
          </div>
        </div>
      );

    case 'THREAT-INTEL-001':
      return (
        <div className="space-y-4">
          <ActionSelect value={config.action ?? 'BLOCK'} onChange={(v) => set({ action: v })} />
        </div>
      );

    default:
      return (
        <div className="space-y-4">
          <ActionSelect value={config.action ?? 'BLOCK'} onChange={(v) => set({ action: v })} />
        </div>
      );
  }
}

// ── Sub-Rule Row ──────────────────────────────────────────────────────────────
function SubRuleRow({ rule, state, onStateChange, onDelete }: {
  rule: SubRuleDef; state?: SubRuleState;
  onStateChange: (id: string, patch: Partial<SubRuleState>) => void;
  onDelete: (id: string) => void;
}) {
  const s = state ?? { enabled: true };
  const currentAction = s.action ?? rule.defaultAction;
  return (
    <div className={`flex items-center gap-3 px-3 py-2 rounded-lg border ${
      s.enabled ? 'border-gray-700/50 bg-gray-800/30' : 'border-gray-800 bg-gray-800/10 opacity-50'
    }`}>
      <Toggle on={s.enabled} onChange={(v) => onStateChange(rule.id, { enabled: v })} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-medium text-white">{rule.name}</span>
          <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${
            currentAction === 'BLOCK' ? 'text-red-400 bg-red-500/10' :
            currentAction === 'ALLOW' ? 'text-green-400 bg-green-500/10' :
            currentAction === 'CHALLENGE' ? 'text-purple-400 bg-purple-500/10' :
            'text-blue-400 bg-blue-500/10'
          }`}>{currentAction}</span>
          {s.action && s.action !== rule.defaultAction && (
            <span className="text-xs text-yellow-400">(overridden)</span>
          )}
          {rule.scope && (
            <span className="text-xs bg-gray-800 text-gray-500 px-1.5 py-0.5 rounded font-mono">{rule.scope}</span>
          )}
        </div>
        <p className="text-xs text-gray-500 mt-0.5">{rule.description}</p>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <select value={currentAction} onChange={(e) => {
          const val = e.target.value as ManagedAction;
          onStateChange(rule.id, { action: val === rule.defaultAction ? undefined : val });
        }}
          className="bg-gray-900 border border-gray-700 rounded-lg px-2 py-1 text-xs text-white focus:outline-none focus:border-cyan-500">
          {MANAGED_ACTION_OPTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <button onClick={() => onDelete(rule.id)}
          className="p-1 hover:bg-red-500/10 rounded text-gray-500 hover:text-red-400 transition-colors" title="Remove rule">
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}

// ── Sub-Rule List ─────────────────────────────────────────────────────────────
function SubRuleList({ groupId, subRules, subRuleStates, onSubRuleChange, onSubRuleDelete }: {
  groupId: string; subRules: SubRuleDef[]; subRuleStates: Record<string, SubRuleState>;
  onSubRuleChange: (id: string, patch: Partial<SubRuleState>) => void;
  onSubRuleDelete: (id: string) => void;
}) {
  const [collapsed, setCollapsed] = useState(false);
  const activeCount = subRules.filter((r) => subRuleStates[r.id]?.enabled ?? true).length;
  return (
    <div className="bg-gray-800/20 border border-gray-700/30 rounded-xl overflow-hidden">
      <button onClick={() => setCollapsed(!collapsed)}
        className="flex items-center justify-between w-full px-4 py-2.5 bg-gray-800/40 hover:bg-gray-800/60 transition-colors">
        <div className="flex items-center gap-2 text-xs text-gray-400">
          <List className="w-3.5 h-3.5" />
          <span className="font-medium">{subRules.length} individual rules</span>
          <span className="text-green-400">({activeCount} active)</span>
        </div>
        {collapsed ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronUp className="w-3.5 h-3.5" />}
      </button>
      {!collapsed && (
        <div className="p-3 space-y-1.5">
          <div className="flex items-center justify-between mb-2 px-1">
            <p className="text-xs text-gray-500">Toggle or override action per rule — delete unwanted rules</p>
          </div>
          {subRules.map((sr) => (
            <SubRuleRow key={sr.id} rule={sr}
              state={subRuleStates[sr.id]}
              onStateChange={onSubRuleChange}
              onDelete={onSubRuleDelete} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Built-in rule row ─────────────────────────────────────────────────────────
function BuiltInRow({ rule, onToggle, config, onConfigChange, subRules, subRuleStates, onSubRuleChange, onSubRuleDelete }: {
  rule: BuiltInRule; onToggle: (id: string, v: boolean) => void;
  config?: ManagedRuleConfig; onConfigChange: (id: string, patch: Partial<ManagedRuleConfig>) => void;
  subRules?: SubRuleDef[]; subRuleStates?: Record<string, SubRuleState>;
  onSubRuleChange?: (id: string, patch: Partial<SubRuleState>) => void;
  onSubRuleDelete?: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const Icon = RULE_ICONS[rule.id] ?? Shield;
  const hasSubRules = subRules && subRules.length > 0;
  const effectiveConfig = config ?? DEFAULT_MANAGED_CONFIGS[rule.id];
  return (
    <div className={`border rounded-xl transition-all ${rule.enabled ? 'border-gray-700 bg-gray-900/40' : 'border-gray-800 bg-gray-900/20 opacity-60'}`}>
      <div className="flex items-center gap-3 px-4 py-3">
        <Toggle on={rule.enabled} onChange={(v) => onToggle(rule.id, v)} />
        <Icon className="w-5 h-5 text-gray-500 shrink-0 hidden sm:block" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-white">{rule.name}</span>
            <SevBadge s={rule.severity} />
            {hasSubRules && (
              <span className="text-xs bg-cyan-500/10 text-cyan-400 px-2 py-0.5 rounded">{subRules!.length} rules</span>
            )}
            {effectiveConfig?.action && effectiveConfig.action !== 'BLOCK' && (
              <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                effectiveConfig.action === 'ALLOW' ? 'text-green-400 bg-green-500/10' :
                effectiveConfig.action === 'CHALLENGE' ? 'text-purple-400 bg-purple-500/10' :
                'text-blue-400 bg-blue-500/10'
              }`}>{effectiveConfig.action}</span>
            )}
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
        <div className="px-4 pb-4 pt-1 border-t border-gray-800 space-y-3 text-sm">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
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
          {/* Sub-Rules List (AWS WAF style) */}
          {hasSubRules && onSubRuleChange && onSubRuleDelete && (
            <SubRuleList groupId={rule.id} subRules={subRules!}
              subRuleStates={subRuleStates ?? {}}
              onSubRuleChange={onSubRuleChange}
              onSubRuleDelete={onSubRuleDelete} />
          )}
          {/* Managed Rule Configuration Panel */}
          {effectiveConfig && (
            <div className="bg-gray-800/30 border border-gray-700/50 rounded-xl p-4">
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-xs text-gray-500 uppercase tracking-wider flex items-center gap-1.5">
                  <Settings className="w-3.5 h-3.5" /> Rule Group Configuration
                </h4>
                <button onClick={async () => {
                  setSaving(true);
                  try {
                    await fetch(`/api/rules/managed-config/${rule.id}`, {
                      method: 'PATCH',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify(effectiveConfig),
                    });
                    toast.success(`${rule.id} config saved`);
                  } catch {
                    toast.error('Failed to save config — API unreachable');
                  } finally {
                    setSaving(false);
                  }
                }} disabled={saving}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg text-xs hover:bg-cyan-500/30 transition-colors disabled:opacity-50">
                  {saving ? <RefreshCw className="w-3 h-3 animate-spin" /> : <CheckCircle className="w-3.5 h-3.5" />}
                  {saving ? 'Saving…' : 'Save Config'}
                </button>
              </div>
              <ManagedConfigPanel ruleId={rule.id} config={effectiveConfig} onChange={onConfigChange} />
            </div>
          )}
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
  { id: 'CORE-001',   name: 'InfiniteXManagedCoreRuleSets',   description: 'AWS WAF Core Rule Set (CRS) — 22 individual rules for basic security protections', category: 'InfiniteXManagedRuleSets', severity: 'CRITICAL', enabled: true,  isBuiltIn: true, hitCount: 0 },
  { id: 'SQLI-001',   name: 'InfiniteXManagedSQLiRuleSets',   description: 'Managed SQL injection protection aligned with AWS WAF managed rule groups', category: 'InfiniteXManagedRuleSets', severity: 'CRITICAL', enabled: true,  isBuiltIn: true, hitCount: 0 },
  { id: 'NOSQLI-001', name: 'InfiniteXManagedNoSQLRuleSets',   description: 'Managed NoSQL injection protection for database operators',              category: 'InfiniteXManagedRuleSets', severity: 'CRITICAL', enabled: true,  isBuiltIn: true, hitCount: 0 },
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
  const [managedConfigs, setManagedConfigs] = useState<Record<string, ManagedRuleConfig>>({});
  const [subRuleGroups, setSubRuleGroups] = useState<Record<string, SubRuleDef[]>>({});
  const [subRuleStates, setSubRuleStates] = useState<Record<string, SubRuleState>>({});

  const audit = useAudit();

  const load = useCallback(async () => {
    // Always show static built-in rules immediately — no blank state
    setBuiltIn(BUILTIN_RULES_STATIC);
    try {
      const [b, c, m, s] = await Promise.all([
        fetch('/api/rules/builtin').then((r) => r.json()),
        fetch('/api/rules/custom').then((r) => r.json()),
        fetch('/api/rules/managed-config').then((r) => r.json()),
        fetch('/api/rules/sub-rules').then((r) => r.json()),
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
      setManagedConfigs(m.configs ?? {});
      // Build sub-rule lookup: groupId -> SubRuleDef[]
      const groups: Record<string, SubRuleDef[]> = {};
      for (const g of (s.groups ?? [])) {
        groups[g.groupId] = g.rules;
      }
      setSubRuleGroups(groups);
      setSubRuleStates(s.states ?? {});
    } catch {
      // API unreachable — static rules already shown with default state
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  function handleConfigChange(id: string, patch: Partial<ManagedRuleConfig>) {
    setManagedConfigs((prev) => ({
      ...prev,
      [id]: { ...(prev[id] ?? {}), ...patch },
    }));
  }

  function handleSubRuleChange(ruleId: string, patch: Partial<SubRuleState>) {
    // Optimistic update
    setSubRuleStates((prev) => ({
      ...prev,
      [ruleId]: { ...(prev[ruleId] ?? { enabled: true }), ...patch },
    }));
    // Persist to API
    fetch(`/api/rules/sub-rules/${ruleId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    }).catch(() => {});
  }

  function handleSubRuleDelete(ruleId: string) {
    if (!confirm(`Remove rule "${ruleId}" from this rule group? You can restore it later.`)) return;
    // Optimistic
    setSubRuleStates((prev) => ({
      ...prev,
      [ruleId]: { ...(prev[ruleId] ?? { enabled: true }), deleted: true, enabled: false },
    }));
    fetch(`/api/rules/sub-rules/${ruleId}`, { method: 'DELETE' })
      .then(() => toast.success(`Rule ${ruleId} removed`))
      .catch(() => toast.error('Failed to delete rule'));
  }

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
            <BuiltInRow key={r.id} rule={r} onToggle={toggleBuiltIn}
              config={managedConfigs[r.id]} onConfigChange={handleConfigChange}
              subRules={subRuleGroups[r.id]} subRuleStates={subRuleStates}
              onSubRuleChange={handleSubRuleChange} onSubRuleDelete={handleSubRuleDelete} />
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
