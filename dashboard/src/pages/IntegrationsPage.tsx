import { useState } from 'react';
import {
  Cloud, Server, Globe, Cpu, Plus, Trash2, Edit2,
  CheckCircle, XCircle, AlertTriangle, RefreshCw,
  ChevronDown, ChevronUp, Link2, Unlink, Copy,
  ExternalLink, Info, Zap, Shield,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { useAudit } from '../hooks/useAudit';

// ── Types ─────────────────────────────────────────────────────────────────────
type IntegrationType =
  | 'alb'          // AWS Application Load Balancer
  | 'cloudfront'   // AWS CloudFront
  | 'azure_agw'    // Azure Application Gateway
  | 'gcp_lb'       // GCP Cloud Load Balancing
  | 'standalone'   // Standalone Public Cloud Server
  | 'onprem'       // On-Premises Web App Server
  | 'nginx'        // Nginx Reverse Proxy
  | 'k8s';         // Kubernetes Ingress

type IntegrationStatus = 'connected' | 'disconnected' | 'pending' | 'error';

interface Integration {
  id: string;
  name: string;
  type: IntegrationType;
  status: IntegrationStatus;
  host: string;
  port: number;
  description: string;
  tags: string[];
  createdAt: string;
  lastSeen?: string;
  requestsProxied: number;
  config: Record<string, string>;
}

// ── Integration type catalogue ────────────────────────────────────────────────
const TYPE_CATALOGUE: Record<IntegrationType, {
  label: string; icon: any; color: string; bg: string; border: string;
  description: string; fields: { key: string; label: string; placeholder: string; secret?: boolean }[];
  setupSteps: string[];
}> = {
  alb: {
    label: 'AWS Application Load Balancer', icon: Cloud, color: 'text-orange-400',
    bg: 'bg-orange-500/10', border: 'border-orange-500/30',
    description: 'Route ALB traffic through InfiniteX WAF using Lambda@Edge or as a reverse proxy target.',
    fields: [
      { key: 'arn',    label: 'ALB ARN',    placeholder: 'arn:aws:elasticloadbalancing:...' },
      { key: 'region', label: 'AWS Region', placeholder: 'us-east-1' },
      { key: 'vpcId',  label: 'VPC ID',     placeholder: 'vpc-xxxxxxxx' },
    ],
    setupSteps: [
      'Deploy InfiniteX WAF on an EC2 instance in the same VPC',
      'Set the WAF instance as the ALB target group',
      'Configure BACKEND_URL to point to your origin server',
      'Update ALB listener rules to forward traffic to WAF target',
    ],
  },
  cloudfront: {
    label: 'AWS CloudFront', icon: Cloud, color: 'text-yellow-400',
    bg: 'bg-yellow-500/10', border: 'border-yellow-500/30',
    description: 'Attach InfiniteX WAF as a CloudFront origin or use Lambda@Edge for edge inspection.',
    fields: [
      { key: 'distributionId', label: 'Distribution ID',  placeholder: 'E1XXXXXXXXXXXXXXX' },
      { key: 'originDomain',   label: 'Origin Domain',    placeholder: 'waf.yourdomain.com' },
      { key: 'region',         label: 'AWS Region',       placeholder: 'us-east-1' },
    ],
    setupSteps: [
      'Deploy InfiniteX WAF on EC2 with a public IP or behind an ALB',
      'Add WAF endpoint as a CloudFront custom origin',
      'Set Origin Protocol Policy to HTTPS only',
      'Configure cache behaviors to forward all headers',
    ],
  },
  azure_agw: {
    label: 'Azure Application Gateway', icon: Cloud, color: 'text-blue-400',
    bg: 'bg-blue-500/10', border: 'border-blue-500/30',
    description: 'Place InfiniteX WAF behind Azure Application Gateway as a backend pool member.',
    fields: [
      { key: 'resourceGroup', label: 'Resource Group',  placeholder: 'my-resource-group' },
      { key: 'gatewayName',   label: 'Gateway Name',    placeholder: 'my-app-gateway' },
      { key: 'backendFqdn',   label: 'WAF Backend FQDN',placeholder: 'waf.yourdomain.com' },
    ],
    setupSteps: [
      'Deploy InfiniteX WAF on an Azure VM in the same VNet',
      'Add the WAF VM as a backend pool member in App Gateway',
      'Configure health probe to /api/health',
      'Set BACKEND_URL to your origin application',
    ],
  },
  gcp_lb: {
    label: 'GCP Cloud Load Balancing', icon: Cloud, color: 'text-green-400',
    bg: 'bg-green-500/10', border: 'border-green-500/30',
    description: 'Use InfiniteX WAF as a GCP backend service behind a Global HTTP(S) Load Balancer.',
    fields: [
      { key: 'projectId',    label: 'GCP Project ID',   placeholder: 'my-gcp-project' },
      { key: 'backendName',  label: 'Backend Service',  placeholder: 'infinitex-waf-backend' },
      { key: 'region',       label: 'Region',           placeholder: 'us-central1' },
    ],
    setupSteps: [
      'Deploy InfiniteX WAF on a GCE instance or GKE pod',
      'Create a backend service pointing to the WAF instance group',
      'Configure health check on /api/health port 3000',
      'Attach backend service to the URL map',
    ],
  },
  standalone: {
    label: 'Standalone Public Cloud Server', icon: Server, color: 'text-cyan-400',
    bg: 'bg-cyan-500/10', border: 'border-cyan-500/30',
    description: 'Direct deployment on any public cloud VM (AWS EC2, Azure VM, GCE, DigitalOcean, Hetzner, etc.).',
    fields: [
      { key: 'host',        label: 'Server IP / Hostname', placeholder: '203.0.113.10' },
      { key: 'backendUrl',  label: 'Backend App URL',      placeholder: 'http://localhost:8080' },
      { key: 'provider',    label: 'Cloud Provider',       placeholder: 'AWS / Azure / GCP / DO / Hetzner' },
    ],
    setupSteps: [
      'SSH into your VM and run the bootstrap script',
      'Set BACKEND_URL to your application\'s internal address',
      'Point your domain DNS A record to the VM\'s public IP',
      'Run: sudo certbot --nginx -d yourdomain.com for HTTPS',
    ],
  },
  onprem: {
    label: 'On-Premises Web App Server', icon: Cpu, color: 'text-purple-400',
    bg: 'bg-purple-500/10', border: 'border-purple-500/30',
    description: 'Deploy InfiniteX WAF on-premises in front of internal web applications.',
    fields: [
      { key: 'host',       label: 'WAF Server IP',     placeholder: '192.168.1.100' },
      { key: 'backendUrl', label: 'App Server URL',    placeholder: 'http://192.168.1.200:8080' },
      { key: 'network',    label: 'Network Segment',   placeholder: '192.168.1.0/24' },
    ],
    setupSteps: [
      'Install Node.js 20 on the WAF server',
      'Clone the repo and run npm install && npm run build',
      'Set BACKEND_URL to your internal application server',
      'Configure firewall to allow port 80/443 inbound to WAF only',
    ],
  },
  nginx: {
    label: 'Nginx Reverse Proxy', icon: Globe, color: 'text-green-400',
    bg: 'bg-green-500/10', border: 'border-green-500/30',
    description: 'Use Nginx as the front door on port 80/443, proxying to InfiniteX WAF on port 3000.',
    fields: [
      { key: 'host',       label: 'Nginx Host',        placeholder: 'yourdomain.com' },
      { key: 'wafPort',    label: 'WAF Port',          placeholder: '3000' },
      { key: 'sslEnabled', label: 'SSL / HTTPS',       placeholder: 'yes / no' },
    ],
    setupSteps: [
      'Install Nginx: sudo apt install nginx',
      'Copy the Nginx config from /etc/nginx/sites-available/infinitex',
      'Run: sudo nginx -t && sudo systemctl reload nginx',
      'Optionally add SSL: sudo certbot --nginx -d yourdomain.com',
    ],
  },
  k8s: {
    label: 'Kubernetes Ingress', icon: Zap, color: 'text-indigo-400',
    bg: 'bg-indigo-500/10', border: 'border-indigo-500/30',
    description: 'Deploy InfiniteX WAF as a Kubernetes Deployment with an Ingress controller in front.',
    fields: [
      { key: 'namespace',   label: 'Namespace',         placeholder: 'infinitex' },
      { key: 'ingressClass',label: 'Ingress Class',     placeholder: 'nginx / traefik' },
      { key: 'servicePort', label: 'Service Port',      placeholder: '3000' },
    ],
    setupSteps: [
      'Apply the k8s manifests: kubectl apply -f k8s/',
      'Set BACKEND_URL env var in the Deployment spec',
      'Configure Ingress to route external traffic to the WAF service',
      'Check pod health: kubectl get pods -n infinitex',
    ],
  },
};

const STATUS_STYLE: Record<IntegrationStatus, { color: string; bg: string; border: string; icon: any; label: string }> = {
  connected:    { color: 'text-green-400',  bg: 'bg-green-500/10',  border: 'border-green-500/30',  icon: CheckCircle,    label: 'Connected'    },
  disconnected: { color: 'text-gray-400',   bg: 'bg-gray-800',      border: 'border-gray-700',      icon: Unlink,         label: 'Disconnected' },
  pending:      { color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', icon: AlertTriangle,  label: 'Pending'      },
  error:        { color: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/30',    icon: XCircle,        label: 'Error'        },
};

// ── Empty form ────────────────────────────────────────────────────────────────
const EMPTY_FORM = {
  name: '', type: 'standalone' as IntegrationType,
  host: '', port: 443, description: '', tags: [] as string[],
  config: {} as Record<string, string>,
};

// ── Integration Card ──────────────────────────────────────────────────────────
function IntegrationCard({
  integration, onEdit, onDelete, onToggle, onTest,
}: {
  integration: Integration;
  onEdit: (i: Integration) => void;
  onDelete: (id: string) => void;
  onToggle: (id: string) => void;
  onTest: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const cat = TYPE_CATALOGUE[integration.type];
  const st  = STATUS_STYLE[integration.status];
  const Icon = cat.icon;
  const StIcon = st.icon;

  return (
    <div className={`border rounded-2xl transition-all ${cat.border} bg-gray-900/50`}>
      {/* Header row */}
      <div className="flex items-center gap-4 p-5">
        <div className={`p-3 rounded-xl ${cat.bg} border ${cat.border} shrink-0`}>
          <Icon className={`w-6 h-6 ${cat.color}`} />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-white font-semibold">{integration.name}</span>
            <span className={`flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border ${st.bg} ${st.border} ${st.color}`}>
              <StIcon className="w-3 h-3" />{st.label}
            </span>
            {integration.tags.map((t) => (
              <span key={t} className="text-xs bg-gray-800 text-gray-400 px-2 py-0.5 rounded-full">{t}</span>
            ))}
          </div>
          <p className="text-xs text-gray-500 mt-0.5">{cat.label} · {integration.host}:{integration.port}</p>
          {integration.lastSeen && (
            <p className="text-xs text-gray-600 mt-0.5">Last seen: {new Date(integration.lastSeen).toLocaleString()}</p>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <div className="text-right hidden sm:block">
            <p className="text-sm font-semibold text-white">{integration.requestsProxied.toLocaleString()}</p>
            <p className="text-xs text-gray-600">requests</p>
          </div>
          <button onClick={() => onTest(integration.id)} title="Test connection"
            className="p-2 hover:bg-gray-800 rounded-lg text-gray-500 hover:text-cyan-400 transition-colors">
            <RefreshCw className="w-4 h-4" />
          </button>
          <button onClick={() => onEdit(integration)} title="Edit"
            className="p-2 hover:bg-gray-800 rounded-lg text-gray-500 hover:text-white transition-colors">
            <Edit2 className="w-4 h-4" />
          </button>
          <button onClick={() => onDelete(integration.id)} title="Remove"
            className="p-2 hover:bg-red-500/10 rounded-lg text-gray-500 hover:text-red-400 transition-colors">
            <Trash2 className="w-4 h-4" />
          </button>
          <button onClick={() => setOpen((o) => !o)} className="p-2 text-gray-500 hover:text-white">
            {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Expanded detail */}
      {open && (
        <div className="px-5 pb-5 border-t border-gray-800 pt-4 space-y-4">
          <p className="text-sm text-gray-400">{integration.description || cat.description}</p>

          {/* Config fields */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            {Object.entries(integration.config).map(([k, v]) => (
              <div key={k} className="bg-gray-800/50 rounded-xl p-3">
                <p className="text-xs text-gray-500 mb-0.5 capitalize">{k.replace(/([A-Z])/g, ' $1')}</p>
                <p className="text-sm text-white font-mono truncate">{v || '—'}</p>
              </div>
            ))}
            <div className="bg-gray-800/50 rounded-xl p-3">
              <p className="text-xs text-gray-500 mb-0.5">Added</p>
              <p className="text-sm text-white">{new Date(integration.createdAt).toLocaleDateString()}</p>
            </div>
          </div>

          {/* Setup steps */}
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Setup Guide</p>
            <div className="space-y-1.5">
              {cat.setupSteps.map((step, i) => (
                <div key={i} className="flex items-start gap-2.5 text-sm text-gray-400">
                  <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 text-xs flex items-center justify-center shrink-0 mt-0.5 font-bold">{i + 1}</span>
                  {step}
                </div>
              ))}
            </div>
          </div>

          {/* WAF endpoint snippet */}
          <div className="bg-gray-950 rounded-xl p-3 border border-gray-800">
            <p className="text-xs text-gray-500 mb-2 flex items-center gap-1"><Info className="w-3 h-3" /> WAF Endpoint</p>
            <div className="flex items-center gap-2">
              <code className="text-cyan-400 text-xs font-mono flex-1">
                http://{integration.host}:{integration.port}/api/health
              </code>
              <button
                onClick={() => { navigator.clipboard.writeText(`http://${integration.host}:${integration.port}`); toast.success('Copied'); }}
                className="p-1.5 hover:bg-gray-800 rounded text-gray-500 hover:text-white transition-colors"
              >
                <Copy className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Add / Edit Form Modal ─────────────────────────────────────────────────────
function IntegrationForm({
  initial, onSave, onClose,
}: {
  initial?: Integration | null;
  onSave: (data: typeof EMPTY_FORM) => void;
  onClose: () => void;
}) {
  const [form, setForm] = useState<typeof EMPTY_FORM>(
    initial
      ? { name: initial.name, type: initial.type, host: initial.host, port: initial.port,
          description: initial.description, tags: [...initial.tags], config: { ...initial.config } }
      : { ...EMPTY_FORM, config: {} }
  );
  const [tagInput, setTagInput] = useState('');
  const cat = TYPE_CATALOGUE[form.type];

  function set<K extends keyof typeof EMPTY_FORM>(k: K, v: typeof EMPTY_FORM[K]) {
    setForm((f) => ({ ...f, [k]: v }));
  }

  function addTag() {
    const t = tagInput.trim();
    if (t && !form.tags.includes(t)) set('tags', [...form.tags, t]);
    setTagInput('');
  }

  function submit() {
    if (!form.name.trim()) { toast.error('Name is required'); return; }
    if (!form.host.trim()) { toast.error('Host / IP is required'); return; }
    onSave(form);
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-2xl w-full max-w-2xl max-h-[92vh] flex flex-col">
        <div className="flex items-center justify-between p-5 border-b border-gray-800 shrink-0">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            <Link2 className="w-5 h-5 text-cyan-400" />
            {initial ? 'Edit Integration' : 'Add Integration'}
          </h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white p-1"><XCircle className="w-5 h-5" /></button>
        </div>

        <div className="overflow-y-auto flex-1 p-5 space-y-5">
          {/* Type selector */}
          <div>
            <label className="text-xs text-gray-500 block mb-2">Integration Type</label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {(Object.entries(TYPE_CATALOGUE) as [IntegrationType, typeof TYPE_CATALOGUE[IntegrationType]][]).map(([type, c]) => {
                const Icon = c.icon;
                return (
                  <button key={type} onClick={() => set('type', type)}
                    className={`flex flex-col items-center gap-1.5 p-3 rounded-xl border text-xs transition-all ${
                      form.type === type ? `${c.border} ${c.bg} ${c.color}` : 'border-gray-700 bg-gray-800/50 text-gray-400 hover:border-gray-600'
                    }`}>
                    <Icon className="w-5 h-5" />
                    <span className="text-center leading-tight">{c.label.split(' ').slice(0, 3).join(' ')}</span>
                  </button>
                );
              })}
            </div>
            <p className="text-xs text-gray-500 mt-2">{cat.description}</p>
          </div>

          {/* Basic fields */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="sm:col-span-2">
              <label className="text-xs text-gray-500 block mb-1">Integration Name *</label>
              <input value={form.name} onChange={(e) => set('name', e.target.value)}
                placeholder="e.g. Production ALB, Main Web Server"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500" />
            </div>
            <div>
              <label className="text-xs text-gray-500 block mb-1">Host / IP *</label>
              <input value={form.host} onChange={(e) => set('host', e.target.value)}
                placeholder="203.0.113.10 or waf.yourdomain.com"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500" />
            </div>
            <div>
              <label className="text-xs text-gray-500 block mb-1">Port</label>
              <input type="number" value={form.port} onChange={(e) => set('port', +e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500" />
            </div>
            <div className="sm:col-span-2">
              <label className="text-xs text-gray-500 block mb-1">Description</label>
              <input value={form.description} onChange={(e) => set('description', e.target.value)}
                placeholder="Optional notes about this integration"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500" />
            </div>
          </div>

          {/* Type-specific config fields */}
          <div>
            <label className="text-xs text-gray-500 block mb-2 uppercase tracking-wider">Configuration</label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {cat.fields.map((f) => (
                <div key={f.key}>
                  <label className="text-xs text-gray-500 block mb-1">{f.label}</label>
                  <input
                    type={f.secret ? 'password' : 'text'}
                    value={form.config[f.key] ?? ''}
                    onChange={(e) => set('config', { ...form.config, [f.key]: e.target.value })}
                    placeholder={f.placeholder}
                    className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500 font-mono"
                  />
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
                placeholder="production, us-east-1, critical…"
                className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500" />
              <button onClick={addTag} className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 hover:text-white">Add</button>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {form.tags.map((t) => (
                <span key={t} className="flex items-center gap-1 text-xs bg-cyan-500/10 text-cyan-400 px-2 py-0.5 rounded-full">
                  {t}
                  <button onClick={() => set('tags', form.tags.filter((x) => x !== t))} className="hover:text-red-400">×</button>
                </span>
              ))}
            </div>
          </div>

          {/* Setup guide preview */}
          <div className="bg-gray-800/50 rounded-xl p-4 border border-gray-700">
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Setup Steps for {cat.label}</p>
            <div className="space-y-1.5">
              {cat.setupSteps.map((step, i) => (
                <div key={i} className="flex items-start gap-2 text-xs text-gray-400">
                  <span className="w-4 h-4 rounded-full bg-cyan-500/20 text-cyan-400 text-[10px] flex items-center justify-center shrink-0 mt-0.5 font-bold">{i + 1}</span>
                  {step}
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="p-5 border-t border-gray-800 flex gap-3 justify-end shrink-0">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-400 hover:text-white transition-colors">Cancel</button>
          <button onClick={submit} className="px-5 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-xl text-sm font-medium transition-colors">
            {initial ? 'Save Changes' : 'Add Integration'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────
export function IntegrationsPage() {
  const audit = useAudit();
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [editItem, setEditItem] = useState<Integration | null>(null);
  const [filterType, setFilterType] = useState<IntegrationType | 'all'>('all');
  const [filterStatus, setFilterStatus] = useState<IntegrationStatus | 'all'>('all');
  const [search, setSearch] = useState('');
  const [activeTab, setActiveTab] = useState<'resources' | 'catalogue'>('resources');

  function addOrUpdate(form: typeof EMPTY_FORM) {
    if (editItem) {
      setIntegrations((prev) => prev.map((i) =>
        i.id === editItem.id
          ? { ...i, ...form, config: form.config }
          : i
      ));
      toast.success('Integration updated');
      audit('SETTINGS_UPDATED', `Integration updated: ${form.name}`, 'info');
    } else {
      const newInt: Integration = {
        id: `int-${Date.now()}`,
        ...form,
        status: 'pending',
        createdAt: new Date().toISOString(),
        requestsProxied: 0,
      };
      setIntegrations((prev) => [newInt, ...prev]);
      toast.success(`Integration "${form.name}" added`);
      audit('SETTINGS_UPDATED', `Integration added: ${form.name} (${form.type})`, 'info');
    }
    setShowForm(false);
    setEditItem(null);
  }

  function remove(id: string) {
    const item = integrations.find((i) => i.id === id);
    if (!confirm(`Remove "${item?.name}"?`)) return;
    setIntegrations((prev) => prev.filter((i) => i.id !== id));
    toast.success('Integration removed');
    audit('SETTINGS_UPDATED', `Integration removed: ${item?.name}`, 'warning');
  }

  function testConnection(id: string) {
    const item = integrations.find((i) => i.id === id);
    toast.loading(`Testing ${item?.name}…`, { id: 'test' });
    setTimeout(() => {
      // Simulate test — in production would hit /api/health on the target
      const ok = Math.random() > 0.3;
      setIntegrations((prev) => prev.map((i) =>
        i.id === id ? { ...i, status: ok ? 'connected' : 'error', lastSeen: ok ? new Date().toISOString() : i.lastSeen } : i
      ));
      toast.dismiss('test');
      ok ? toast.success(`${item?.name} — connection OK`) : toast.error(`${item?.name} — connection failed`);
    }, 1500);
  }

  function toggleStatus(id: string) {
    setIntegrations((prev) => prev.map((i) =>
      i.id === id
        ? { ...i, status: i.status === 'connected' ? 'disconnected' : 'connected' }
        : i
    ));
  }

  const filtered = integrations.filter((i) => {
    if (filterType !== 'all' && i.type !== filterType) return false;
    if (filterStatus !== 'all' && i.status !== filterStatus) return false;
    const q = search.toLowerCase();
    if (q && !i.name.toLowerCase().includes(q) && !i.host.toLowerCase().includes(q)) return false;
    return true;
  });

  const stats = {
    total:       integrations.length,
    connected:   integrations.filter((i) => i.status === 'connected').length,
    pending:     integrations.filter((i) => i.status === 'pending').length,
    error:       integrations.filter((i) => i.status === 'error').length,
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Link2 className="w-6 h-6 text-cyan-400" /> Integrations
          </h2>
          <p className="text-gray-400 text-sm mt-1">
            Associate resources with InfiniteX WAF — load balancers, CDNs, cloud servers, and on-prem apps
          </p>
        </div>
        <button
          onClick={() => { setEditItem(null); setShowForm(true); }}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-xl text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" /> Add Integration
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Total',      value: stats.total,     color: 'text-white',        icon: Link2        },
          { label: 'Connected',  value: stats.connected, color: 'text-green-400',    icon: CheckCircle  },
          { label: 'Pending',    value: stats.pending,   color: 'text-yellow-400',   icon: AlertTriangle},
          { label: 'Error',      value: stats.error,     color: 'text-red-400',      icon: XCircle      },
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

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-800">
        {([
          { key: 'resources', label: `My Resources (${integrations.length})` },
          { key: 'catalogue', label: 'Integration Catalogue' },
        ] as const).map(({ key, label }) => (
          <button key={key} onClick={() => setActiveTab(key)}
            className={`px-4 py-2.5 text-sm border-b-2 transition-all -mb-px ${
              activeTab === key ? 'border-cyan-400 text-cyan-400' : 'border-transparent text-gray-400 hover:text-white'
            }`}>
            {label}
          </button>
        ))}
      </div>

      {/* ── MY RESOURCES TAB ── */}
      {activeTab === 'resources' && (
        <>
          {/* Filters */}
          <div className="flex flex-wrap gap-3 items-center">
            <div className="relative flex-1 min-w-[200px]">
              <Shield className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input value={search} onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by name or host…"
                className="w-full bg-gray-900/50 border border-gray-800 rounded-xl pl-9 pr-4 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500" />
            </div>
            <select value={filterType} onChange={(e) => setFilterType(e.target.value as any)}
              className="bg-gray-900/50 border border-gray-800 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500">
              <option value="all">All Types</option>
              {(Object.entries(TYPE_CATALOGUE) as [IntegrationType, any][]).map(([k, v]) => (
                <option key={k} value={k}>{v.label}</option>
              ))}
            </select>
            <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value as any)}
              className="bg-gray-900/50 border border-gray-800 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500">
              <option value="all">All Statuses</option>
              <option value="connected">Connected</option>
              <option value="disconnected">Disconnected</option>
              <option value="pending">Pending</option>
              <option value="error">Error</option>
            </select>
          </div>

          {/* List */}
          <div className="space-y-3">
            {filtered.length === 0 && (
              <div className="text-center py-16 space-y-4">
                <Link2 className="w-12 h-12 text-gray-700 mx-auto" />
                <p className="text-gray-400">No integrations yet</p>
                <p className="text-gray-600 text-sm">Add your first resource to start routing traffic through InfiniteX WAF</p>
                <button onClick={() => { setEditItem(null); setShowForm(true); }}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-xl text-sm hover:bg-cyan-500/30 transition-colors">
                  <Plus className="w-4 h-4" /> Add Integration
                </button>
              </div>
            )}
            {filtered.map((i) => (
              <IntegrationCard key={i.id} integration={i}
                onEdit={(item) => { setEditItem(item); setShowForm(true); }}
                onDelete={remove}
                onToggle={toggleStatus}
                onTest={testConnection}
              />
            ))}
          </div>
        </>
      )}

      {/* ── CATALOGUE TAB ── */}
      {activeTab === 'catalogue' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {(Object.entries(TYPE_CATALOGUE) as [IntegrationType, typeof TYPE_CATALOGUE[IntegrationType]][]).map(([type, cat]) => {
            const Icon = cat.icon;
            const count = integrations.filter((i) => i.type === type).length;
            return (
              <div key={type} className={`bg-gray-900/50 border rounded-2xl p-5 ${cat.border} hover:border-opacity-60 transition-all`}>
                <div className="flex items-start gap-4 mb-4">
                  <div className={`p-3 rounded-xl ${cat.bg} border ${cat.border} shrink-0`}>
                    <Icon className={`w-6 h-6 ${cat.color}`} />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="text-white font-semibold">{cat.label}</h3>
                      {count > 0 && (
                        <span className="text-xs bg-cyan-500/20 text-cyan-400 px-2 py-0.5 rounded-full">{count} active</span>
                      )}
                    </div>
                    <p className="text-sm text-gray-400 mt-1">{cat.description}</p>
                  </div>
                </div>

                <div className="space-y-1.5 mb-4">
                  {cat.setupSteps.map((step, i) => (
                    <div key={i} className="flex items-start gap-2 text-xs text-gray-500">
                      <span className={`w-4 h-4 rounded-full ${cat.bg} ${cat.color} text-[10px] flex items-center justify-center shrink-0 mt-0.5 font-bold`}>{i + 1}</span>
                      {step}
                    </div>
                  ))}
                </div>

                <button
                  onClick={() => { setEditItem(null); setShowForm(true); setActiveTab('resources'); setTimeout(() => { /* pre-select type */ }, 0); }}
                  className={`w-full flex items-center justify-center gap-2 py-2 rounded-xl text-sm border transition-all ${cat.bg} ${cat.border} ${cat.color} hover:opacity-80`}
                >
                  <Plus className="w-4 h-4" /> Add {cat.label.split(' ').slice(0, 2).join(' ')}
                </button>
              </div>
            );
          })}
        </div>
      )}

      {/* Form modal */}
      {showForm && (
        <IntegrationForm
          initial={editItem}
          onSave={addOrUpdate}
          onClose={() => { setShowForm(false); setEditItem(null); }}
        />
      )}
    </div>
  );
}
