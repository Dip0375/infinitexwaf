import { useState } from 'react';
import { Save, Database, Cloud, HardDrive, Settings, Bell, Shield, CheckCircle } from 'lucide-react';
import toast from 'react-hot-toast';

type StorageType = 's3' | 'azure' | 'gcs' | 'local';
type ExportFormat = 'json' | 'csv' | 'parquet';
type ExportInterval = 'realtime' | 'minute' | 'hour' | 'day';

interface StorageConfig {
  enabled: boolean;
  type: StorageType;
  format: ExportFormat;
  interval: ExportInterval;
  compression: 'gzip' | 'none';
  // S3
  s3Bucket: string;
  s3Region: string;
  s3AccessKey: string;
  s3SecretKey: string;
  s3Prefix: string;
  // Azure
  azureConnectionString: string;
  azureContainerName: string;
  azurePrefix: string;
  // GCS
  gcsBucket: string;
  gcsProjectId: string;
  gcsKeyFile: string;
  gcsPrefix: string;
  // Local
  localPath: string;
}

const DEFAULT_STORAGE: StorageConfig = {
  enabled: false,
  type: 'local',
  format: 'json',
  interval: 'hour',
  compression: 'none',
  s3Bucket: '', s3Region: 'us-east-1', s3AccessKey: '', s3SecretKey: '', s3Prefix: 'infinitex-logs',
  azureConnectionString: '', azureContainerName: '', azurePrefix: 'infinitex-logs',
  gcsBucket: '', gcsProjectId: '', gcsKeyFile: '', gcsPrefix: 'infinitex-logs',
  localPath: './logs/export',
};

const STORAGE_ICONS: Record<StorageType, any> = {
  s3: Cloud,
  azure: Cloud,
  gcs: Cloud,
  local: HardDrive,
};

const STORAGE_LABELS: Record<StorageType, string> = {
  s3: 'AWS S3',
  azure: 'Azure Blob Storage',
  gcs: 'Google Cloud Storage',
  local: 'Local Filesystem',
};

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="text-sm text-gray-400 block mb-1">{label}</label>
      {children}
    </div>
  );
}

function Input({ value, onChange, placeholder, type = 'text' }: {
  value: string; onChange: (v: string) => void; placeholder?: string; type?: string;
}) {
  return (
    <input
      type={type}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
    />
  );
}

export function SettingsPage() {
  const [storage, setStorage] = useState<StorageConfig>(DEFAULT_STORAGE);
  const [activeTab, setActiveTab] = useState<'logging' | 'waf' | 'general'>('logging');
  const [saved, setSaved] = useState(false);

  function set<K extends keyof StorageConfig>(key: K, value: StorageConfig[K]) {
    setStorage((s) => ({ ...s, [key]: value }));
  }

  async function saveConfig() {
    try {
      await fetch('/api/export/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(storage),
      });
      toast.success('Settings saved');
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch {
      toast.error('Failed to save settings');
    }
  }

  async function forceExport() {
    try {
      await fetch('/api/export/force', { method: 'POST' });
      toast.success('Export initiated');
    } catch {
      toast.error('Export failed');
    }
  }

  const StorageIcon = STORAGE_ICONS[storage.type];

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Settings</h2>
          <p className="text-gray-400 text-sm mt-1">Configure logging, storage, and WAF behavior</p>
        </div>
        <button
          onClick={saveConfig}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-xl text-sm transition-colors"
        >
          {saved ? <CheckCircle className="w-4 h-4" /> : <Save className="w-4 h-4" />}
          {saved ? 'Saved' : 'Save Settings'}
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-gray-800">
        {([
          { key: 'logging', label: 'Log Export', icon: Database },
          { key: 'waf', label: 'WAF Config', icon: Shield },
          { key: 'general', label: 'General', icon: Settings },
        ] as const).map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            className={`flex items-center gap-2 px-4 py-2 text-sm border-b-2 transition-all -mb-px ${
              activeTab === key
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            <Icon className="w-4 h-4" /> {label}
          </button>
        ))}
      </div>

      {activeTab === 'logging' && (
        <div className="space-y-6">
          {/* Enable Toggle */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Database className="w-5 h-5 text-cyan-400" />
                <div>
                  <p className="text-white font-medium">Log Export</p>
                  <p className="text-sm text-gray-400">Export WAF logs to object storage or local filesystem</p>
                </div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={storage.enabled}
                  onChange={(e) => set('enabled', e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-500" />
              </label>
            </div>
          </div>

          {/* Storage Type Selector */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-5">
            <h3 className="text-sm font-semibold text-white mb-4">Storage Destination</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {(Object.entries(STORAGE_LABELS) as [StorageType, string][]).map(([type, label]) => {
                const Icon = STORAGE_ICONS[type];
                return (
                  <button
                    key={type}
                    onClick={() => set('type', type)}
                    className={`flex flex-col items-center gap-2 p-4 rounded-xl border transition-all ${
                      storage.type === type
                        ? 'border-cyan-500 bg-cyan-500/10 text-cyan-400'
                        : 'border-gray-700 bg-gray-800/50 text-gray-400 hover:border-gray-600'
                    }`}
                  >
                    <Icon className="w-6 h-6" />
                    <span className="text-xs text-center">{label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Format & Interval */}
          <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-5">
            <h3 className="text-sm font-semibold text-white mb-4">Export Options</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Field label="Format">
                <select
                  value={storage.format}
                  onChange={(e) => set('format', e.target.value as ExportFormat)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="json">JSON</option>
                  <option value="csv">CSV</option>
                  <option value="parquet">Parquet</option>
                </select>
              </Field>
              <Field label="Export Interval">
                <select
                  value={storage.interval}
                  onChange={(e) => set('interval', e.target.value as ExportInterval)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="realtime">Real-time</option>
                  <option value="minute">Every Minute</option>
                  <option value="hour">Every Hour</option>
                  <option value="day">Daily</option>
                </select>
              </Field>
              <Field label="Compression">
                <select
                  value={storage.compression}
                  onChange={(e) => set('compression', e.target.value as 'gzip' | 'none')}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="none">None</option>
                  <option value="gzip">GZIP</option>
                </select>
              </Field>
            </div>
          </div>

          {/* Storage-specific config */}
          {storage.type === 's3' && (
            <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                <Cloud className="w-4 h-4 text-orange-400" /> AWS S3 Configuration
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Field label="Bucket Name"><Input value={storage.s3Bucket} onChange={(v) => set('s3Bucket', v)} placeholder="my-waf-logs" /></Field>
                <Field label="Region"><Input value={storage.s3Region} onChange={(v) => set('s3Region', v)} placeholder="us-east-1" /></Field>
                <Field label="Access Key ID"><Input value={storage.s3AccessKey} onChange={(v) => set('s3AccessKey', v)} placeholder="AKIA..." /></Field>
                <Field label="Secret Access Key"><Input value={storage.s3SecretKey} onChange={(v) => set('s3SecretKey', v)} type="password" placeholder="••••••••" /></Field>
                <Field label="Key Prefix"><Input value={storage.s3Prefix} onChange={(v) => set('s3Prefix', v)} placeholder="infinitex-logs/" /></Field>
              </div>
            </div>
          )}

          {storage.type === 'azure' && (
            <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                <Cloud className="w-4 h-4 text-blue-400" /> Azure Blob Storage Configuration
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="md:col-span-2">
                  <Field label="Connection String"><Input value={storage.azureConnectionString} onChange={(v) => set('azureConnectionString', v)} placeholder="DefaultEndpointsProtocol=https;AccountName=..." /></Field>
                </div>
                <Field label="Container Name"><Input value={storage.azureContainerName} onChange={(v) => set('azureContainerName', v)} placeholder="waf-logs" /></Field>
                <Field label="Blob Prefix"><Input value={storage.azurePrefix} onChange={(v) => set('azurePrefix', v)} placeholder="infinitex-logs/" /></Field>
              </div>
            </div>
          )}

          {storage.type === 'gcs' && (
            <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                <Cloud className="w-4 h-4 text-green-400" /> Google Cloud Storage Configuration
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Field label="Bucket Name"><Input value={storage.gcsBucket} onChange={(v) => set('gcsBucket', v)} placeholder="my-waf-logs" /></Field>
                <Field label="Project ID"><Input value={storage.gcsProjectId} onChange={(v) => set('gcsProjectId', v)} placeholder="my-gcp-project" /></Field>
                <Field label="Service Account Key File"><Input value={storage.gcsKeyFile} onChange={(v) => set('gcsKeyFile', v)} placeholder="/path/to/key.json" /></Field>
                <Field label="Object Prefix"><Input value={storage.gcsPrefix} onChange={(v) => set('gcsPrefix', v)} placeholder="infinitex-logs/" /></Field>
              </div>
            </div>
          )}

          {storage.type === 'local' && (
            <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                <HardDrive className="w-4 h-4 text-gray-400" /> Local Filesystem Configuration
              </h3>
              <Field label="Export Directory">
                <Input value={storage.localPath} onChange={(v) => set('localPath', v)} placeholder="./logs/export" />
              </Field>
            </div>
          )}

          {/* Force Export */}
          <div className="flex justify-end">
            <button
              onClick={forceExport}
              className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-xl text-sm transition-colors border border-gray-700"
            >
              Force Export Now
            </button>
          </div>
        </div>
      )}

      {activeTab === 'waf' && (
        <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-6">
          <div className="flex items-center gap-3 mb-4">
            <Shield className="w-5 h-5 text-cyan-400" />
            <h3 className="text-white font-medium">WAF Rule Configuration</h3>
          </div>
          <p className="text-gray-400 text-sm mb-6">
            WAF rules are configured server-side via <code className="text-cyan-400 bg-gray-800 px-1 rounded">waf-config-advanced.json</code>.
            The following rules are active by default:
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              { id: 'SQLI-001', name: 'SQL Injection', sev: 'CRITICAL' },
              { id: 'XSS-001', name: 'Cross-Site Scripting', sev: 'CRITICAL' },
              { id: 'PT-001', name: 'Path Traversal', sev: 'HIGH' },
              { id: 'CMDI-001', name: 'Command Injection', sev: 'CRITICAL' },
              { id: 'NOSQLI-001', name: 'NoSQL Injection', sev: 'CRITICAL' },
              { id: 'SSRF-001', name: 'Server-Side Request Forgery', sev: 'HIGH' },
              { id: 'BOT-001', name: 'Malicious Bot/Scanner', sev: 'MEDIUM' },
              { id: 'METH-001', name: 'Invalid HTTP Method', sev: 'MEDIUM' },
              { id: 'NULL-001', name: 'Null Byte Injection', sev: 'HIGH' },
            ].map((rule) => {
              const sevColors: Record<string, string> = {
                CRITICAL: 'text-red-400 bg-red-500/10',
                HIGH: 'text-orange-400 bg-orange-500/10',
                MEDIUM: 'text-yellow-400 bg-yellow-500/10',
              };
              return (
                <div key={rule.id} className="flex items-center justify-between bg-gray-800/50 rounded-xl p-3">
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full bg-green-500" />
                    <div>
                      <p className="text-sm text-white">{rule.name}</p>
                      <p className="text-xs text-gray-500">{rule.id}</p>
                    </div>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded ${sevColors[rule.sev]}`}>{rule.sev}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {activeTab === 'general' && (
        <div className="space-y-4">
          <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-5">
            <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
              <Bell className="w-4 h-4 text-cyan-400" /> Notification Channels
            </h3>
            <div className="space-y-3">
              {[
                { label: 'Email Notifications', desc: 'Send alerts via SMTP email' },
                { label: 'Slack Webhook', desc: 'Post alerts to a Slack channel' },
                { label: 'Custom Webhook', desc: 'POST alert payload to any URL' },
              ].map((item) => (
                <div key={item.label} className="flex items-center justify-between p-3 bg-gray-800/50 rounded-xl">
                  <div>
                    <p className="text-sm text-white">{item.label}</p>
                    <p className="text-xs text-gray-500">{item.desc}</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input type="checkbox" className="sr-only peer" />
                    <div className="w-9 h-5 bg-gray-700 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-500" />
                  </label>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-5">
            <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
              <Settings className="w-4 h-4 text-cyan-400" /> Dashboard Preferences
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Field label="Auto-refresh Interval">
                <select className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500">
                  <option value="10">10 seconds</option>
                  <option value="30" selected>30 seconds</option>
                  <option value="60">1 minute</option>
                  <option value="300">5 minutes</option>
                </select>
              </Field>
              <Field label="Timezone">
                <select className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500">
                  <option value="UTC">UTC</option>
                  <option value="America/New_York">Eastern (ET)</option>
                  <option value="America/Los_Angeles">Pacific (PT)</option>
                  <option value="Europe/London">London (GMT)</option>
                  <option value="Asia/Kolkata">India (IST)</option>
                </select>
              </Field>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
