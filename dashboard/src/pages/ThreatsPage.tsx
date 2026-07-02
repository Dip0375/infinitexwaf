import { useEffect } from 'react';
import { useDashboardStore } from '../store/dashboardStore';
import { Shield, Server, Monitor, FileText, Globe, TrendingUp, TrendingDown } from 'lucide-react';

function TopList({
  title,
  icon: Icon,
  color,
  items,
  valueLabel = 'Hits',
}: {
  title: string;
  icon: any;
  color: string;
  items: { name: string; count: number; percentage?: number; trend?: string; trendValue?: number }[];
  valueLabel?: string;
}) {
  const max = items[0]?.count || 1;
  return (
    <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-6">
      <div className="flex items-center gap-3 mb-5">
        <div className={`p-2 rounded-xl ${color}`}>
          <Icon className="w-5 h-5 text-white" />
        </div>
        <h3 className="text-lg font-semibold text-white">{title}</h3>
      </div>
      <div className="space-y-1">
        {items.slice(0, 10).map((item, i) => (
          <div key={item.name} className="flex items-center gap-3 py-2.5 group">
            <span className={`w-6 text-center font-mono text-sm shrink-0 ${i < 3 ? 'text-cyan-400 font-bold' : 'text-gray-500'}`}>
              {i + 1}
            </span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between mb-1">
                <p className="text-sm text-white truncate" title={item.name}>{item.name}</p>
                <div className="flex items-center gap-2 shrink-0 ml-2">
                  <span className="text-sm font-medium text-white">{item.count.toLocaleString()}</span>
                  {item.trend && (
                    <span className={`flex items-center text-xs ${item.trend === 'up' ? 'text-red-400' : 'text-green-400'}`}>
                      {item.trend === 'up' ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
                      {item.trendValue}%
                    </span>
                  )}
                </div>
              </div>
              <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-500 group-hover:from-cyan-400 group-hover:to-blue-400"
                  style={{ width: `${(item.count / max) * 100}%` }}
                />
              </div>
            </div>
          </div>
        ))}
        {items.length === 0 && (
          <p className="text-gray-500 text-sm text-center py-6">No data yet</p>
        )}
      </div>
    </div>
  );
}

export function ThreatsPage() {
  const { topIPs, topRules, topUserAgents, topPaths, topCountries, refreshAll } = useDashboardStore();

  useEffect(() => {
    refreshAll();
    const interval = setInterval(refreshAll, 30000);
    return () => clearInterval(interval);
  }, [refreshAll]);

  const ruleItems = topRules.map((r) => ({
    name: `${r.name} (${r.ruleId})`,
    count: r.hits,
    percentage: 0,
    badge: r.severity,
  }));

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white">Threats & Inspections</h2>
        <p className="text-gray-400 text-sm mt-1">Top 10 lists for IPs, WAF rules, user agents, URI paths, and geolocations</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
        <TopList
          title="Top 10 IP Addresses"
          icon={Server}
          color="bg-blue-500"
          items={topIPs}
        />

        <TopList
          title="Top 10 WAF Rules Triggered"
          icon={Shield}
          color="bg-red-500"
          items={ruleItems}
          valueLabel="Hits"
        />

        <TopList
          title="Top 10 User Agents"
          icon={Monitor}
          color="bg-purple-500"
          items={topUserAgents}
        />

        <TopList
          title="Top 10 URI Paths"
          icon={FileText}
          color="bg-green-500"
          items={topPaths}
        />

        <TopList
          title="Top 10 Geolocations"
          icon={Globe}
          color="bg-cyan-500"
          items={topCountries}
        />

        {/* Severity breakdown */}
        <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-6">
          <div className="flex items-center gap-3 mb-5">
            <div className="p-2 rounded-xl bg-orange-500">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <h3 className="text-lg font-semibold text-white">Rule Severity Breakdown</h3>
          </div>
          <div className="space-y-3">
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => {
              const sevColors = {
                CRITICAL: 'bg-red-500',
                HIGH: 'bg-orange-500',
                MEDIUM: 'bg-yellow-500',
                LOW: 'bg-green-500',
              };
              const count = topRules.filter((r) => r.severity === sev).reduce((a, r) => a + r.hits, 0);
              const total = topRules.reduce((a, r) => a + r.hits, 0) || 1;
              return (
                <div key={sev} className="flex items-center gap-3">
                  <span className={`text-xs px-2 py-0.5 rounded font-medium text-white ${sevColors[sev]}`}>{sev}</span>
                  <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${sevColors[sev]} rounded-full`}
                      style={{ width: `${(count / total) * 100}%` }}
                    />
                  </div>
                  <span className="text-sm text-gray-400 w-12 text-right">{count.toLocaleString()}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
