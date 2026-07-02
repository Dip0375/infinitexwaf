import { useDashboardStore } from '../store/dashboardStore';
import { Globe, Server, Shield, Monitor, FileText, TrendingUp, TrendingDown } from 'lucide-react';

interface TopItemRowProps {
  rank: number;
  name: string;
  count: number;
  maxCount: number;
  trend?: 'up' | 'down' | 'neutral';
  trendValue?: number;
}

function TopItemRow({ rank, name, count, maxCount, trend, trendValue }: TopItemRowProps) {
  return (
    <div className="flex items-center gap-4 py-2.5 group">
      <span className={`w-6 text-center font-mono text-sm shrink-0 ${rank <= 3 ? 'text-cyan-400 font-bold' : 'text-gray-500'}`}>
        {rank}
      </span>
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between mb-1">
          <p className="text-sm text-white truncate" title={name}>{name}</p>
          <div className="flex items-center gap-2 shrink-0 ml-2">
            <span className="text-sm font-medium text-white">{count.toLocaleString()}</span>
            {trend && trend !== 'neutral' && (
              <span className={`flex items-center text-xs ${trend === 'up' ? 'text-red-400' : 'text-green-400'}`}>
                {trend === 'up' ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
                {trendValue}%
              </span>
            )}
          </div>
        </div>
        <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-500 group-hover:from-cyan-400 group-hover:to-blue-400"
            style={{ width: `${(count / maxCount) * 100}%` }}
          />
        </div>
      </div>
    </div>
  );
}

function TopListCard({
  title,
  icon: Icon,
  items,
  colorClass,
}: {
  title: string;
  icon: any;
  items: { name: string; count: number; percentage?: number; trend?: string; trendValue?: number }[];
  colorClass: string;
}) {
  const maxCount = items[0]?.count || 1;
  return (
    <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-6">
      <div className="flex items-center gap-3 mb-5">
        <div className={`p-2 rounded-xl ${colorClass}`}>
          <Icon className="w-5 h-5 text-white" />
        </div>
        <h3 className="text-lg font-semibold text-white">{title}</h3>
      </div>
      <div className="space-y-0.5">
        {items.slice(0, 10).map((item, index) => (
          <TopItemRow
            key={item.name}
            rank={index + 1}
            name={item.name}
            count={item.count}
            maxCount={maxCount}
            trend={item.trend as any}
            trendValue={item.trendValue}
          />
        ))}
        {items.length === 0 && (
          <p className="text-gray-500 text-sm text-center py-6">No data yet</p>
        )}
      </div>
    </div>
  );
}

export function TopTenLists() {
  const { topCountries, topIPs, topRules, topUserAgents, topPaths } = useDashboardStore();

  const ruleItems = topRules.map((r) => ({
    name: `${r.name} (${r.ruleId})`,
    count: r.hits,
    percentage: 0,
  }));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6">
      <TopListCard title="Top 10 Countries" icon={Globe} items={topCountries} colorClass="bg-cyan-500" />
      <TopListCard title="Top 10 IP Addresses" icon={Server} items={topIPs} colorClass="bg-blue-500" />
      <TopListCard title="Top 10 WAF Rules" icon={Shield} items={ruleItems} colorClass="bg-red-500" />
      <TopListCard title="Top 10 User Agents" icon={Monitor} items={topUserAgents} colorClass="bg-purple-500" />
      <TopListCard title="Top 10 URI Paths" icon={FileText} items={topPaths} colorClass="bg-green-500" />

      {/* Traffic Insights */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-6">
        <div className="flex items-center gap-3 mb-5">
          <div className="p-2 rounded-xl bg-yellow-500">
            <TrendingUp className="w-5 h-5 text-white" />
          </div>
          <h3 className="text-lg font-semibold text-white">Traffic Insights</h3>
        </div>
        <div className="space-y-4">
          <div className="bg-gray-800/50 rounded-xl p-4">
            <p className="text-sm text-gray-400 mb-1">Top Threat Category</p>
            <p className="text-lg font-semibold text-red-400">SQL Injection</p>
            <p className="text-xs text-gray-500">42% of all blocked requests</p>
          </div>
          <div className="bg-gray-800/50 rounded-xl p-4">
            <p className="text-sm text-gray-400 mb-1">Peak Traffic Hour</p>
            <p className="text-lg font-semibold text-cyan-400">14:00 - 15:00 UTC</p>
            <p className="text-xs text-gray-500">15,234 requests</p>
          </div>
          <div className="bg-gray-800/50 rounded-xl p-4">
            <p className="text-sm text-gray-400 mb-1">Avg Inspection Latency</p>
            <p className="text-lg font-semibold text-green-400">4.2ms</p>
            <p className="text-xs text-gray-500"><span className="text-green-400">↓ 12%</span> from last hour</p>
          </div>
        </div>
      </div>
    </div>
  );
}
