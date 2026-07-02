import { useEffect } from 'react';
import { StatCard } from '../components/StatCard';
import { TrafficChart } from '../components/TrafficChart';
import { GlobalMap } from '../components/GlobalMap';
import { TopTenLists } from '../components/TopTenLists';
import { LiveDataBanner } from '../components/LiveDataBanner';
import { TimeRangePicker } from '../components/TimeRangePicker';
import { useDashboardStore } from '../store/dashboardStore';
import {
  Activity, Shield, CheckCircle, AlertTriangle, Bot, FileText,
} from 'lucide-react';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';

const DIST_COLORS = ['#10b981', '#ef4444', '#a855f7', '#f59e0b'];

export function Dashboard() {
  const { metrics, distribution, refreshAll } = useDashboardStore();

  useEffect(() => {
    refreshAll();
    const interval = setInterval(refreshAll, 30000);
    return () => clearInterval(interval);
  }, [refreshAll]);

  const blockedRate = metrics.total > 0
    ? ((metrics.blocked / metrics.total) * 100).toFixed(1) : '0.0';
  const botRate = metrics.total > 0
    ? ((metrics.bot / metrics.total) * 100).toFixed(1) : '0.0';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white">Security Overview</h2>
          <p className="text-gray-400 text-sm mt-1">Real-time WAF analytics and threat intelligence</p>
        </div>
        <TimeRangePicker />
      </div>

      {/* Live data status banner */}
      <LiveDataBanner />

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard
          title="Total Traffic"
          value={metrics.total.toLocaleString()}
          subtitle="All requests"
          icon={<Activity className="w-6 h-6 text-cyan-400" />}
          color="cyan"
          trend="up"
          trendValue={12}
        />
        <StatCard
          title="Blocked"
          value={metrics.blocked.toLocaleString()}
          subtitle={`${blockedRate}% of total`}
          icon={<Shield className="w-6 h-6 text-red-400" />}
          color="red"
          trend="down"
          trendValue={5}
        />
        <StatCard
          title="Allowed"
          value={metrics.allowed.toLocaleString()}
          subtitle="Legitimate traffic"
          icon={<CheckCircle className="w-6 h-6 text-green-400" />}
          color="green"
          trend="up"
          trendValue={8}
        />
        <StatCard
          title="Logged"
          value={metrics.logged.toLocaleString()}
          subtitle="Events logged"
          icon={<FileText className="w-6 h-6 text-yellow-400" />}
          color="yellow"
        />
        <StatCard
          title="Bot Traffic"
          value={metrics.bot.toLocaleString()}
          subtitle={`${botRate}% of total`}
          icon={<Bot className="w-6 h-6 text-purple-400" />}
          color="purple"
          trend="up"
          trendValue={15}
        />
        <StatCard
          title="Threat Score"
          value="24/100"
          subtitle="Current risk level"
          icon={<AlertTriangle className="w-6 h-6 text-orange-400" />}
          color="yellow"
          trend="down"
          trendValue={3}
        />
      </div>

      {/* Traffic Chart & Global Map */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <TrafficChart />
        <GlobalMap />
      </div>

      {/* Top 10 Lists */}
      <TopTenLists />

      {/* Traffic Distribution */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-6">
          <h3 className="text-lg font-semibold text-white mb-6">Traffic Distribution</h3>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie
                data={distribution}
                cx="50%"
                cy="50%"
                innerRadius={65}
                outerRadius={100}
                paddingAngle={3}
                dataKey="value"
              >
                {distribution.map((entry, index) => (
                  <Cell key={entry.name} fill={DIST_COLORS[index % DIST_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: '8px' }}
                formatter={(v: number) => [`${v}%`, '']}
              />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Quick Stats */}
        <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-6">
          <h3 className="text-lg font-semibold text-white mb-6">Traffic Segregation</h3>
          <div className="space-y-4">
            {[
              { label: 'Legitimate Traffic', value: metrics.legitimate, color: '#10b981', pct: metrics.total > 0 ? ((metrics.legitimate / metrics.total) * 100).toFixed(1) : '0' },
              { label: 'Bot Traffic', value: metrics.bot, color: '#a855f7', pct: botRate },
              { label: 'Blocked Requests', value: metrics.blocked, color: '#ef4444', pct: blockedRate },
              { label: 'Logged Events', value: metrics.logged, color: '#f59e0b', pct: metrics.total > 0 ? ((metrics.logged / metrics.total) * 100).toFixed(1) : '0' },
            ].map((item) => (
              <div key={item.label}>
                <div className="flex justify-between mb-1.5">
                  <span className="text-sm text-gray-300">{item.label}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-white">{item.value.toLocaleString()}</span>
                    <span className="text-xs text-gray-500">{item.pct}%</span>
                  </div>
                </div>
                <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${item.pct}%`, backgroundColor: item.color }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
