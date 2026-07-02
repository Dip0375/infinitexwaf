import { useEffect, useState } from 'react';
import { useDashboardStore } from '../store/dashboardStore';
import { TrafficChart } from '../components/TrafficChart';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts';
import { Activity, Shield, CheckCircle, Bot, FileText, TrendingUp } from 'lucide-react';

const COLORS = ['#10b981', '#ef4444', '#a855f7', '#f59e0b'];

export function TrafficAnalysis() {
  const { metrics, distribution, timeSeries, refreshAll } = useDashboardStore();
  const [activeTab, setActiveTab] = useState<'overview' | 'segregation'>('overview');

  useEffect(() => {
    refreshAll();
    const interval = setInterval(refreshAll, 30000);
    return () => clearInterval(interval);
  }, [refreshAll]);

  const segregationData = [
    { name: 'Legitimate', value: metrics.legitimate, color: '#10b981', icon: CheckCircle },
    { name: 'Bot Traffic', value: metrics.bot, color: '#a855f7', icon: Bot },
    { name: 'Blocked', value: metrics.blocked, color: '#ef4444', icon: Shield },
    { name: 'Logged', value: metrics.logged, color: '#f59e0b', icon: FileText },
  ];

  const hourlyBreakdown = timeSeries.slice(-12).map((d) => ({
    time: new Date(d.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
    Legitimate: d.allowed - (d.bot || 0),
    Bot: d.bot || 0,
    Blocked: d.blocked,
  }));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Traffic Analysis</h2>
          <p className="text-gray-400 text-sm mt-1">Real-time traffic monitoring and segregation</p>
        </div>
        <div className="flex gap-2">
          {(['overview', 'segregation'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 rounded-lg text-sm capitalize transition-all ${
                activeTab === tab
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                  : 'text-gray-400 hover:bg-gray-800'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {segregationData.map((item) => {
          const Icon = item.icon;
          const pct = metrics.total > 0 ? ((item.value / metrics.total) * 100).toFixed(1) : '0.0';
          return (
            <div
              key={item.name}
              className="bg-gray-900/50 border border-gray-800 rounded-2xl p-5"
              style={{ borderLeftColor: item.color, borderLeftWidth: 3 }}
            >
              <div className="flex items-center gap-3 mb-3">
                <Icon className="w-5 h-5" style={{ color: item.color }} />
                <span className="text-sm text-gray-400">{item.name}</span>
              </div>
              <p className="text-3xl font-bold text-white">{item.value.toLocaleString()}</p>
              <p className="text-xs mt-1" style={{ color: item.color }}>{pct}% of total</p>
            </div>
          );
        })}
      </div>

      {/* Traffic Chart */}
      <TrafficChart />

      {activeTab === 'segregation' && (
        <>
          {/* Pie Chart + Bar Chart */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-6">
              <h3 className="text-lg font-semibold text-white mb-6">Traffic Distribution</h3>
              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie
                    data={distribution}
                    cx="50%"
                    cy="50%"
                    innerRadius={70}
                    outerRadius={110}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {distribution.map((entry, index) => (
                      <Cell key={entry.name} fill={COLORS[index % COLORS.length]} />
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

            <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-6">
              <h3 className="text-lg font-semibold text-white mb-6">Hourly Traffic Breakdown</h3>
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={hourlyBreakdown} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="time" stroke="#9ca3af" fontSize={11} />
                  <YAxis stroke="#9ca3af" fontSize={11} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: '8px' }}
                  />
                  <Legend />
                  <Bar dataKey="Legitimate" stackId="a" fill="#10b981" radius={[0, 0, 0, 0]} />
                  <Bar dataKey="Bot" stackId="a" fill="#a855f7" />
                  <Bar dataKey="Blocked" stackId="a" fill="#ef4444" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Bandwidth note */}
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-2xl p-5 flex items-start gap-4">
            <TrendingUp className="w-5 h-5 text-yellow-400 mt-0.5 shrink-0" />
            <div>
              <p className="text-yellow-400 font-medium text-sm">Traffic Inspection Mode</p>
              <p className="text-gray-400 text-sm mt-1">
                InfiniteX operates on request-level inspection — no bandwidth throttling or byte-level rate limiting is applied.
                All traffic counts are based on HTTP request inspection, not data transfer volume.
              </p>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
