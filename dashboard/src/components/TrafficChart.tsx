import {
  XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Area, AreaChart, Legend,
} from 'recharts';
import { useDashboardStore } from '../store/dashboardStore';
import { useTimeRange } from '../context/TimeRangeContext';
import { useEffect } from 'react';

export function TrafficChart() {
  const { timeSeries, fetchTimeSeries, isLoading } = useDashboardStore();
  const { range } = useTimeRange();

  useEffect(() => {
    fetchTimeSeries(range.apiRange);
  }, [range.apiRange, fetchTimeSeries]);

  const formatXAxis = (timestamp: string) => {
    const date = new Date(timestamp);
    if (range.apiRange === '1h') {
      return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    }
    if (range.apiRange === '6h' || range.apiRange === '24h') {
      return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    }
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  };

  return (
    <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold text-white">Traffic Overview</h3>
          <p className="text-xs text-gray-500 mt-0.5">{range.label}</p>
        </div>
      </div>

      <div className="h-80">
        {isLoading ? (
          <div className="flex items-center justify-center h-full">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400" />
          </div>
        ) : timeSeries.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-gray-600 gap-2">
            <span className="text-4xl">📊</span>
            <p className="text-sm">No traffic data for this time range</p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeSeries} margin={{ top: 5, right: 30, left: 0, bottom: 5 }}>
              <defs>
                <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorBot" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#a855f7" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#a855f7" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="timestamp" tickFormatter={formatXAxis} stroke="#9ca3af" fontSize={12} />
              <YAxis stroke="#9ca3af" fontSize={12} />
              <Tooltip
                contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151', borderRadius: '8px' }}
                labelStyle={{ color: '#fff' }}
                labelFormatter={(v) => new Date(v).toLocaleString()}
              />
              <Legend />
              <Area type="monotone" dataKey="total"   name="Total"   stroke="#06b6d4" fillOpacity={1} fill="url(#colorTotal)"   strokeWidth={2} />
              <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#ef4444" fillOpacity={1} fill="url(#colorBlocked)" strokeWidth={2} />
              <Area type="monotone" dataKey="bot"     name="Bot"     stroke="#a855f7" fillOpacity={1} fill="url(#colorBot)"     strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
