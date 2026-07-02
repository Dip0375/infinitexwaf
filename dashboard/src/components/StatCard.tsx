import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  trend?: 'up' | 'down' | 'neutral';
  trendValue?: number;
  icon: React.ReactNode;
  color: 'cyan' | 'red' | 'green' | 'yellow' | 'purple';
}

const colorClasses = {
  cyan: 'from-cyan-500/20 to-blue-500/20 border-cyan-500/30 text-cyan-400',
  red: 'from-red-500/20 to-orange-500/20 border-red-500/30 text-red-400',
  green: 'from-green-500/20 to-emerald-500/20 border-green-500/30 text-green-400',
  yellow: 'from-yellow-500/20 to-amber-500/20 border-yellow-500/30 text-yellow-400',
  purple: 'from-purple-500/20 to-pink-500/20 border-purple-500/30 text-purple-400',
};

export function StatCard({ title, value, subtitle, trend, trendValue, icon, color }: StatCardProps) {
  return (
    <div className={`relative overflow-hidden rounded-2xl border bg-gradient-to-br ${colorClasses[color]} p-6`}>
      <div className="relative z-10">
        <div className="flex items-center justify-between mb-4">
          <div className={`p-3 rounded-xl bg-${color}-500/20`}>{icon}</div>
          {trend && (
            <div className={`flex items-center gap-1 text-sm ${
              trend === 'up' ? 'text-green-400' : trend === 'down' ? 'text-red-400' : 'text-gray-400'
            }`}>
              {trend === 'up' ? <TrendingUp className="w-4 h-4" /> :
               trend === 'down' ? <TrendingDown className="w-4 h-4" /> :
               <Minus className="w-4 h-4" />}
              <span>{trendValue ? `${trendValue}%` : ''}</span>
            </div>
          )}
        </div>

        <h3 className="text-3xl font-bold text-white mb-1">{value}</h3>
        <p className="text-sm text-gray-400">{title}</p>
        {subtitle && <p className="text-xs text-gray-500 mt-2">{subtitle}</p>}
      </div>

      {/* Background decoration */}
      <div className="absolute -right-6 -bottom-6 w-32 h-32 bg-white/5 rounded-full blur-3xl" />
    </div>
  );
}
