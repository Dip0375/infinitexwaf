import { useDashboardStore } from '../store/dashboardStore';
import { Activity, Clock, AlertTriangle, CheckCircle } from 'lucide-react';

export function LiveDataBanner() {
  const { isLive, requestsProcessed, lastRequestAt } = useDashboardStore();

  if (isLive) {
    return (
      <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-green-500/10 border border-green-500/20 text-sm">
        <span className="relative flex h-2.5 w-2.5 shrink-0">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-500" />
        </span>
        <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
        <span className="text-green-300 font-medium">Live Data</span>
        <span className="text-green-500 hidden sm:inline">
          — {requestsProcessed.toLocaleString()} real requests processed
        </span>
        {lastRequestAt && (
          <span className="text-green-600 hidden md:inline ml-auto flex items-center gap-1">
            <Clock className="w-3 h-3" />
            Last: {new Date(lastRequestAt).toLocaleTimeString()}
          </span>
        )}
      </div>
    );
  }

  return (
    <div className="flex items-center gap-3 px-4 py-2.5 rounded-xl bg-yellow-500/10 border border-yellow-500/20 text-sm">
      <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0" />
      <span className="text-yellow-300 font-medium">Waiting for traffic</span>
      <span className="text-yellow-600 hidden sm:inline">
        — No real requests have passed through the WAF yet.
        Point your application traffic at the WAF to see live data.
      </span>
      <span className="ml-auto flex items-center gap-1.5 text-yellow-600 text-xs shrink-0">
        <Activity className="w-3 h-3 animate-pulse" />
        Polling every 30s
      </span>
    </div>
  );
}
