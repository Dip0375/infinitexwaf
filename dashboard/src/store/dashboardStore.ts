import { create } from 'zustand';
import { DashboardState, TimeSeriesData, MapDataPoint, GeoLocation, TopItem, RuleHit, TrafficDistribution } from '../types';

interface DashboardStore extends DashboardState {
  isLive: boolean;
  requestsProcessed: number;
  lastRequestAt: string | null;
  fetchMetrics: () => Promise<void>;
  fetchGeoData: () => Promise<void>;
  fetchTimeSeries: (range: string) => Promise<void>;
  fetchStatus: () => Promise<void>;
  refreshAll: () => Promise<void>;
}

const API_BASE = '/api/dashboard';

export const useDashboardStore = create<DashboardStore>((set, get) => ({
  metrics: {
    total: 0, blocked: 0, allowed: 0, logged: 0,
    bot: 0, legitimate: 0, timestamp: new Date().toISOString(),
  },
  geoData: [],
  mapPoints: [],
  topCountries: [],
  topIPs: [],
  topRules: [],
  topUserAgents: [],
  topPaths: [],
  timeSeries: [],
  distribution: [],
  isLoading: false,
  error: null,
  isLive: false,
  requestsProcessed: 0,
  lastRequestAt: null,

  fetchMetrics: async () => {
    try {
      set({ isLoading: true });
      const response = await fetch(`${API_BASE}/metrics`);
      const data = await response.json();
      set({
        metrics: data.metrics,
        topCountries: data.topCountries,
        topIPs: data.topIPs,
        topRules: data.topRules,
        topUserAgents: data.topUserAgents,
        topPaths: data.topPaths,
        distribution: data.distribution,
        isLoading: false,
      });
    } catch (error) {
      set({ error: 'Failed to fetch metrics', isLoading: false });
    }
  },

  fetchGeoData: async () => {
    try {
      const response = await fetch(`${API_BASE}/geo`);
      const data = await response.json();
      set({
        geoData: data.geoData,
        mapPoints: data.mapPoints,
      });
    } catch (error) {
      set({ error: 'Failed to fetch geo data' });
    }
  },

  fetchTimeSeries: async (range: string) => {
    try {
      const response = await fetch(`${API_BASE}/timeseries?range=${range}`);
      const data = await response.json();
      set({ timeSeries: data.timeSeries });
    } catch (error) {
      set({ error: 'Failed to fetch time series data' });
    }
  },

  fetchStatus: async () => {
    try {
      const response = await fetch(`${API_BASE}/status`);
      const data = await response.json();
      set({
        isLive: data.isLive ?? false,
        requestsProcessed: data.requestsProcessed ?? 0,
        lastRequestAt: data.lastRequestAt ?? null,
      });
    } catch {
      // status endpoint may not exist on dev server — ignore
    }
  },

  refreshAll: async () => {
    await get().fetchStatus();
    await get().fetchMetrics();
    await get().fetchGeoData();
    await get().fetchTimeSeries('24h');
  },
}));
