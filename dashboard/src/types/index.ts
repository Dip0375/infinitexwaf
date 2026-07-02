export interface TrafficMetrics {
  total: number;
  blocked: number;
  allowed: number;
  logged: number;
  bot: number;
  legitimate: number;
  timestamp: string;
}

export interface GeoLocation {
  country: string;
  countryCode: string;
  lat: number;
  lng: number;
  requests: number;
  blocked: number;
  allowed: number;
}

export interface MapDataPoint {
  id: string;
  lat: number;
  lng: number;
  country: string;
  requests: number;
  type: 'legitimate' | 'bot' | 'blocked' | 'threat';
  intensity: number;
}

export interface TopItem {
  name: string;
  count: number;
  percentage: number;
  trend?: 'up' | 'down' | 'neutral';
  trendValue?: number;
}

export interface RuleHit {
  ruleId: string;
  name: string;
  category: string;
  hits: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface TimeSeriesData {
  timestamp: string;
  total: number;
  blocked: number;
  allowed: number;
  bot: number;
}

export interface TrafficDistribution {
  name: string;
  value: number;
  color: string;
}

export interface AlertConfig {
  id: string;
  name: string;
  type: 'rate_limit' | 'threat' | 'ddos' | 'bot' | 'custom';
  threshold: number;
  timeWindow: number;
  emailRecipients: string[];
  enabled: boolean;
  lastTriggered?: string;
}

export interface StorageConfig {
  type: 's3' | 'azure' | 'gcs' | 'local';
  enabled: boolean;
  bucket?: string;
  region?: string;
  accessKey?: string;
  secretKey?: string;
  endpoint?: string;
  prefix?: string;
}

export interface DashboardState {
  metrics: TrafficMetrics;
  geoData: GeoLocation[];
  mapPoints: MapDataPoint[];
  topCountries: TopItem[];
  topIPs: TopItem[];
  topRules: RuleHit[];
  topUserAgents: TopItem[];
  topPaths: TopItem[];
  timeSeries: TimeSeriesData[];
  distribution: TrafficDistribution[];
  isLoading: boolean;
  error: string | null;
}
