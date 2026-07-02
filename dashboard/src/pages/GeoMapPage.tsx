import { useEffect, useState } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import { useDashboardStore } from '../store/dashboardStore';
import { Shield, Bot, AlertTriangle, CheckCircle, Globe } from 'lucide-react';

function MapController() {
  const map = useMap();
  useEffect(() => { map.setView([20, 0], 2); }, [map]);
  return null;
}

const TYPE_CONFIG = {
  legitimate: { color: '#10b981', label: 'Legitimate', icon: CheckCircle },
  bot:        { color: '#a855f7', label: 'Bot',        icon: Bot },
  blocked:    { color: '#ef4444', label: 'Blocked',    icon: Shield },
  threat:     { color: '#f59e0b', label: 'Threat',     icon: AlertTriangle },
} as const;

export function GeoMapPage() {
  const { mapPoints, geoData, fetchGeoData, topCountries } = useDashboardStore();
  const [filter, setFilter] = useState<string | null>(null);

  useEffect(() => {
    fetchGeoData();
    const interval = setInterval(fetchGeoData, 30000);
    return () => clearInterval(interval);
  }, [fetchGeoData]);

  const filtered = filter ? mapPoints.filter((p) => p.type === filter) : mapPoints;

  const stats = {
    total: mapPoints.length,
    legitimate: mapPoints.filter((p) => p.type === 'legitimate').length,
    bot: mapPoints.filter((p) => p.type === 'bot').length,
    blocked: mapPoints.filter((p) => p.type === 'blocked').length,
    threat: mapPoints.filter((p) => p.type === 'threat').length,
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white">Global Traffic Map</h2>
        <p className="text-gray-400 text-sm mt-1">Real-time geographic threat visualization and traffic origin</p>
      </div>

      {/* Filter Buttons */}
      <div className="flex flex-wrap gap-3">
        <button
          onClick={() => setFilter(null)}
          className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm transition-all ${
            !filter ? 'bg-gray-700 text-white border border-gray-500' : 'bg-gray-900/50 text-gray-400 border border-gray-800 hover:bg-gray-800'
          }`}
        >
          <Globe className="w-4 h-4" /> All ({stats.total})
        </button>
        {(Object.entries(TYPE_CONFIG) as [string, typeof TYPE_CONFIG[keyof typeof TYPE_CONFIG]][]).map(([type, cfg]) => {
          const Icon = cfg.icon;
          const count = stats[type as keyof typeof stats] ?? 0;
          return (
            <button
              key={type}
              onClick={() => setFilter(filter === type ? null : type)}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm transition-all border ${
                filter === type ? 'bg-gray-800' : 'bg-gray-900/50 hover:bg-gray-800'
              }`}
              style={{ color: cfg.color, borderColor: filter === type ? cfg.color : '#374151' }}
            >
              <Icon className="w-4 h-4" />
              {cfg.label} ({count})
            </button>
          );
        })}
      </div>

      {/* Map */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-2xl overflow-hidden">
        <div className="h-[500px]">
          <MapContainer center={[20, 0]} zoom={2} scrollWheelZoom className="h-full w-full" style={{ background: '#111827' }}>
            <MapController />
            <TileLayer
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            />
            {filtered.map((point) => {
              const cfg = TYPE_CONFIG[point.type];
              return (
                <CircleMarker
                  key={point.id}
                  center={[point.lat, point.lng]}
                  radius={Math.min(Math.max(point.intensity / 10, 5), 22)}
                  fillColor={cfg.color}
                  color={cfg.color}
                  fillOpacity={0.65}
                  weight={1.5}
                >
                  <Popup>
                    <div className="p-2 min-w-[140px]">
                      <p className="font-semibold text-gray-900">{point.country}</p>
                      <p className="text-sm text-gray-600">Requests: {point.requests}</p>
                      <p className="text-sm capitalize" style={{ color: cfg.color }}>
                        {cfg.label}
                      </p>
                      <p className="text-xs text-gray-500">Intensity: {Math.round(point.intensity)}</p>
                    </div>
                  </Popup>
                </CircleMarker>
              );
            })}
          </MapContainer>
        </div>

        {/* Legend */}
        <div className="p-4 border-t border-gray-800 flex flex-wrap gap-4">
          {Object.entries(TYPE_CONFIG).map(([type, cfg]) => (
            <div key={type} className="flex items-center gap-2 text-sm text-gray-400">
              <div className="w-3 h-3 rounded-full" style={{ backgroundColor: cfg.color }} />
              {cfg.label}
            </div>
          ))}
          <span className="text-xs text-gray-600 ml-auto">Circle size = threat intensity</span>
        </div>
      </div>

      {/* Top Geolocations */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-6">
        <h3 className="text-lg font-semibold text-white mb-5 flex items-center gap-2">
          <Globe className="w-5 h-5 text-cyan-400" /> Top 10 Geolocations
        </h3>
        <div className="space-y-3">
          {topCountries.slice(0, 10).map((country, i) => (
            <div key={country.name} className="flex items-center gap-4">
              <span className={`w-6 text-center font-mono text-sm ${i < 3 ? 'text-cyan-400 font-bold' : 'text-gray-500'}`}>
                {i + 1}
              </span>
              <div className="flex-1">
                <div className="flex justify-between mb-1">
                  <span className="text-sm text-white">{country.name}</span>
                  <span className="text-sm text-gray-400">{country.count.toLocaleString()}</span>
                </div>
                <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full"
                    style={{ width: `${country.percentage}%` }}
                  />
                </div>
              </div>
              <span className="text-xs text-gray-500 w-10 text-right">{country.percentage}%</span>
            </div>
          ))}
          {topCountries.length === 0 && (
            <p className="text-gray-500 text-sm text-center py-4">No geographic data yet</p>
          )}
        </div>
      </div>
    </div>
  );
}
