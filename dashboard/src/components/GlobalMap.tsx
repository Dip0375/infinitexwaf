import { useEffect, useState } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import { useDashboardStore } from '../store/dashboardStore';
import { Shield, Globe, AlertTriangle, Bot } from 'lucide-react';

function MapController() {
  const map = useMap();
  useEffect(() => {
    map.setView([20, 0], 2);
  }, [map]);
  return null;
}

const typeColors = {
  legitimate: '#10b981',
  bot: '#a855f7',
  blocked: '#ef4444',
  threat: '#f59e0b',
};

const typeIcons = {
  legitimate: Shield,
  bot: Bot,
  blocked: AlertTriangle,
  threat: AlertTriangle,
};

export function GlobalMap() {
  const { mapPoints, fetchGeoData, isLoading } = useDashboardStore();
  const [selectedType, setSelectedType] = useState<string | null>(null);

  useEffect(() => {
    fetchGeoData();
    const interval = setInterval(fetchGeoData, 30000);
    return () => clearInterval(interval);
  }, [fetchGeoData]);

  const filteredPoints = selectedType
    ? mapPoints.filter((p) => p.type === selectedType)
    : mapPoints;

  const stats = {
    total: mapPoints.length,
    legitimate: mapPoints.filter((p) => p.type === 'legitimate').length,
    bot: mapPoints.filter((p) => p.type === 'bot').length,
    blocked: mapPoints.filter((p) => p.type === 'blocked').length,
    threat: mapPoints.filter((p) => p.type === 'threat').length,
  };

  return (
    <div className="bg-gray-900/50 border border-gray-800 rounded-2xl p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-lg font-semibold text-white">Global Traffic Map</h3>
          <p className="text-sm text-gray-400">Real-time threat visualization</p>
        </div>
        <div className="flex items-center gap-4">
          {Object.entries(typeColors).map(([type, color]) => (
            <button
              key={type}
              onClick={() => setSelectedType(selectedType === type ? null : type)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-all ${
                selectedType === type
                  ? 'bg-gray-800 ring-2'
                  : 'hover:bg-gray-800'
              }`}
              style={{ color, ...(selectedType === type ? { ringColor: color } : {}) }}
            >
              <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
              <span className="capitalize">{type}</span>
              <span className="text-gray-500">(
                {type === 'legitimate' ? stats.legitimate :
                 type === 'bot' ? stats.bot :
                 type === 'blocked' ? stats.blocked : stats.threat}
              )</span>
            </button>
          ))}
        </div>
      </div>

      <div className="h-96 rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-full bg-gray-900">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-400" />
          </div>
        ) : (
          <MapContainer
            center={[20, 0]}
            zoom={2}
            scrollWheelZoom={true}
            className="h-full w-full"
            style={{ background: '#111827' }}
          >
            <MapController />
            <TileLayer
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            />
            {filteredPoints.map((point) => (
              <CircleMarker
                key={point.id}
                center={[point.lat, point.lng]}
                radius={Math.min(Math.max(point.intensity / 10, 5), 20)}
                fillColor={typeColors[point.type]}
                color={typeColors[point.type]}
                fillOpacity={0.7}
                weight={2}
              >
                <Popup>
                  <div className="p-2">
                    <p className="font-semibold">{point.country}</p>
                    <p>Requests: {point.requests}</p>
                    <p className="capitalize">Type: {point.type}</p>
                  </div>
                </Popup>
              </CircleMarker>
            ))}
          </MapContainer>
        )}
      </div>

      <div className="mt-4 grid grid-cols-4 gap-4">
        <div className="bg-gray-800/50 rounded-lg p-4">
          <p className="text-sm text-gray-400">Total Locations</p>
          <p className="text-2xl font-bold text-white">{stats.total}</p>
        </div>
        <div className="bg-gray-800/50 rounded-lg p-4">
          <p className="text-sm text-gray-400">Active Threats</p>
          <p className="text-2xl font-bold text-red-400">{stats.blocked + stats.threat}</p>
        </div>
        <div className="bg-gray-800/50 rounded-lg p-4">
          <p className="text-sm text-gray-400">Bot Traffic</p>
          <p className="text-2xl font-bold text-purple-400">{stats.bot}</p>
        </div>
        <div className="bg-gray-800/50 rounded-lg p-4">
          <p className="text-sm text-gray-400">Legitimate</p>
          <p className="text-2xl font-bold text-green-400">{stats.legitimate}</p>
        </div>
      </div>
    </div>
  );
}
