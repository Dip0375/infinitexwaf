import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { TimeRangeProvider } from './context/TimeRangeContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import { AuditLogProvider } from './context/AuditLogContext';
import { LoginPage } from './pages/LoginPage';
import { Dashboard } from './pages/Dashboard';
import { TrafficAnalysis } from './pages/TrafficAnalysis';
import { TrafficLogsPage } from './pages/TrafficLogsPage';
import { GeoMapPage } from './pages/GeoMapPage';
import { ThreatsPage } from './pages/ThreatsPage';
import { AlertsPage } from './pages/AlertsPage';
import { SettingsPage } from './pages/SettingsPage';
import { ThreatIntel } from './pages/ThreatIntel';
import { RulesPage } from './pages/RulesPage';
import { ReportsPage } from './pages/ReportsPage';
import { AuditLogPage } from './pages/AuditLogPage';
import { IntegrationsPage } from './pages/IntegrationsPage';
import { Toaster } from 'react-hot-toast';

function ProtectedApp() {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) return <LoginPage />;

  return (
    <TimeRangeProvider>
      <Layout>
        <Routes>
          <Route path="/"         element={<Dashboard />} />
          <Route path="/traffic"  element={<TrafficAnalysis />} />
          <Route path="/logs"     element={<TrafficLogsPage />} />
          <Route path="/geo"      element={<GeoMapPage />} />
          <Route path="/threats"  element={<ThreatsPage />} />
          <Route path="/rules"    element={<RulesPage />} />
          <Route path="/integrations" element={<IntegrationsPage />} />
          <Route path="/intel"    element={<ThreatIntel />} />
          <Route path="/alerts"   element={<AlertsPage />} />
          <Route path="/reports"  element={<ReportsPage />} />
          <Route path="/audit"    element={<AuditLogPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*"         element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </TimeRangeProvider>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AuditLogProvider>
        <AuthProvider>
          <ProtectedApp />
        </AuthProvider>
      </AuditLogProvider>
      <Toaster
        position="top-right"
        toastOptions={{
          style: { background: '#1f2937', color: '#fff', border: '1px solid #374151' },
        }}
      />
    </BrowserRouter>
  );
}

export default App;
