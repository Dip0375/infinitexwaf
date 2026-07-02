import { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, Globe, Shield, AlertTriangle, Settings,
  Menu, X, Activity, Bell, ChevronRight, Zap, Crosshair,
  SlidersHorizontal, FileBarChart, ClipboardList, LogOut,
  User, ScrollText, Link2,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useAuditLog } from '../context/AuditLogContext';

const menuItems = [
  { path: '/',            icon: LayoutDashboard,   label: 'Dashboard',       description: 'Overview & Analytics'          },
  { path: '/traffic',     icon: Activity,          label: 'Traffic Analysis', description: 'Real-time traffic monitoring'  },
  { path: '/logs',        icon: ScrollText,        label: 'Traffic Logs',    description: 'Live WAF request log'           },
  { path: '/geo',         icon: Globe,             label: 'Global Map',      description: 'Geographic threat visualization' },
  { path: '/threats',     icon: Shield,            label: 'Threats',         description: 'Blocked attacks & top 10 lists' },
  { path: '/rules',       icon: SlidersHorizontal, label: 'WAF Rules',       description: 'Enable, disable & custom rules' },
  { path: '/integrations',icon: Link2,             label: 'Integrations',    description: 'ALB, CDN, servers & on-prem'    },
  { path: '/intel',       icon: Crosshair,         label: 'Threat Intel',    description: 'Attack categories & live feed'  },
  { path: '/alerts',      icon: AlertTriangle,     label: 'Alerts',          description: 'Notifications & triggers'       },
  { path: '/reports',     icon: FileBarChart,      label: 'Reports',         description: 'Generate PDF security reports'  },
  { path: '/audit',       icon: ClipboardList,     label: 'Audit Log',       description: 'Console activity log (15m)'     },
  { path: '/settings',    icon: Settings,          label: 'Settings',        description: 'Logging, storage & config'      },
];

export function Layout({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const location = useLocation();
  const { user, logout } = useAuth();
  const { log, entries } = useAuditLog();

  function handleLogout() {
    if (user) log(user.username, 'LOGOUT', 'User signed out', 'info');
    logout();
  }

  const unreadCritical = entries.filter((e) => e.severity === 'critical').length;

  return (
    <div className="min-h-screen bg-gray-950 text-white">
      {/* Sidebar */}
      <aside className={`fixed top-0 left-0 z-40 h-screen transition-transform duration-300 ${
        sidebarOpen ? 'translate-x-0' : '-translate-x-full'
      } bg-gray-900 border-r border-gray-800 w-72`}>
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="flex items-center gap-3 px-6 py-5 border-b border-gray-800">
            <div className="w-10 h-10 bg-gradient-to-br from-cyan-400 to-blue-600 rounded-xl flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Zap className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">InfiniteX</h1>
              <p className="text-xs text-gray-500">WAF Protection Platform</p>
            </div>
          </div>

          {/* Nav */}
          <nav className="flex-1 px-4 py-4 space-y-0.5 overflow-y-auto">
            {menuItems.map((item) => {
              const isActive = location.pathname === item.path;
              const Icon = item.icon;
              return (
                <Link key={item.path} to={item.path}
                  className={`flex items-center gap-3 px-4 py-2.5 rounded-xl transition-all duration-200 group ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/20 border border-cyan-500/30'
                      : 'hover:bg-gray-800/50'
                  }`}
                >
                  <div className={`p-1.5 rounded-lg transition-colors ${isActive ? 'bg-cyan-500/20 text-cyan-400' : 'text-gray-400 group-hover:text-gray-300'}`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className={`text-sm font-medium ${isActive ? 'text-white' : 'text-gray-300'}`}>{item.label}</p>
                    <p className="text-xs text-gray-600 truncate">{item.description}</p>
                  </div>
                  {isActive && <ChevronRight className="w-3.5 h-3.5 text-cyan-400 shrink-0" />}
                </Link>
              );
            })}
          </nav>

          {/* User card */}
          <div className="p-4 border-t border-gray-800 space-y-2">
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl bg-gray-800/50">
              <div className="w-8 h-8 bg-cyan-500/20 rounded-full flex items-center justify-center shrink-0">
                <User className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-white truncate">{user?.username}</p>
                <p className="text-xs text-gray-500 capitalize">{user?.role}</p>
              </div>
              <button onClick={handleLogout} title="Sign out"
                className="p-1.5 hover:bg-red-500/10 rounded-lg text-gray-500 hover:text-red-400 transition-colors">
                <LogOut className="w-4 h-4" />
              </button>
            </div>
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-green-500/10">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
              <p className="text-xs text-green-400">System Active · All rules enforced</p>
            </div>
          </div>
        </div>
      </aside>

      {/* Main */}
      <div className={`transition-all duration-300 ${sidebarOpen ? 'ml-72' : 'ml-0'}`}>
        {/* Header */}
        <header className="sticky top-0 z-30 bg-gray-950/80 backdrop-blur-xl border-b border-gray-800">
          <div className="flex items-center justify-between px-6 py-3.5">
            <button onClick={() => setSidebarOpen(!sidebarOpen)}
              className="p-2 rounded-lg hover:bg-gray-800 transition-colors" aria-label="Toggle sidebar">
              {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>

            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2 text-sm text-gray-400">
                <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                Live · {new Date().toLocaleTimeString()}
              </div>

              {/* Audit bell */}
              <Link to="/audit" className="relative p-2 rounded-lg hover:bg-gray-800 transition-colors text-gray-400 hover:text-white" aria-label="Audit log">
                <Bell className="w-5 h-5" />
                {unreadCritical > 0 && (
                  <span className="absolute top-1 right-1 w-4 h-4 bg-red-500 rounded-full text-white text-[9px] flex items-center justify-center font-bold">
                    {unreadCritical > 9 ? '9+' : unreadCritical}
                  </span>
                )}
              </Link>
            </div>
          </div>
        </header>

        <main className="p-6">{children}</main>
      </div>
    </div>
  );
}
