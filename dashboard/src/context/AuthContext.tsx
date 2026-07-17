import { createContext, useContext, useState, useCallback, useEffect, ReactNode } from 'react';

export interface User {
  username: string;
  role: 'admin' | 'viewer';
  loginAt: string;
  sessionId: string;
}

interface AuthCtx {
  user: User | null;
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<{ ok: boolean; error?: string }>;
  logout: () => void;
}

// Hard-coded credentials — replace with real API auth on production
const USERS: Record<string, { password: string; role: 'admin' | 'viewer' }> = {
  admin:  { password: 'InfiniteX@2024', role: 'admin'  },
  viewer: { password: 'viewer@123',     role: 'viewer' },
};

const SESSION_KEY = 'infinitex_session';
const AuthContext = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  });

  // Auto-logout after 1 hour of session
  useEffect(() => {
    if (!user) return;
    const loginTime = new Date(user.loginAt).getTime();
    const remaining = loginTime + 3_600_000 - Date.now();
    if (remaining <= 0) { logout(); return; }
    const t = setTimeout(logout, remaining);
    return () => clearTimeout(t);
  }, [user]);

  const login = useCallback(async (username: string, password: string) => {
    const found = USERS[username.toLowerCase()];
    if (!found || found.password !== password) {
      return { ok: false, error: 'Invalid username or password' };
    }
    const newUser: User = {
      username: username.toLowerCase(),
      role: found.role,
      loginAt: new Date().toISOString(),
      sessionId: (typeof crypto !== 'undefined' && crypto.randomUUID) ? crypto.randomUUID() : Math.random().toString(36).slice(2) + Date.now().toString(36),
    };
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(newUser));
    setUser(newUser);
    return { ok: true };
  }, []);

  const logout = useCallback(() => {
    sessionStorage.removeItem(SESSION_KEY);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, isAuthenticated: !!user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be inside AuthProvider');
  return ctx;
}
