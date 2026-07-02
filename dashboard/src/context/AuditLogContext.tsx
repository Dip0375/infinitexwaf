import { createContext, useContext, useState, useCallback, useEffect, useRef, ReactNode } from 'react';

export type AuditAction =
  | 'LOGIN' | 'LOGOUT'
  | 'RULE_ENABLED' | 'RULE_DISABLED' | 'RULE_CREATED' | 'RULE_UPDATED' | 'RULE_DELETED'
  | 'ALERT_CREATED' | 'ALERT_DELETED' | 'ALERT_TESTED'
  | 'SETTINGS_UPDATED' | 'EXPORT_TRIGGERED'
  | 'REPORT_GENERATED' | 'PAGE_VIEWED';

export interface AuditEntry {
  id: string;
  timestamp: string;
  user: string;
  action: AuditAction;
  detail: string;
  ip?: string;
  severity: 'info' | 'warning' | 'critical';
  expiresAt: string; // 15 min from creation
}

interface AuditCtx {
  entries: AuditEntry[];
  log: (user: string, action: AuditAction, detail: string, severity?: AuditEntry['severity']) => void;
  clear: () => void;
}

const FLUSH_MS = 15 * 60 * 1000; // 15 minutes
const AuditContext = createContext<AuditCtx | null>(null);

export function AuditLogProvider({ children }: { children: ReactNode }) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const timerRef = useRef<NodeJS.Timeout | null>(null);

  // Prune expired entries every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      const now = Date.now();
      setEntries((prev) => prev.filter((e) => new Date(e.expiresAt).getTime() > now));
    }, 30_000);
    return () => clearInterval(interval);
  }, []);

  // Auto-flush ALL entries every 15 minutes
  useEffect(() => {
    timerRef.current = setInterval(() => {
      setEntries([]);
    }, FLUSH_MS);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, []);

  const log = useCallback((
    user: string,
    action: AuditAction,
    detail: string,
    severity: AuditEntry['severity'] = 'info',
  ) => {
    const now = new Date();
    const entry: AuditEntry = {
      id: `audit-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: now.toISOString(),
      user,
      action,
      detail,
      severity,
      expiresAt: new Date(now.getTime() + FLUSH_MS).toISOString(),
    };
    setEntries((prev) => [entry, ...prev].slice(0, 500));
  }, []);

  const clear = useCallback(() => setEntries([]), []);

  return (
    <AuditContext.Provider value={{ entries, log, clear }}>
      {children}
    </AuditContext.Provider>
  );
}

export function useAuditLog() {
  const ctx = useContext(AuditContext);
  if (!ctx) throw new Error('useAuditLog must be inside AuditLogProvider');
  return ctx;
}
