import { useCallback } from 'react';
import { useAuth } from '../context/AuthContext';
import { useAuditLog, AuditAction } from '../context/AuditLogContext';

export function useAudit() {
  const { user } = useAuth();
  const { log } = useAuditLog();

  return useCallback((action: AuditAction, detail: string, severity: 'info' | 'warning' | 'critical' = 'info') => {
    log(user?.username ?? 'unknown', action, detail, severity);
  }, [user, log]);
}
