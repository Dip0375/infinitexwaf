import { useState, useEffect, useCallback } from 'react';
import {
  Shield, RefreshCw, Search, CheckCircle, XCircle,
  AlertTriangle, Clock, Database, Wifi, WifiOff, Eye,
} from 'lucide-react';
import toast from 'react-hot-toast';

interface FeedInfo {
  id: string;
  name: string;
  description: string;
  category: string;
  ipCount: number;
  status: 'ok' | 'error' | 'pending' | 'disabled';
  lastUpdated?: string;
  error?: string;
  enabled: boolean;
  updateIntervalHours: number;
}

interface Summary {