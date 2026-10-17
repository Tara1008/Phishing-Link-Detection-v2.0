import axios from 'axios';
import { useState, useCallback } from 'react';
import type { ScanResult } from '../types';
import toast from 'react-hot-toast';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
});

export interface UseAnalyzeReturn {
  result:    ScanResult | null;
  loading:   boolean;
  error:     string | null;
  analyze:   (url: string) => Promise<ScanResult | null>;
  clearResult: () => void;
}

/** Persistent user / client identifier across browser sessions */
export function getUserId(): string {
  let id = localStorage.getItem('pg-user-id');
  if (!id) {
    id = 'user_' + Math.random().toString(36).slice(2, 10) + '_' + Date.now().toString(36);
    localStorage.setItem('pg-user-id', id);
  }
  return id;
}

/** Retrieve offline local cache of scans */
export function getLocalHistoryCache(): ScanResult[] {
  try {
    const raw = localStorage.getItem('pg-local-history');
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed;
    }
  } catch {
    // Ignore storage parse error
  }
  return [];
}

/** Save a scan to local storage cache */
function saveToLocalCache(scan: ScanResult) {
  try {
    const existing = getLocalHistoryCache();
    const filtered = existing.filter(s => s.id !== scan.id);
    const updated = [scan, ...filtered].slice(0, 150);
    localStorage.setItem('pg-local-history', JSON.stringify(updated));
  } catch {
    // Ignore storage write error
  }
}

export function useAnalyze(): UseAnalyzeReturn {
  const [result,  setResult]  = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState<string | null>(null);

  const analyze = useCallback(async (url: string): Promise<ScanResult | null> => {
    setLoading(true);
    setError(null);

    const userId = getUserId();

    try {
      const { data } = await api.post('/analyze', {
        url: url.trim(),
        session_id: userId,
      });

      if (!data.success) throw new Error(data.error ?? 'Analysis failed');

      const scanData = data.data as ScanResult;
      setResult(scanData);
      saveToLocalCache(scanData);
      return scanData;
    } catch (err: any) {
      const msg = err?.response?.data?.error ?? err?.message ?? 'Analysis failed';
      setError(msg);
      toast.error(msg, { id: 'analyze-error' });
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  const clearResult = useCallback(() => {
    setResult(null);
    setError(null);
  }, []);

  return { result, loading, error, analyze, clearResult };
}

// ── Standalone fetch for history page ─────────────────────────────
export async function fetchHistory(limit = 100, onlyMyScans = false): Promise<ScanResult[]> {
  const userId = getUserId();
  const params: Record<string, any> = { limit };

  if (onlyMyScans) {
    params.session_id = userId;
  }

  try {
    const { data } = await api.get('/history', { params });
    const serverScans = (data?.data ?? []) as ScanResult[];

    // Sync with local cache
    serverScans.forEach(saveToLocalCache);
    return serverScans;
  } catch (err) {
    console.warn('Backend history fetch failed, returning local cache:', err);
    const cached = getLocalHistoryCache();
    if (onlyMyScans) {
      return cached.filter(s => s.session_id === userId);
    }
    return cached;
  }
}

export async function deleteScanById(id: number): Promise<void> {
  try {
    await api.delete(`/history/${id}`);
  } catch {
    // Ignore backend deletion failure if offline
  }

  // Also remove from local cache
  try {
    const existing = getLocalHistoryCache().filter(s => s.id !== id);
    localStorage.setItem('pg-local-history', JSON.stringify(existing));
  } catch {
    // Ignore
  }
}

export async function clearAllHistory(onlyMyScans = false): Promise<void> {
  const userId = getUserId();
  try {
    await api.delete('/history/clear', {
      params: { session_id: onlyMyScans ? userId : undefined },
    });
  } catch {
    // Ignore
  }

  // Also clear local cache
  try {
    if (onlyMyScans) {
      const remaining = getLocalHistoryCache().filter(s => s.session_id !== userId);
      localStorage.setItem('pg-local-history', JSON.stringify(remaining));
    } else {
      localStorage.removeItem('pg-local-history');
    }
  } catch {
    // Ignore
  }
}

export async function fetchStats() {
  try {
    const { data } = await api.get('/stats');
    return data.data;
  } catch {
    return null;
  }
}

export async function fetchHealth() {
  try {
    const { data } = await api.get('/health');
    return data;
  } catch {
    return null;
  }
}
