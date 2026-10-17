import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Trash2, Search, RefreshCcw, History, ExternalLink, Download, Database, ShieldCheck } from 'lucide-react';
import { fetchHistory, deleteScanById, clearAllHistory, fetchHealth } from '../hooks/useAnalyze';
import type { ScanResult } from '../types';
import { getRiskColor } from '../types';
import toast from 'react-hot-toast';
import { useNavigate } from 'react-router-dom';

const classificationBadge: Record<string, string> = {
  safe:       'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
  suspicious: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
  phishing:   'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
};

export default function HistoryPage() {
  const [scans,       setScans]       = useState<ScanResult[]>([]);
  const [loading,     setLoading]     = useState(true);
  const [query,       setQuery]       = useState('');
  const [onlyMyScans, setOnlyMyScans] = useState(false);
  const [dbStatus,    setDbStatus]    = useState<{ driver: string; connected: boolean; info: string } | null>(null);
  const [historySource, setHistorySource] = useState<'server' | 'browser-cache'>('server');
  const navigate = useNavigate();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [data, health] = await Promise.all([
        fetchHistory(100, onlyMyScans),
        fetchHealth(),
      ]);
      setScans(data.scans);
      setHistorySource(data.source);
      setDbStatus(health?.db ?? null);
    } catch {
      toast.error('Failed to load history');
    } finally {
      setLoading(false);
    }
  }, [onlyMyScans]);

  useEffect(() => {
    load();
  }, [load]);

  const del = async (id: number) => {
    try {
      await deleteScanById(id, historySource === 'browser-cache');
      setScans(s => s.filter(r => r.id !== id));
      toast.success(historySource === 'browser-cache'
        ? 'Removed from this browser cache only'
        : 'Scan deleted');
    } catch {
      toast.error('Delete failed');
    }
  };

  const clearAll = async () => {
    if (!confirm(onlyMyScans ? 'Clear all your search history?' : 'Clear all scan history?')) return;
    try {
      await clearAllHistory(onlyMyScans, historySource === 'browser-cache');
      setScans([]);
      toast.success(historySource === 'browser-cache'
        ? 'Browser cache cleared; server history is unchanged'
        : 'History cleared');
    } catch {
      toast.error('Clear failed');
    }
  };

  const exportAllCSV = () => {
    if (scans.length === 0) return;
    const headers = ['ID', 'URL', 'Classification', 'Risk Score', 'Grade', 'Date'];
    const rows = scans.map(s => [
      s.id ?? '',
      `"${s.url.replace(/"/g, '""')}"`,
      s.classification,
      s.risk_score,
      s.security_grade,
      s.created_at ?? '',
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `phishguard-history-${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast.success('History exported as CSV');
  };

  const filtered = scans.filter(s =>
    s.url.toLowerCase().includes(query.toLowerCase()) ||
    s.classification.includes(query.toLowerCase())
  );

  return (
    <div className="max-w-6xl mx-auto px-4 py-12">
      {/* Header */}
      <div className="flex items-center justify-between mb-8 flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-black text-slate-900 dark:text-white flex items-center gap-2">
            <History className="w-6 h-6 text-indigo-500" /> Scan History
          </h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1 flex items-center gap-2 flex-wrap">
            <span>Previous URL inspections and threat reports</span>
            {(dbStatus || historySource === 'browser-cache') && (
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-indigo-50 text-indigo-700 dark:bg-indigo-950/40 dark:text-indigo-300 border border-indigo-200/60 dark:border-indigo-800/40">
                <Database className="w-3 h-3 text-indigo-500" />
                {historySource === 'browser-cache'
                  ? 'Browser cache (API unavailable)'
                  : dbStatus?.driver === 'mysql'
                    ? 'MySQL database'
                    : dbStatus?.driver === 'local'
                      ? 'Local JSON fallback'
                      : 'Server history'}
              </span>
            )}
          </p>
          {(historySource === 'browser-cache' || dbStatus?.driver === 'local') && (
            <p className="text-xs text-amber-600 dark:text-amber-400 mt-2 max-w-2xl">
              {historySource === 'browser-cache'
                ? 'Showing this browser’s cached scans because the history API is unavailable. Delete and clear actions affect only this browser cache.'
                : 'The backend is using local JSON storage. On serverless hosts such as Vercel, local files may not persist across instances or deployments; configure MySQL for durable shared history.'}
            </p>
          )}
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Filter Toggle */}
          <div className="flex bg-slate-100 dark:bg-slate-800 p-1 rounded-xl border border-slate-200 dark:border-slate-700 text-xs font-semibold">
            <button
              onClick={() => setOnlyMyScans(false)}
              className={`px-3 py-1.5 rounded-lg transition-all ${
                !onlyMyScans
                  ? 'bg-white dark:bg-slate-700 text-indigo-600 dark:text-white shadow-sm'
                  : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
              }`}
            >
              All Scans
            </button>
            <button
              onClick={() => setOnlyMyScans(true)}
              className={`px-3 py-1.5 rounded-lg transition-all ${
                onlyMyScans
                  ? 'bg-white dark:bg-slate-700 text-indigo-600 dark:text-white shadow-sm'
                  : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
              }`}
            >
              My Scans
            </button>
          </div>

          <button
            onClick={load}
            className="p-2.5 rounded-xl border border-slate-200 dark:border-slate-700 text-slate-500 hover:text-indigo-500 hover:border-indigo-300 transition-all"
            title="Refresh"
          >
            <RefreshCcw className="w-4 h-4" />
          </button>

          {scans.length > 0 && (
            <>
              <button
                onClick={exportAllCSV}
                className="flex items-center gap-2 px-3.5 py-2.5 rounded-xl text-xs font-semibold text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 hover:bg-slate-50 dark:hover:bg-slate-800 transition-all"
                title="Export CSV"
              >
                <Download className="w-3.5 h-3.5" /> CSV
              </button>
              <button
                onClick={clearAll}
                className="flex items-center gap-2 px-3.5 py-2.5 rounded-xl text-xs font-semibold text-red-600 dark:text-red-400 border border-red-200 dark:border-red-900 hover:bg-red-50 dark:hover:bg-red-950/20 transition-all"
              >
                <Trash2 className="w-3.5 h-3.5" /> Clear
              </button>
            </>
          )}
        </div>
      </div>

      {/* Search Input */}
      <div className="relative mb-6">
        <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
        <input
          type="text"
          placeholder="Search by URL or classification (e.g. google.com, phishing, safe)…"
          value={query}
          onChange={e => setQuery(e.target.value)}
          className="w-full pl-10 pr-4 py-3 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl text-sm text-slate-800 dark:text-slate-200 placeholder:text-slate-400 outline-none focus:border-indigo-400 transition-colors"
        />
      </div>

      {/* Metrics Summary */}
      {scans.length > 0 && (
        <div className="grid grid-cols-3 gap-4 mb-6">
          {[
            { label: 'Loaded Records', value: scans.length, color: '#6366f1' },
            { label: 'Phishing Results', value: scans.filter(s => s.classification === 'phishing').length, color: '#ef4444' },
            { label: 'Safe Results', value: scans.filter(s => s.classification === 'safe').length, color: '#22c55e' },
          ].map(s => (
            <div key={s.label} className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-700 p-4 text-center shadow-sm">
              <div className="text-2xl font-black" style={{ color: s.color }}>{s.value}</div>
              <div className="text-xs text-slate-400 mt-0.5">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Table & Empty States */}
      {loading ? (
        <div className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="skeleton h-16 rounded-xl" />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-20 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-8 shadow-card">
          <History className="w-14 h-14 text-slate-300 dark:text-slate-700 mx-auto mb-4" />
          <h3 className="text-base font-semibold text-slate-800 dark:text-slate-200 mb-1">
            {query ? 'No matching scan results found' : 'No scans recorded yet'}
          </h3>
          <p className="text-slate-400 dark:text-slate-500 text-sm max-w-sm mx-auto mb-6">
            {query
              ? 'Try modifying your search keywords or clear the filter.'
              : 'Scan your first URL to view detailed risk analysis and vulnerability reports here.'}
          </p>
          <button
            onClick={() => navigate('/scan')}
            className="inline-flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-indigo-500 to-purple-600 text-white text-sm font-semibold rounded-xl hover:shadow-lg transition-all"
          >
            <ShieldCheck className="w-4 h-4" /> Scan a URL Now
          </button>
        </div>
      ) : (
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-700 overflow-hidden shadow-card">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-800/50">
                  {['URL', 'Classification', 'Risk', 'Grade', 'Date', 'Actions'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {filtered.map((scan, i) => (
                  <motion.tr
                    key={scan.id ?? `${scan.url}-${i}`}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: Math.min(i * 0.02, 0.3) }}
                    className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
                  >
                    <td className="px-4 py-3 max-w-xs">
                      <span className="font-mono text-xs text-slate-700 dark:text-slate-300 truncate block" title={scan.url}>
                        {scan.url}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2.5 py-1 rounded-full text-xs font-semibold capitalize ${classificationBadge[scan.classification] || ''}`}>
                        {scan.classification}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-bold tabular-nums" style={{ color: getRiskColor(scan.risk_score) }}>
                        {scan.risk_score}
                      </span>
                      <span className="text-slate-400 text-xs">/100</span>
                    </td>
                    <td className="px-4 py-3 font-bold text-slate-800 dark:text-slate-200">
                      {scan.security_grade}
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-xs whitespace-nowrap">
                      {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'Just now'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => {
                            navigator.clipboard.writeText(scan.url);
                            toast.success('URL copied');
                          }}
                          className="p-1.5 rounded-lg text-slate-400 hover:text-indigo-500 hover:bg-indigo-50 dark:hover:bg-indigo-950/20 transition-colors"
                          title="Copy URL"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => scan.id !== undefined && del(scan.id)}
                          className="p-1.5 rounded-lg text-slate-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-950/20 transition-colors"
                          title="Delete"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
