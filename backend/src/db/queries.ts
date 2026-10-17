import { getPool, isMySQL } from './pool';
import type { ScanResult, ScanStats } from '../types';
import {
  localInsertScan,
  localGetHistory,
  localGetScanById,
  localDeleteScan,
  localClearHistory,
  localGetStats,
  localGetRecentScans,
} from './localStore';

// ----------------------------------------------------------------
// Insert a new scan result and return the inserted row's id
// ----------------------------------------------------------------
export async function insertScan(result: Omit<ScanResult, 'id' | 'created_at'>): Promise<number> {
  if (!isMySQL()) {
    return localInsertScan(result);
  }

  try {
    const pool = getPool();
    const [res] = await pool.execute(
      `INSERT INTO scan_results
        (url, protocol, domain, subdomain, path, tld,
         risk_score, classification, confidence, security_grade,
         risk_level, features, reasons, recommendations,
         scan_duration_ms, session_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        result.url,
        result.protocol,
        result.domain,
        result.subdomain,
        result.path,
        result.tld,
        result.risk_score,
        result.classification,
        result.confidence,
        result.security_grade,
        result.risk_level,
        JSON.stringify(result.features),
        JSON.stringify(result.reasons),
        result.recommendations,
        result.scan_duration_ms,
        result.session_id,
      ]
    ) as any;

    return (res as any).insertId as number;
  } catch (err) {
    console.warn('MySQL insert failed, saving to local store:', err);
    return localInsertScan(result);
  }
}

// ----------------------------------------------------------------
// Retrieve paginated history (newest first)
// ----------------------------------------------------------------
export async function getHistory(
  limit = 50,
  offset = 0,
  sessionId?: string
): Promise<ScanResult[]> {
  if (!isMySQL()) {
    return localGetHistory(limit, offset, sessionId);
  }

  try {
    const pool = getPool();
    const params: (string | number)[] = [];
    let where = '';

    if (sessionId && sessionId.trim() !== '') {
      where = 'WHERE session_id = ?';
      params.push(sessionId);
    }

    params.push(limit, offset);

    const [rows] = await pool.execute(
      `SELECT * FROM scan_results ${where}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      params
    ) as any;

    return (rows as any[]).map(parseRow);
  } catch (err) {
    console.warn('MySQL history fetch failed, reading from local store:', err);
    return localGetHistory(limit, offset, sessionId);
  }
}

// ----------------------------------------------------------------
// Get a single scan by id
// ----------------------------------------------------------------
export async function getScanById(id: number): Promise<ScanResult | null> {
  if (!isMySQL()) {
    return localGetScanById(id);
  }

  try {
    const pool = getPool();
    const [rows] = await pool.execute(
      'SELECT * FROM scan_results WHERE id = ? LIMIT 1',
      [id]
    ) as any;

    const arr = rows as any[];
    return arr.length ? parseRow(arr[0]) : null;
  } catch (err) {
    console.warn('MySQL getById failed, checking local store:', err);
    return localGetScanById(id);
  }
}

// ----------------------------------------------------------------
// Delete a single scan
// ----------------------------------------------------------------
export async function deleteScan(id: number): Promise<boolean> {
  if (!isMySQL()) {
    return localDeleteScan(id);
  }

  try {
    const pool = getPool();
    const [res] = await pool.execute(
      'DELETE FROM scan_results WHERE id = ?',
      [id]
    ) as any;
    const ok = (res as any).affectedRows > 0;
    localDeleteScan(id); // keep in sync
    return ok;
  } catch (err) {
    console.warn('MySQL delete failed, deleting from local store:', err);
    return localDeleteScan(id);
  }
}

// ----------------------------------------------------------------
// Clear all history (optionally scoped to session)
// ----------------------------------------------------------------
export async function clearHistory(sessionId?: string): Promise<number> {
  if (!isMySQL()) {
    return localClearHistory(sessionId);
  }

  try {
    const pool = getPool();
    let affected = 0;
    if (sessionId && sessionId.trim() !== '') {
      const [res] = await pool.execute(
        'DELETE FROM scan_results WHERE session_id = ?',
        [sessionId]
      ) as any;
      affected = (res as any).affectedRows;
    } else {
      const [res] = await pool.execute('DELETE FROM scan_results') as any;
      affected = (res as any).affectedRows;
    }
    localClearHistory(sessionId);
    return affected;
  } catch (err) {
    console.warn('MySQL clear failed, clearing local store:', err);
    return localClearHistory(sessionId);
  }
}

// ----------------------------------------------------------------
// Aggregate stats
// ----------------------------------------------------------------
export async function getStats(): Promise<ScanStats> {
  if (!isMySQL()) {
    return localGetStats();
  }

  try {
    const pool = getPool();
    const [rows] = await pool.execute(
      `SELECT
        COUNT(*) AS total_scans,
        SUM(classification = 'safe') AS safe_count,
        SUM(classification = 'suspicious') AS suspicious_count,
        SUM(classification = 'phishing') AS phishing_count,
        ROUND(AVG(risk_score), 1) AS avg_risk_score,
        ROUND(SUM(classification = 'phishing') / NULLIF(COUNT(*), 0) * 100, 1) AS phishing_pct,
        ROUND(SUM(classification = 'safe') / NULLIF(COUNT(*), 0) * 100, 1) AS safe_pct,
        MIN(created_at) AS first_scan,
        MAX(created_at) AS last_scan
      FROM scan_results`
    ) as any;

    const row = (rows as any[])[0] ?? {};
    return {
      total_scans:      Number(row.total_scans     ?? 0),
      safe_count:       Number(row.safe_count      ?? 0),
      suspicious_count: Number(row.suspicious_count ?? 0),
      phishing_count:   Number(row.phishing_count  ?? 0),
      avg_risk_score:   Number(row.avg_risk_score  ?? 0),
      phishing_pct:     Number(row.phishing_pct    ?? 0),
      safe_pct:         Number(row.safe_pct        ?? 0),
      first_scan:       row.first_scan ? String(row.first_scan) : null,
      last_scan:        row.last_scan  ? String(row.last_scan)  : null,
    };
  } catch (err) {
    console.warn('MySQL getStats failed, computing from local store:', err);
    return localGetStats();
  }
}

// ----------------------------------------------------------------
// Recent scans
// ----------------------------------------------------------------
export async function getRecentScans(limit = 30): Promise<ScanResult[]> {
  if (!isMySQL()) {
    return localGetRecentScans(limit);
  }

  try {
    const pool = getPool();
    const [rows] = await pool.execute(
      'SELECT * FROM scan_results ORDER BY created_at DESC LIMIT ?',
      [limit]
    ) as any;
    return (rows as any[]).map(parseRow);
  } catch (err) {
    console.warn('MySQL recent scans failed, reading from local store:', err);
    return localGetRecentScans(limit);
  }
}

// ----------------------------------------------------------------
// Parse DB row — JSON columns come back as strings in some drivers
// ----------------------------------------------------------------
function parseRow(row: any): ScanResult {
  return {
    ...row,
    features: typeof row.features === 'string' ? JSON.parse(row.features) : row.features,
    reasons:  typeof row.reasons  === 'string' ? JSON.parse(row.reasons)  : row.reasons,
    created_at: row.created_at instanceof Date
      ? row.created_at.toISOString()
      : String(row.created_at),
  };
}
