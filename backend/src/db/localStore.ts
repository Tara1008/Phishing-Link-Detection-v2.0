import fs from 'fs';
import path from 'path';
import type { ScanResult, ScanStats } from '../types';

const DATA_DIR = path.resolve(__dirname, '../../data');
const DATA_FILE = path.join(DATA_DIR, 'scans.json');
const LEGACY_DATA_FILE = path.resolve(__dirname, '../../../data/scans.json');

let inMemoryScans: ScanResult[] = [];
let isLoaded = false;

function ensureDataLoaded() {
  if (isLoaded) return;
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    const sourceFile = fs.existsSync(DATA_FILE)
      ? DATA_FILE
      : fs.existsSync(LEGACY_DATA_FILE)
        ? LEGACY_DATA_FILE
        : null;

    if (sourceFile) {
      const raw = fs.readFileSync(sourceFile, 'utf8');
      inMemoryScans = JSON.parse(raw);
      if (!Array.isArray(inMemoryScans)) {
        inMemoryScans = [];
      }
      if (sourceFile !== DATA_FILE) persistToFile();
    } else {
      inMemoryScans = [];
      fs.writeFileSync(DATA_FILE, JSON.stringify([], null, 2), 'utf8');
    }
  } catch (err) {
    console.error('Error loading local scan store:', err);
    inMemoryScans = [];
  }
  isLoaded = true;
}

function persistToFile() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    fs.writeFileSync(DATA_FILE, JSON.stringify(inMemoryScans, null, 2), 'utf8');
  } catch (err) {
    console.error('Error saving local scan store:', err);
  }
}

export async function localInsertScan(result: Omit<ScanResult, 'id' | 'created_at'>): Promise<number> {
  ensureDataLoaded();
  const nextId = inMemoryScans.length > 0
    ? Math.max(...inMemoryScans.map(s => s.id ?? 0)) + 1
    : 1;

  const newScan: ScanResult = {
    ...result,
    id: nextId,
    created_at: new Date().toISOString(),
  };

  inMemoryScans.unshift(newScan);
  persistToFile();
  return nextId;
}

export async function localGetHistory(
  limit = 50,
  offset = 0,
  sessionId?: string
): Promise<ScanResult[]> {
  ensureDataLoaded();
  let list = inMemoryScans;
  if (sessionId && sessionId.trim() !== '') {
    list = list.filter(s => s.session_id === sessionId);
  }
  return list.slice(offset, offset + limit);
}

export async function localGetScanById(id: number): Promise<ScanResult | null> {
  ensureDataLoaded();
  const scan = inMemoryScans.find(s => s.id === id);
  return scan ?? null;
}

export async function localDeleteScan(id: number): Promise<boolean> {
  ensureDataLoaded();
  const initialLen = inMemoryScans.length;
  inMemoryScans = inMemoryScans.filter(s => s.id !== id);
  const deleted = inMemoryScans.length < initialLen;
  if (deleted) persistToFile();
  return deleted;
}

export async function localClearHistory(sessionId?: string): Promise<number> {
  ensureDataLoaded();
  if (sessionId && sessionId.trim() !== '') {
    const before = inMemoryScans.length;
    inMemoryScans = inMemoryScans.filter(s => s.session_id !== sessionId);
    const removed = before - inMemoryScans.length;
    if (removed > 0) persistToFile();
    return removed;
  }
  const count = inMemoryScans.length;
  inMemoryScans = [];
  persistToFile();
  return count;
}

export async function localGetStats(): Promise<ScanStats> {
  ensureDataLoaded();
  const total = inMemoryScans.length;
  if (total === 0) {
    return {
      total_scans: 0,
      safe_count: 0,
      suspicious_count: 0,
      phishing_count: 0,
      avg_risk_score: 0,
      phishing_pct: 0,
      safe_pct: 0,
      first_scan: null,
      last_scan: null,
    };
  }

  const safe = inMemoryScans.filter(s => s.classification === 'safe').length;
  const suspicious = inMemoryScans.filter(s => s.classification === 'suspicious').length;
  const phishing = inMemoryScans.filter(s => s.classification === 'phishing').length;
  const sumScore = inMemoryScans.reduce((acc, s) => acc + (s.risk_score || 0), 0);
  const avg = Math.round((sumScore / total) * 10) / 10;
  const phishingPct = Math.round((phishing / total) * 1000) / 10;
  const safePct = Math.round((safe / total) * 1000) / 10;

  return {
    total_scans: total,
    safe_count: safe,
    suspicious_count: suspicious,
    phishing_count: phishing,
    avg_risk_score: avg,
    phishing_pct: phishingPct,
    safe_pct: safePct,
    first_scan: inMemoryScans[inMemoryScans.length - 1]?.created_at ?? null,
    last_scan: inMemoryScans[0]?.created_at ?? null,
  };
}

export async function localGetRecentScans(limit = 30): Promise<ScanResult[]> {
  ensureDataLoaded();
  return inMemoryScans.slice(0, limit);
}
