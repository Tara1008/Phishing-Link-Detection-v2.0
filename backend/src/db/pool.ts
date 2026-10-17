import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import path from 'path';

dotenv.config({ path: path.resolve(__dirname, '../../../.env') });
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

export type DbDriver = 'mysql' | 'local';

export interface DbStatus {
  driver: DbDriver;
  connected: boolean;
  info: string;
}

let activeDriver: DbDriver = 'local';
let mysqlPool: mysql.Pool | null = null;

// Determine connection parameters
const mysqlUrl = process.env.MYSQL_URL || process.env.DATABASE_URL;
const host     = process.env.MYSQLHOST || process.env.DB_HOST || 'localhost';
const port     = Number(process.env.MYSQLPORT || process.env.DB_PORT) || 3306;
const user     = process.env.MYSQLUSER || process.env.DB_USER || 'root';
const password = process.env.MYSQLPASSWORD ?? process.env.DB_PASSWORD ?? '';
const database = process.env.MYSQLDATABASE || process.env.DB_NAME || 'phishguard';

export function getDbStatus(): DbStatus {
  return {
    driver: activeDriver,
    connected: true,
    info: activeDriver === 'mysql'
      ? (mysqlUrl ? 'MySQL (Connection URL)' : `MySQL (${host}:${port}/${database})`)
      : 'Embedded persistent store (data/scans.json)',
  };
}

export function isMySQL(): boolean {
  return activeDriver === 'mysql' && mysqlPool !== null;
}

export function getPool(): mysql.Pool {
  if (!mysqlPool) {
    throw new Error('MySQL pool is not initialized');
  }
  return mysqlPool;
}

const TABLE_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS scan_results (
  id              INT UNSIGNED    NOT NULL AUTO_INCREMENT,
  url             TEXT            NOT NULL,
  protocol        VARCHAR(10)     NOT NULL DEFAULT 'http',
  domain          VARCHAR(255)    NOT NULL DEFAULT '',
  subdomain       VARCHAR(255)    NOT NULL DEFAULT '',
  path            TEXT            NOT NULL,
  tld             VARCHAR(30)     NOT NULL DEFAULT '',
  risk_score      TINYINT UNSIGNED NOT NULL DEFAULT 0,
  classification  ENUM('safe', 'suspicious', 'phishing') NOT NULL DEFAULT 'safe',
  confidence      FLOAT           NOT NULL DEFAULT 0,
  security_grade  ENUM('A', 'B', 'C', 'D', 'F') NOT NULL DEFAULT 'A',
  risk_level      VARCHAR(20)     NOT NULL DEFAULT 'Safe',
  features        JSON            NOT NULL,
  reasons         JSON            NOT NULL,
  recommendations TEXT            NOT NULL,
  scan_duration_ms INT UNSIGNED   NOT NULL DEFAULT 0,
  session_id      VARCHAR(64)     NOT NULL DEFAULT '',
  created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  INDEX idx_classification (classification),
  INDEX idx_risk_score (risk_score),
  INDEX idx_created_at (created_at),
  INDEX idx_session_id (session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`;

const VIEW_SCHEMA_SQL = `
CREATE OR REPLACE VIEW scan_stats AS
SELECT
  COUNT(*)                                                AS total_scans,
  SUM(classification = 'safe')                           AS safe_count,
  SUM(classification = 'suspicious')                     AS suspicious_count,
  SUM(classification = 'phishing')                       AS phishing_count,
  ROUND(AVG(risk_score), 1)                              AS avg_risk_score,
  ROUND(SUM(classification = 'phishing') / COUNT(*) * 100, 1) AS phishing_pct,
  ROUND(SUM(classification = 'safe')     / COUNT(*) * 100, 1) AS safe_pct,
  MIN(created_at)                                        AS first_scan,
  MAX(created_at)                                        AS last_scan
FROM scan_results;
`;

// ----------------------------------------------------------------
// Bootstrap — connects to MySQL with short timeout, falls back to local
// ----------------------------------------------------------------
export async function bootstrapDatabase(): Promise<void> {
  const tryMysql = Boolean(
    mysqlUrl ||
    process.env.MYSQLHOST ||
    process.env.DB_HOST ||
    process.env.DB_NAME ||
    process.env.MYSQLDATABASE
  );

  if (!tryMysql) {
    console.log('📦  No MySQL configuration found. Using persistent local store (data/scans.json).');
    activeDriver = 'local';
    return;
  }

  try {
    console.log('🔌  Attempting to connect to MySQL database…');

    // Create pool
    if (mysqlUrl) {
      mysqlPool = mysql.createPool({
        uri: mysqlUrl,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
        enableKeepAlive: true,
        connectTimeout: 5000,
      });
    } else {
      // Connect to server (try creating database if root/local)
      try {
        const adminConn = await mysql.createConnection({
          host,
          port,
          user,
          password,
          connectTimeout: 4000,
        });
        await adminConn.query(`CREATE DATABASE IF NOT EXISTS \`${database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`);
        await adminConn.end();
      } catch (adminErr: any) {
        // Ignored — in hosted cloud DBs, user already connects directly to their pre-created DB
      }

      mysqlPool = mysql.createPool({
        host,
        port,
        user,
        password,
        database,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
        enableKeepAlive: true,
        connectTimeout: 5000,
      });
    }

    // Ping test
    const testConn = await mysqlPool.getConnection();
    await testConn.ping();

    // Create tables & view
    await testConn.query(TABLE_SCHEMA_SQL);
    try {
      await testConn.query(VIEW_SCHEMA_SQL);
    } catch (viewErr) {
      console.warn('⚠️  Could not create scan_stats view (queries will calculate stats directly):', viewErr);
    }
    testConn.release();

    activeDriver = 'mysql';
    console.log('✅  MySQL database connected and tables verified.');
  } catch (err: any) {
    console.warn(`⚠️  MySQL connection failed (${err?.message ?? 'unknown error'}).`);
    console.log('📁  Switching to persistent local storage (data/scans.json) — all scans and history will be saved safely.');
    activeDriver = 'local';
    mysqlPool = null;
  }
}

// ----------------------------------------------------------------
// Health-check helper
// ----------------------------------------------------------------
export async function testConnection(): Promise<boolean> {
  if (activeDriver === 'local') return true;
  if (!mysqlPool) return false;
  try {
    const conn = await mysqlPool.getConnection();
    await conn.ping();
    conn.release();
    return true;
  } catch {
    return false;
  }
}
