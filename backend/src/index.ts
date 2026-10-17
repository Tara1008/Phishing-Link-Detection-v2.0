import express from 'express';
import cors    from 'cors';
import helmet  from 'helmet';
import morgan  from 'morgan';
import rateLimit from 'express-rate-limit';
import dotenv  from 'dotenv';
import path    from 'path';
import fs      from 'fs';

import { bootstrapDatabase, testConnection, getDbStatus } from './db/pool';
import analyzeRouter  from './routes/analyze';
import historyRouter  from './routes/history';
import statsRouter    from './routes/stats';

dotenv.config();

const app  = express();
const PORT = Number(process.env.PORT ?? 3001);

// ── Security & Middleware ─────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // Allows flexible SPA asset loading in production
}));

// CORS configuration — supports dev proxy & production single-origin or cross-origin
const allowedOrigin = process.env.FRONTEND_URL;
app.use(cors({
  origin: allowedOrigin ? allowedOrigin : true,
  credentials: true,
}));

app.use(express.json({ limit: '1mb' }));
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));

// Global rate limiter
app.use(rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS ?? 15 * 60 * 1000),
  max:      Number(process.env.RATE_LIMIT_MAX       ?? 300),
  standardHeaders: true,
  legacyHeaders:   false,
  message: { success: false, error: 'Too many requests, please slow down.' },
}));

// ── API Routes ───────────────────────────────────────────────────
app.use('/api/analyze',  analyzeRouter);
app.use('/api/history',  historyRouter);
app.use('/api/stats',    statsRouter);

// Health check with DB status
app.get('/api/health', async (_req, res) => {
  const isConnected = await testConnection();
  const dbInfo = getDbStatus();
  res.json({
    status: 'ok',
    db: {
      driver: dbInfo.driver,
      connected: isConnected,
      info: dbInfo.info,
    },
    uptime_seconds: Math.floor(process.uptime()),
    time: new Date().toISOString(),
  });
});

// ── Serve Frontend SPA in Production ─────────────────────────────
// Check multiple possible locations for frontend dist
const candidateDistPaths = [
  path.resolve(__dirname, '../../frontend/dist'),
  path.resolve(__dirname, '../frontend/dist'),
  path.resolve(process.cwd(), 'frontend/dist'),
  path.resolve(process.cwd(), '../frontend/dist'),
];

const frontendDist = candidateDistPaths.find(p => fs.existsSync(p));

if (frontendDist) {
  console.log(`📦  Serving frontend from ${frontendDist}`);
  app.use(express.static(frontendDist));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) return next();
    res.sendFile(path.join(frontendDist, 'index.html'));
  });
} else {
  // 404 handler for API routes or when frontend dist is not built yet
  app.use((req, res, next) => {
    if (req.path.startsWith('/api')) {
      return res.status(404).json({ success: false, error: 'API route not found' });
    }
    res.status(404).send('PhishGuard API is running. (Build frontend to enable web UI)');
  });
}

// Global error handler
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('Unhandled server error:', err);
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// ── Bootstrap & Start ────────────────────────────────────────────
async function main() {
  try {
    await bootstrapDatabase();
    const dbStatus = getDbStatus();

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀  PhishGuard running on port ${PORT}`);
      console.log(`💾  Database mode: [${dbStatus.driver.toUpperCase()}] - ${dbStatus.info}`);
      console.log(`📊  Health check: http://localhost:${PORT}/api/health`);
    });
  } catch (err) {
    console.error('Fatal startup error:', err);
    process.exit(1);
  }
}

main();
