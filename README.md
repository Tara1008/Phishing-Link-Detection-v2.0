# 🛡️ PhishGuard AI

> A production-quality phishing URL detection web app with AI-ready architecture, flexible MySQL & embedded storage, and a cybersecurity dashboard.

---

## 🚀 Railway Deployment (One-Click Git Push Ready)

This repository is pre-configured for direct deployment on **[Railway](https://railway.app)**:

1. **Push this repository to GitHub**:
   ```bash
   git init
   git add .
   git commit -m "Initial commit for Railway deployment"
   git remote add origin https://github.com/<your-username>/<your-repo-name>.git
   git push -u origin main
   ```
2. **Deploy on Railway**:
   - Go to [Railway Dashboard](https://railway.app/dashboard)
   - Click **New Project** → **Deploy from GitHub repo**
   - Select your repository
3. **Database (Zero-Config or MySQL)**:
   - **Zero Config**: If you do not attach a database, PhishGuard automatically saves all scans and search history to a persistent file store (`data/scans.json`).
   - **Railway MySQL (Optional)**: Click **+ New** → **Database** → **MySQL**. Railway automatically provides `MYSQL_URL` or `DATABASE_URL`, and PhishGuard will connect immediately without needing manual setup.

---

## ▲ Vercel Deployment

The repository is configured as a Vercel project with two services:

- `frontend` builds the Vite app and receives public requests on `/*`.
- `backend` runs the Express API and receives public requests on `/api/*`.

The frontend uses same-origin `/api` requests, so the Vercel rewrites route API traffic to the backend. There are no private service-to-service calls, so no service bindings are required.

For durable scan history, provision an external MySQL database and add `MYSQL_URL` (or `DATABASE_URL`) as an environment variable in the Vercel project settings. Apply it to each environment you deploy, such as Production and Preview. Do not commit database credentials. After deployment, check `/api/health` and confirm that `db.driver` is `mysql`; without a working MySQL connection, the backend falls back to local JSON storage, which is not durable across Vercel function instances or deployments.

---

## 💻 Local Development

### Prerequisites
- Node.js ≥ 18
- npm

### 1. Quick Start (Both Frontend & Backend)
From the project root:
```bash
# Install all dependencies across root, backend, and frontend
npm install

# Run backend (API on port 3001)
npm run dev:backend

# In a second terminal, run frontend (Vite UI on port 5173)
npm run dev:frontend
```

### 2. Production Build Locally
```bash
# Builds frontend to frontend/dist and backend to backend/dist
npm run build

# Start the unified production server
npm start
```
The unified production server serves both the React UI and API routes on `http://localhost:3001`.

---

## 🗄️ Flexible Database Architecture

PhishGuard AI features a hybrid, resilient database layer:

- **MySQL Connection**: When `MYSQL_URL`, `DATABASE_URL`, or `DB_HOST`/`DB_USER` credentials are provided, PhishGuard connects to MySQL, automatically verifies tables, and indexes scans.
- **Embedded Local Fallback**: If MySQL is unavailable or offline, PhishGuard automatically falls back to an embedded persistent JSON store (`backend/data/scans.json`). The store location is consistent across development and production runs; existing root-level `data/scans.json` files are copied over on first use if needed.
- **Client History Cache**: The frontend persistently stores scans in browser `localStorage`, ensuring your scan history reflects across browser restarts and tab refreshes.

---

## ⚙️ Environment Variables

Copy `.env.example` to `.env`. The backend loads the repository-root `.env` first, then uses `backend/.env` for any variables not set there:

```env
PORT=3001
NODE_ENV=development

# MySQL (Optional - falls back to data/scans.json if omitted)
# MYSQL_URL=mysql://root:password@containers.railway.app:3306/railway
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=phishguard

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=300
```

---

## 📡 API Reference

| Method | Endpoint                 | Description                          |
|--------|--------------------------|--------------------------------------|
| POST   | `/api/analyze`           | Analyze a URL for phishing threats   |
| GET    | `/api/history`           | Get scan history (supports ?limit)   |
| GET    | `/api/history/:id`       | Get single scan by ID                |
| DELETE | `/api/history/:id`       | Delete a scan                        |
| DELETE | `/api/history/clear`     | Clear scan history                   |
| GET    | `/api/history/:id/export`| Export scan report (JSON or CSV)     |
| GET    | `/api/stats`             | Aggregate detection statistics       |
| GET    | `/api/health`            | Health check & database connection   |

---

## 🎨 Features

- ✅ Instant URL threat score (0–100) and security grade (A–F)
- ✅ 20+ heuristic and structural detection signals
- ✅ Complete URL component breakdown (subdomains, entropy, suspicious TLDs)
- ✅ Persistent search history with "All Scans" / "My Scans" toggle
- ✅ CSV export and printable report
- ✅ Light/Dark theme mode
- ✅ 100% Railway deployment ready with single service unified architecture

---

## ⚠️ Disclaimer

This tool provides automated threat assessments based on heuristics, lexical signals, and structural patterns. It does not replace real-time antivirus or network firewall solutions.
