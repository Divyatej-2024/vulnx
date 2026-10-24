# VulnX

VulnX is a vulnerability intelligence dashboard backed by NVD CVE feeds. The repository contains a React dashboard, a FastAPI service with a SQLite store, NVD feed ingestion tools, and an experimental feature export pipeline.

## Run locally

Requirements: Python 3.10+ and Node.js 18+.

1. Start the API:

   ```powershell
   cd backend
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   uvicorn app.main:app --reload
   ```

   The API creates `backend/dev.db` on startup. Interactive API docs are at <http://localhost:8000/docs>.

2. In a second terminal, start the dashboard:

   ```powershell
   cd frontend/vulnx-ui
   npm ci
   npm start
   ```

   Open <http://localhost:3000>. The React development server proxies `/api/v1` to the local API.

## Load vulnerability data

From the `backend` directory, download and ingest the current NVD recent and modified feeds:

```powershell
python -m app.update_nvd
```

Feed refresh requires internet access and can take time. The ingester accepts both the legacy NVD format and the current CVE 2.0 format. Records are upserted by CVE identifier.

### Run NVD refresh automatically on Windows

After creating the backend virtual environment and installing requirements, run this once from PowerShell:

```powershell
cd backend
Set-ExecutionPolicy -Scope Process Bypass
.\setup_scheduled_task.ps1 -DailyAt "02:00"
```

This registers a Windows Task Scheduler job that downloads and ingests both current feeds daily at 02:00 (local machine time). `StartWhenAvailable` runs a missed refresh when Windows becomes available again. Output is appended to `backend/logs/scheduled_update.log`. Run a refresh manually with `backend/run_daily.bat`; remove the scheduled job with `Unregister-ScheduledTask -TaskName VulnX-NVD-Update`.

### Install on a phone

Deploy the frontend over HTTPS, open it in the phone's browser, and select **Install app** or **Add to Home Screen**. VulnX caches its app shell and successful API responses so the most recently loaded feed can be browsed offline. A PWA install requires HTTPS outside localhost.

For production, set `REACT_APP_API_URL` to the deployed API URL before building the frontend. Set backend `CORS_ORIGINS` to the comma-separated frontend origins when the API is hosted separately. For the simplest offline behavior, serve `/api/v1` from the same origin as the frontend through a reverse proxy, which also avoids cross-origin browser restrictions.

## API

- `GET /api/v1/health` — service health
- `GET /api/v1/summary` — total, critical, and high CVE counts
- `GET /api/v1/vulns?limit=50&offset=0&search=CVE&severity=high` — filtered, paginated CVEs
- `GET /api/v1/vulns/{cve_id}` — CVE details

The dashboard's priority bar is CVSS v3 divided by 10. It is a transparent severity normalization, not the output of the experimental ML pipeline. CVSS severity filters use the standard bands (Critical 9.0+, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9).

## Project structure

```text
backend/       FastAPI API, SQLAlchemy models, NVD ingestion and feature export
frontend/      React dashboard
ml_pipeline/   Experimental model training entry point
```

The ML training script currently expects a generated feature dataset; no trained model is included. The API and dashboard work without the model.
