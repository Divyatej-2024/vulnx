# VulnX

VulnX is a vulnerability intelligence dashboard backed by NVD CVE feeds. The repository contains a React dashboard, a FastAPI service with a SQLite store, NVD feed ingestion tools, and an experimental feature export pipeline.

## Run locally

Requirements: Python 3.10+ and Node.js 18+.

1. Start the API:

   ```powershell
   cd backend
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements-api.txt
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

### Preview on a phone over your home Wi-Fi

Keep both development servers running on the PC. Start the API with `uvicorn app.main:app --reload --host 0.0.0.0`. In the frontend terminal, set the development server to listen on the network and start it:

```powershell
$env:HOST = "0.0.0.0"
npm start
```

On the PC, run `ipconfig` and find its IPv4 address. On the phone connected to the same Wi-Fi, open `http://<PC-IPv4-address>:3000`. Approve Windows Firewall's private-network prompt if it appears. This is for previewing the app on your phone; browser installation requires an HTTPS deployment, as described below.

## Load vulnerability data

From the `backend` directory, download and ingest the current NVD recent and modified feeds:

```powershell
python -m app.update_nvd
```

Feed refresh requires internet access and can take time. The ingester accepts both the legacy NVD format and the current CVE 2.0 format. Records are upserted by CVE identifier.

## Automatic mobile deployment

For a phone-ready version that updates without your PC staying on, run the Docker Compose stack on an always-on host with Docker Compose installed:

```powershell
docker compose up --build -d
```

The frontend is served on port `8080` by default. The `updater` service refreshes the NVD feeds immediately when it starts and every 24 hours after that. Its output is available with `docker compose logs -f updater`; the SQLite database and downloaded feeds persist in the `vulnx-data` Docker volume. Set `UPDATE_INTERVAL_HOURS` or `VULNX_PORT` in a `.env` file beside `docker-compose.yml` to change those defaults.

To install it on your phone, deploy this stack to a host reachable from the internet, point a domain to it, and terminate HTTPS at a reverse proxy in front of port `8080`. Open the HTTPS address in your phone's browser and choose **Install app** or **Add to Home Screen**. The app view refreshes every five minutes while open and when you return to it; offline mode can show previously loaded records. `http://localhost:8080` is useful for desktop preview, but a phone needs a hosted HTTPS address for installation.

Keep the Windows Task Scheduler option below for a local-only setup where the PC is always on. Use either that local updater or the Compose updater for a given database, rather than running both against the same SQLite file.

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
mobile/        Standalone Expo / React Native Android and iOS app
ml_pipeline/   Experimental model training entry point
```

The ML training script currently expects a generated feature dataset; no trained model is included. The API and dashboard work without the model.

See [mobile/README.md](mobile/README.md) for phone development and Android/iOS build instructions.
