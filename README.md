# VulnX

VulnX is a vulnerability intelligence dashboard backed by NVD CVE feeds, enriched with CISA Known Exploited Vulnerabilities (KEV) and FIRST Exploit Prediction Scoring System (EPSS) data. The repository contains a React dashboard, a FastAPI service, SQLAlchemy persistence, NVD ingestion, and an experimental feature export pipeline.

## Run locally

Requirements: Python 3.12 and Node.js 18+.

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

## Load vulnerability data

From the `backend` directory, download and ingest the current NVD recent and modified feeds:

```powershell
python -m app.update_nvd
```

Feed refresh requires internet access and can take time. The ingester accepts both the legacy NVD format and the current CVE 2.0 format. Records are upserted by CVE identifier.

## Threat intelligence enrichment

VulnX 1.2 adds a separate `threat_intelligence` table. It does not overwrite NVD source records. The synchroniser joins the public CISA KEV catalogue and FIRST's daily EPSS CSV against CVE identifiers already stored in VulnX:

- CISA KEV: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- FIRST EPSS data and format: <https://www.first.org/epss/data>
- Daily EPSS CSV: <https://epss.empiricalsecurity.com/epss_scores-current.csv.gz>

Run a sync manually from the `backend` directory:

```powershell
python -m app.intel.sync
```

The GitHub Actions workflow `.github/workflows/threat-intel-sync.yml` is scheduled daily and can also be run manually. It uses the existing `DATABASE_URL` repository secret; it does not store credentials in source. The sync requires that secret to point to the same database used by the API. It fetches both public datasets before writing and only upserts CVEs already present in VulnX. A successful run reports checked CVEs, source match counts and the sync timestamp.

The parser ignores FIRST's leading `#model_version` metadata line before reading the CSV header. EPSS values are probabilities from 0 to 1; the percentile is a relative ranking, not another probability.

## API

- `GET /api/v1/health` — liveness check for the API process.
- `GET /api/v1/ready` — readiness check that executes a database query; returns HTTP 200 when connected or HTTP 503 when unavailable.
- `GET /api/v1/summary` — CVE totals, severity counts, CISA KEV matches, EPSS ≥10% count and EPSS coverage.
- `GET /api/v1/vulns?limit=50&offset=0&search=CVE&severity=high` — filtered, paginated CVEs enriched with EPSS probability, EPSS percentile, KEV membership and priority score.
- `GET /api/v1/vulns/{cve_id}` — CVE details plus available exploitation intelligence and CISA remediation metadata.

The explainable 0–100 triage heuristic is `min(100, 5 × CVSS + 30 × EPSS + 20 if in CISA KEV)`. CVSS contributes at most 50 points, EPSS probability contributes at most 30, and confirmed KEV catalogue membership contributes 20. This is a transparent prioritisation aid—not a calibrated breach probability, a CVSS replacement, or an ML prediction. Missing EPSS data is represented as unavailable in the API, not as proof of zero exploitation risk. CVSS severity filters use the standard bands (Critical 9.0+, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9).

## Project structure

```text
backend/       FastAPI API, SQLAlchemy models, NVD ingestion, KEV/EPSS enrichment and feature export
frontend/      React dashboard
mobile/        Standalone Expo / React Native Android and iOS app
ml_pipeline/   Experimental model training entry point
```

The ML training script currently expects a generated feature dataset; no trained model is included. The API and dashboard work without the model.

See [mobile/README.md](mobile/README.md) for phone development and Android/iOS build instructions.
