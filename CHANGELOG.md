# Changelog

## 1.2.0 — Threat intelligence enrichment (proposed)

- Added an isolated `threat_intelligence` table for external exploitation intelligence; existing NVD records remain unchanged.
- Added parsers for the CISA Known Exploited Vulnerabilities JSON catalogue and FIRST daily EPSS gzip CSV, including the leading EPSS model metadata comment.
- Added an idempotent synchronisation command that enriches only CVEs already stored in VulnX.
- Added a daily/manual GitHub Actions workflow using the existing `DATABASE_URL` secret.
- Enriched vulnerability list and detail responses with EPSS probability, EPSS percentile, CISA KEV membership and remediation metadata.
- Added an explainable 0–100 triage heuristic and aggregate KEV/EPSS coverage metrics; this is not a calibrated exploitation probability or an ML prediction.
- Added dashboard intelligence coverage, KEV/EPSS indicators and detail-panel context.
- Added deterministic parser, synchronisation, API and frontend regression tests.

Release remains subject to passing CI and staging verification.

## 1.1.0 — Database readiness

- Added `GET /api/v1/ready` to verify that the configured database is reachable.
- Returns HTTP 200 with a minimal connected status when the database query succeeds.
- Returns HTTP 503 with a generic unavailable status when the database cannot be reached; connection details are not exposed.
- Kept `GET /api/v1/health` as a lightweight liveness check for compatibility.
- Added regression tests for successful readiness and database failure handling.

This release does not change vulnerability ingestion, stored records, dashboard behaviour, or deployment secrets.
