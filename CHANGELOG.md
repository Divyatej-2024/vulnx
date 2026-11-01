# Changelog

## 1.1.0 — Database readiness

- Added `GET /api/v1/ready` to verify that the configured database is reachable.
- Returns HTTP 200 with a minimal connected status when the database query succeeds.
- Returns HTTP 503 with a generic unavailable status when the database cannot be reached; connection details are not exposed.
- Kept `GET /api/v1/health` as a lightweight liveness check for compatibility.
- Added regression tests for successful readiness and database failure handling.

This release does not change vulnerability ingestion, stored records, dashboard behaviour, or deployment secrets.
