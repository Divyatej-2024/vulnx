"""Synchronise official CISA KEV and FIRST EPSS data for VulnX CVEs.

EPSS current scores are stored separately from NVD records. Daily snapshots
are retained for 90 days so score movement can be explained without treating
EPSS as a measure of impact or proof of exploitation.
"""
from __future__ import annotations

import csv
import gzip
import json
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from urllib.request import Request, urlopen

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.db import SessionLocal
from app.models import EPSSHistory, ThreatIntelligence, Vulnerability

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
USER_AGENT = "VulnX-Threat-Intelligence/1.3 (+https://github.com/Divyatej-2024/vulnx)"
EPSS_HISTORY_DAYS = 90


@dataclass(frozen=True)
class EPSSFeed:
    scores: dict[str, tuple[float, float]]
    score_date: date | None
    model_version: str | None


def _download(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    with urlopen(request, timeout=90) as response:
        return response.read()


def _parse_date(value: str | None):
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except (TypeError, ValueError):
        return None


def parse_kev(payload: bytes | str) -> dict[str, dict]:
    document = json.loads(payload)
    vulnerabilities = document.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("CISA KEV response has no vulnerabilities list")
    result = {}
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cveID")
        if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
            continue
        result[cve_id.upper()] = {
            "is_kev": True,
            "kev_date_added": _parse_date(item.get("dateAdded")),
            "kev_due_date": _parse_date(item.get("dueDate")),
            "kev_required_action": item.get("requiredAction"),
            "kev_vendor_project": item.get("vendorProject"),
            "kev_product": item.get("product"),
        }
    return result


def parse_epss_feed(payload: bytes) -> EPSSFeed:
    """Parse the gzip CSV, including FIRST's #model_version/#score_date line."""
    try:
        decoded = gzip.decompress(payload).decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("FIRST EPSS response is not a valid gzip CSV") from exc

    model_version = None
    score_date = None
    csv_lines = []
    for line in decoded.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            metadata = stripped.lstrip("#").strip()
            for key, value in re.findall(r"([a-zA-Z_]+):([^,]+)", metadata):
                if key == "model_version":
                    model_version = value.strip()
                elif key == "score_date":
                    score_date = _parse_date(value.strip())
            continue
        csv_lines.append(line)

    reader = csv.DictReader(csv_lines)
    if not reader.fieldnames or not {"cve", "epss", "percentile"}.issubset(reader.fieldnames):
        raise ValueError("FIRST EPSS CSV is missing required columns")

    result = {}
    for row in reader:
        cve_id = (row.get("cve") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        try:
            probability = float(row["epss"])
            percentile = float(row["percentile"])
        except (KeyError, TypeError, ValueError):
            continue
        if not (0 <= probability <= 1 and 0 <= percentile <= 1):
            continue
        result[cve_id] = (probability, percentile)
    return EPSSFeed(result, score_date, model_version)


def parse_epss_gzip(payload: bytes) -> dict[str, tuple[float, float]]:
    """Backward-compatible scores-only parser."""
    return parse_epss_feed(payload).scores


def _upsert(session, model, rows: list[dict], conflict_columns: list, update_columns: list) -> None:
    if not rows:
        return
    dialect = session.get_bind().dialect.name
    if dialect not in {"postgresql", "sqlite"}:
        for row in rows:
            session.merge(model(**row))
        return
    insert = pg_insert if dialect == "postgresql" else sqlite_insert
    statement = insert(model).values(rows)
    statement = statement.on_conflict_do_update(
        index_elements=conflict_columns,
        set_={key: getattr(statement.excluded, key) for key in update_columns},
    )
    session.execute(statement)


def sync_intelligence(session_factory=SessionLocal, downloader=_download) -> dict:
    """Fetch both public feeds and persist records only for CVEs in VulnX."""
    kev = parse_kev(downloader(KEV_URL))
    epss_feed = parse_epss_feed(downloader(EPSS_URL))
    epss = epss_feed.scores

    session = session_factory()
    synced_at = datetime.utcnow()
    try:
        cve_ids = {
            row[0] for row in session.query(Vulnerability.cve_id).all()
            if row[0]
        }
        rows = []
        history_rows = []
        for cve_id in cve_ids:
            epss_values = epss.get(cve_id)
            kev_values = kev.get(cve_id, {})
            rows.append({
                "cve_id": cve_id,
                "epss_probability": epss_values[0] if epss_values else None,
                "epss_percentile": epss_values[1] if epss_values else None,
                "epss_score_date": epss_feed.score_date if epss_values else None,
                "epss_model_version": epss_feed.model_version if epss_values else None,
                "is_kev": bool(kev_values),
                "kev_date_added": kev_values.get("kev_date_added"),
                "kev_due_date": kev_values.get("kev_due_date"),
                "kev_required_action": kev_values.get("kev_required_action"),
                "kev_vendor_project": kev_values.get("kev_vendor_project"),
                "kev_product": kev_values.get("kev_product"),
                "synced_at": synced_at,
            })
            if epss_values and epss_feed.score_date:
                history_rows.append({
                    "cve_id": cve_id,
                    "score_date": epss_feed.score_date,
                    "epss_probability": epss_values[0],
                    "epss_percentile": epss_values[1],
                    "model_version": epss_feed.model_version,
                    "recorded_at": synced_at,
                })

        for start in range(0, len(rows), 500):
            _upsert(
                session, ThreatIntelligence, rows[start:start + 500],
                [ThreatIntelligence.cve_id],
                ["epss_probability", "epss_percentile", "epss_score_date",
                 "epss_model_version", "is_kev", "kev_date_added", "kev_due_date",
                 "kev_required_action", "kev_vendor_project", "kev_product", "synced_at"],
            )
        for start in range(0, len(history_rows), 500):
            _upsert(
                session, EPSSHistory, history_rows[start:start + 500],
                [EPSSHistory.cve_id, EPSSHistory.score_date],
                ["epss_probability", "epss_percentile", "model_version", "recorded_at"],
            )

        cutoff = (epss_feed.score_date or synced_at.date()) - timedelta(days=EPSS_HISTORY_DAYS - 1)
        session.query(EPSSHistory).filter(EPSSHistory.score_date < cutoff).delete(synchronize_session=False)
        session.commit()
        return {
            "vulnerabilities_checked": len(cve_ids),
            "kev_catalogue_entries": len(kev),
            "epss_scores_received": len(epss),
            "kev_matches": sum(1 for row in rows if row["is_kev"]),
            "epss_matches": sum(1 for row in rows if row["epss_probability"] is not None),
            "epss_history_snapshots": len(history_rows),
            "epss_score_date": epss_feed.score_date.isoformat() if epss_feed.score_date else None,
            "epss_model_version": epss_feed.model_version,
            "epss_history_cutoff": cutoff.isoformat(),
            "synced_at": synced_at.isoformat() + "Z",
        }
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    print(json.dumps(sync_intelligence(), indent=2))
