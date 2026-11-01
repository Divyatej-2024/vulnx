"""Synchronise official CISA KEV and FIRST EPSS data for VulnX CVEs.

Sources:
- CISA Known Exploited Vulnerabilities catalogue (JSON)
- FIRST EPSS current daily scores (compressed CSV)

The sync is additive: it writes to the separate threat_intelligence table and
never modifies NVD vulnerability records.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
from datetime import date, datetime
from urllib.request import Request, urlopen

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.db import SessionLocal
from app.models import ThreatIntelligence, Vulnerability

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
USER_AGENT = "VulnX-Threat-Intelligence/1.2 (+https://github.com/Divyatej-2024/vulnx)"


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


def parse_epss_gzip(payload: bytes) -> dict[str, tuple[float, float]]:
    try:
        decoded = gzip.decompress(payload).decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("FIRST EPSS response is not a valid gzip CSV") from exc
    # EPSS v2+ daily exports begin with a #model_version metadata line.
    # Ignore comment/blank lines so DictReader sees the actual cve,epss,percentile header.
    csv_lines = [line for line in decoded.splitlines() if line.strip() and not line.lstrip().startswith("#")]
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
    return result


def _upsert(session, rows: list[dict]) -> None:
    if not rows:
        return
    dialect = session.get_bind().dialect.name
    if dialect not in {"postgresql", "sqlite"}:
        for row in rows:
            session.merge(ThreatIntelligence(**row))
        return
    insert = pg_insert if dialect == "postgresql" else sqlite_insert
    statement = insert(ThreatIntelligence).values(rows)
    statement = statement.on_conflict_do_update(
        index_elements=[ThreatIntelligence.cve_id],
        set_={
            key: getattr(statement.excluded, key)
            for key in (
                "epss_probability", "epss_percentile", "is_kev",
                "kev_date_added", "kev_due_date", "kev_required_action",
                "kev_vendor_project", "kev_product", "synced_at",
            )
        },
    )
    session.execute(statement)


def sync_intelligence(session_factory=SessionLocal, downloader=_download) -> dict:
    """Fetch both public feeds and persist records only for CVEs in VulnX."""
    kev = parse_kev(downloader(KEV_URL))
    epss = parse_epss_gzip(downloader(EPSS_URL))

    session = session_factory()
    synced_at = datetime.utcnow()
    try:
        cve_ids = {
            row[0] for row in session.query(Vulnerability.cve_id).all()
            if row[0]
        }
        rows = []
        for cve_id in cve_ids:
            epss_values = epss.get(cve_id)
            kev_values = kev.get(cve_id, {})
            rows.append({
                "cve_id": cve_id,
                "epss_probability": epss_values[0] if epss_values else None,
                "epss_percentile": epss_values[1] if epss_values else None,
                "is_kev": bool(kev_values),
                "kev_date_added": kev_values.get("kev_date_added"),
                "kev_due_date": kev_values.get("kev_due_date"),
                "kev_required_action": kev_values.get("kev_required_action"),
                "kev_vendor_project": kev_values.get("kev_vendor_project"),
                "kev_product": kev_values.get("kev_product"),
                "synced_at": synced_at,
            })
        for start in range(0, len(rows), 500):
            _upsert(session, rows[start:start + 500])
            session.commit()
        return {
            "vulnerabilities_checked": len(cve_ids),
            "kev_catalogue_entries": len(kev),
            "epss_scores_received": len(epss),
            "kev_matches": sum(1 for row in rows if row["is_kev"]),
            "epss_matches": sum(1 for row in rows if row["epss_probability"] is not None),
            "synced_at": synced_at.isoformat() + "Z",
        }
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    print(json.dumps(sync_intelligence(), indent=2))
