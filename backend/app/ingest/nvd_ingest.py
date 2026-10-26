"""Fast, restart-safe ingestion of official NVD CVE JSON 2.0 feeds."""
from __future__ import annotations

import gzip
import json
import os
from dateutil import parser
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.db import SessionLocal
from app.models import Vulnerability

BATCH_SIZE = int(os.getenv("NVD_INGEST_BATCH_SIZE", "500"))


def _normalize_item(item):
    if not isinstance(item, dict):
        return None
    cve = item.get("cve") or {}
    cve_id = cve.get("CVE_data_meta", {}).get("ID") or cve.get("id")
    if not cve_id:
        return None

    old_desc = cve.get("description", {}).get("description_data", [])
    new_desc = cve.get("descriptions", [])
    if old_desc:
        description = old_desc[0].get("value", "")
    else:
        description = next(
            (entry.get("value") for entry in new_desc if entry.get("lang") == "en"),
            None,
        ) or (new_desc[0].get("value", "") if new_desc else "")

    published = item.get("publishedDate") or cve.get("published") or None
    try:
        published_date = parser.isoparse(published).replace(tzinfo=None) if published else None
    except (TypeError, ValueError, OverflowError):
        published_date = None

    cvss_v3 = None
    impact = item.get("impact") or {}
    if "baseMetricV3" in impact:
        cvss_v3 = impact["baseMetricV3"].get("cvssV3", {}).get("baseScore")
    if cvss_v3 is None:
        metrics = cve.get("metrics") or {}
        for metric_name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV3"):
            candidates = metrics.get(metric_name) or []
            if candidates:
                cvss_v3 = candidates[0].get("cvssData", {}).get("baseScore")
                if cvss_v3 is not None:
                    break

    return {
        "cve_id": cve_id,
        "title": cve_id,
        "description": description,
        "published_date": published_date,
        "cvss_v3": cvss_v3,
        "raw": item,
    }


def _upsert_batch(session, rows):
    if not rows:
        return
    # A single PostgreSQL ON CONFLICT statement cannot update the same key twice.
    # Keep the last occurrence for any duplicated CVE ID in this batch.
    unique_rows = {row["cve_id"]: row for row in rows}
    payload = list(unique_rows.values())
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        statement = pg_insert(Vulnerability).values(payload)
        statement = statement.on_conflict_do_update(
            index_elements=[Vulnerability.cve_id],
            set_={
                "title": statement.excluded.title,
                "description": statement.excluded.description,
                "published_date": statement.excluded.published_date,
                "cvss_v3": statement.excluded.cvss_v3,
                "raw": statement.excluded.raw,
            },
        )
    elif dialect == "sqlite":
        statement = sqlite_insert(Vulnerability).values(payload)
        statement = statement.on_conflict_do_update(
            index_elements=[Vulnerability.cve_id],
            set_={
                "title": statement.excluded.title,
                "description": statement.excluded.description,
                "published_date": statement.excluded.published_date,
                "cvss_v3": statement.excluded.cvss_v3,
                "raw": statement.excluded.raw,
            },
        )
    else:
        # Defensive fallback for other SQLAlchemy dialects.
        for row in payload:
            existing = session.query(Vulnerability).filter_by(cve_id=row["cve_id"]).first()
            if existing is None:
                session.add(Vulnerability(**row))
            else:
                for key, value in row.items():
                    setattr(existing, key, value)
        session.flush()
        return
    session.execute(statement)


def ingest_nvd_gz(gz_path, batch_size: int | None = None):
    if not os.path.exists(gz_path):
        raise FileNotFoundError(f"No such file: {gz_path}")
    if os.path.getsize(gz_path) < 100:
        raise ValueError("File too small; likely invalid download.")

    size = batch_size or BATCH_SIZE
    if size < 1:
        raise ValueError("batch_size must be positive")

    print(f"Opening NVD feed: {gz_path}", flush=True)
    with gzip.open(gz_path, "rt", encoding="utf-8") as source:
        try:
            document = json.load(source)
        except Exception as exc:
            raise ValueError(f"Failed to decode JSON from gz file: {exc}") from exc

    items = document.get("CVE_Items") or document.get("vulnerabilities") or []
    total = len(items)
    session = SessionLocal()
    processed = 0
    batch = []
    try:
        for item in items:
            row = _normalize_item(item)
            if row is None:
                continue
            batch.append(row)
            if len(batch) >= size:
                _upsert_batch(session, batch)
                session.commit()
                processed += len(batch)
                batch.clear()
                print(f"Committed {processed:,}/{total:,} feed items", flush=True)
        if batch:
            _upsert_batch(session, batch)
            session.commit()
            processed += len(batch)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    print(f"Feed complete: {processed:,} CVE items processed from {total:,} entries.", flush=True)
    return processed
