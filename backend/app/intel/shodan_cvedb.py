"""Passive CVE metadata enrichment from Shodan's public CVEDB API.

This module uses the CVE database endpoint only. It does not perform host
lookups, Shodan searches, scans, or asset discovery.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from app.db import SessionLocal
from app.models import ShodanCVEIntelligence

BASE_URL = "https://cvedb.shodan.io/cve/"
CACHE_TTL = timedelta(hours=24)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
USER_AGENT = "VulnX-Shodan-CVEDB/1.0 (+https://github.com/Divyatej-2024/vulnx)"


class ShodanUnavailable(RuntimeError):
    """Raised when the public Shodan CVEDB service cannot be reached."""


def fetch_cve(cve_id: str) -> dict | None:
    """Fetch one CVE record from Shodan CVEDB; no API key is required."""
    request = Request(
        BASE_URL + quote(cve_id, safe=""),
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    try:
        with urlopen(request, timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        if exc.code == 404:
            return None
        raise ShodanUnavailable(f"Shodan CVEDB returned HTTP {exc.code}") from exc
    except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise ShodanUnavailable("Could not retrieve Shodan CVEDB data") from exc

    if not isinstance(payload, dict):
        raise ShodanUnavailable("Shodan CVEDB returned an unexpected response")
    return payload


def _normalise(cve_id: str, payload: dict) -> dict:
    """Whitelist CVEDB fields and keep source provenance separate."""
    returned_id = payload.get("cve_id")
    if returned_id and str(returned_id).upper() != cve_id:
        raise ShodanUnavailable("Shodan CVEDB returned a different CVE identifier")

    def number(name):
        value = payload.get(name)
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    return {
        "cve_id": cve_id,
        "summary": payload.get("summary"),
        "cvss": number("cvss"),
        "cvss_version": str(payload["cvss_version"]) if payload.get("cvss_version") is not None else None,
        "cvss_v2": number("cvss_v2"),
        "cvss_v3": number("cvss_v3"),
        "cvss_v4": number("cvss_v4"),
        "epss": number("epss"),
        "ranking_epss": number("ranking_epss"),
        "kev": payload.get("kev") if isinstance(payload.get("kev"), bool) else None,
        "propose_action": payload.get("propose_action"),
        "ransomware_campaign": payload.get("ransomware_campaign"),
        "references": payload.get("references") if isinstance(payload.get("references"), list) else [],
        "cpes": payload.get("cpes") if isinstance(payload.get("cpes"), list) else [],
        "published_time": payload.get("published_time"),
    }


def get_shodan_cve(
    cve_id: str,
    *,
    force_refresh: bool = False,
    session_factory=SessionLocal,
    fetcher=fetch_cve,
) -> dict | None:
    """Return a 24-hour cached record, fetching only on cache miss/expiry."""
    normalized_id = cve_id.strip().upper()
    if not CVE_PATTERN.fullmatch(normalized_id):
        raise ValueError("A valid CVE identifier is required")

    session = session_factory()
    try:
        cached = session.query(ShodanCVEIntelligence).filter_by(cve_id=normalized_id).first()
        now = datetime.utcnow()
        if cached and not force_refresh and cached.fetched_at and cached.fetched_at >= now - CACHE_TTL:
            return _serialize(cached)

        payload = fetcher(normalized_id)
        if payload is None:
            return None
        record = _normalise(normalized_id, payload)
        if cached is None:
            cached = ShodanCVEIntelligence(cve_id=normalized_id)
            session.add(cached)
        for field, value in record.items():
            if field != "cve_id":
                setattr(cached, field, value)
        cached.fetched_at = now
        session.commit()
        session.refresh(cached)
        return _serialize(cached)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _serialize(record: ShodanCVEIntelligence) -> dict:
    return {
        "cve_id": record.cve_id,
        "summary": record.summary,
        "cvss": record.cvss,
        "cvss_version": record.cvss_version,
        "cvss_v2": record.cvss_v2,
        "cvss_v3": record.cvss_v3,
        "cvss_v4": record.cvss_v4,
        "epss": record.epss,
        "ranking_epss": record.ranking_epss,
        "kev": record.kev,
        "propose_action": record.propose_action,
        "ransomware_campaign": record.ransomware_campaign,
        "references": record.references or [],
        "cpes": record.cpes or [],
        "published_time": record.published_time,
        "source": "Shodan CVEDB",
        "source_url": f"https://cvedb.shodan.io/cve/{record.cve_id}",
        "fetched_at": record.fetched_at.isoformat() + "Z" if record.fetched_at else None,
        "cache_ttl_hours": 24,
    }
