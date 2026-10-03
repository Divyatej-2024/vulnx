from datetime import datetime

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, or_

from app.db import SessionLocal
from app.models import Vulnerability

router = APIRouter()


def _record(vuln: Vulnerability) -> dict:
    # A transparent CVSS normalization for sorting; this is not an ML prediction.
    score = round((vuln.cvss_v3 or 0.0) / 10, 3)
    return {
        "cve_id": vuln.cve_id,
        "title": vuln.title or vuln.cve_id,
        "description": vuln.description or "No description provided by the source.",
        "published_date": vuln.published_date.isoformat() if vuln.published_date else None,
        "cvss_v3": vuln.cvss_v3,
        "score": score,
    }


@router.get("/health")
def health() -> dict:
    return {"status": "ok"}


@router.get("/vulns")
def list_vulns(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    search: str | None = Query(default=None, max_length=200),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low|unknown)$"),
) -> dict:
    session = SessionLocal()
    try:
        query = session.query(Vulnerability)
        if search:
            term = f"%{search.strip()}%"
            query = query.filter(or_(Vulnerability.cve_id.ilike(term), Vulnerability.description.ilike(term)))
        if severity:
            bounds = {"critical": (9, 10.1), "high": (7, 9), "medium": (4, 7), "low": (0.1, 4)}
            if severity == "unknown":
                query = query.filter(Vulnerability.cvss_v3.is_(None))
            else:
                lower, upper = bounds[severity]
                query = query.filter(Vulnerability.cvss_v3 >= lower, Vulnerability.cvss_v3 < upper)
        total = query.count()
        items = query.order_by(Vulnerability.cvss_v3.desc().nullslast(), Vulnerability.published_date.desc().nullslast()) \
            .offset(offset).limit(limit).all()
        return {"vulns": [_record(item) for item in items], "total": total, "limit": limit, "offset": offset}
    finally:
        session.close()


@router.get("/summary")
def summary() -> dict:
    session = SessionLocal()
    try:
        total = session.query(func.count(Vulnerability.id)).scalar() or 0
        critical = session.query(func.count(Vulnerability.id)).filter(Vulnerability.cvss_v3 >= 9).scalar() or 0
        high = session.query(func.count(Vulnerability.id)).filter(
            Vulnerability.cvss_v3 >= 7, Vulnerability.cvss_v3 < 9
        ).scalar() or 0
        latest = session.query(func.max(Vulnerability.published_date)).scalar()
        return {
            "total": total,
            "critical": critical,
            "high": high,
            "latest_published": latest.isoformat() if latest else None,
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }
    finally:
        session.close()


@router.get("/vulns/{cve_id}")
def get_vuln(cve_id: str) -> dict:
    session = SessionLocal()
    try:
        vuln = session.query(Vulnerability).filter(Vulnerability.cve_id == cve_id.upper()).first()
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        result = _record(vuln)
        result["source"] = vuln.raw
        return result
    finally:
        session.close()
