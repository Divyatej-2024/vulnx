from datetime import datetime

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy import func, or_, text
from sqlalchemy.exc import SQLAlchemyError

from app.db import SessionLocal
from app.models import ThreatIntelligence, Vulnerability

router = APIRouter()


def _priority(cvss_v3, epss_probability, is_kev):
    """Explainable 0–100 triage heuristic; not a breach probability or ML model."""
    cvss_component = (cvss_v3 or 0.0) * 5.0
    epss_component = (epss_probability or 0.0) * 30.0
    kev_component = 20.0 if is_kev else 0.0
    return round(min(100.0, cvss_component + epss_component + kev_component), 1)


def _record(vuln: Vulnerability, intel: ThreatIntelligence | None = None) -> dict:
    epss = intel.epss_probability if intel else None
    percentile = intel.epss_percentile if intel else None
    is_kev = bool(intel.is_kev) if intel else False
    return {
        "cve_id": vuln.cve_id,
        "title": vuln.title or vuln.cve_id,
        "description": vuln.description or "No description provided by the source.",
        "published_date": vuln.published_date.isoformat() if vuln.published_date else None,
        "cvss_v3": vuln.cvss_v3,
        "score": round((vuln.cvss_v3 or 0.0) / 10, 3),
        "epss_probability": epss,
        "epss_percentile": percentile,
        "is_kev": is_kev,
        "kev_date_added": intel.kev_date_added.isoformat() if intel and intel.kev_date_added else None,
        "kev_due_date": intel.kev_due_date.isoformat() if intel and intel.kev_due_date else None,
        "kev_required_action": intel.kev_required_action if intel else None,
        "kev_vendor_project": intel.kev_vendor_project if intel else None,
        "kev_product": intel.kev_product if intel else None,
        "priority_score": _priority(vuln.cvss_v3, epss, is_kev),
        "intelligence_available": bool(intel and (epss is not None or is_kev)),
    }


@router.get("/health")
def health() -> dict:
    """Liveness check: confirms that the API process can answer requests."""
    return {"status": "ok"}


@router.get("/ready")
def readiness():
    """Readiness check: confirms the API can reach its configured database."""
    session = SessionLocal()
    try:
        session.execute(text("SELECT 1"))
        return {"status": "ready", "database": "connected"}
    except SQLAlchemyError:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "database": "unavailable"},
        )
    finally:
        session.close()


@router.get("/vulns")
def list_vulns(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    search: str | None = Query(default=None, max_length=200),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low|unknown)$"),
) -> dict:
    session = SessionLocal()
    try:
        query = session.query(Vulnerability, ThreatIntelligence).outerjoin(
            ThreatIntelligence, Vulnerability.cve_id == ThreatIntelligence.cve_id
        )
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
        items = query.order_by(
            ThreatIntelligence.is_kev.desc(),
            ThreatIntelligence.epss_probability.desc().nullslast(),
            Vulnerability.cvss_v3.desc().nullslast(),
            Vulnerability.published_date.desc().nullslast(),
        ).offset(offset).limit(limit).all()
        return {
            "vulns": [_record(vuln, intel) for vuln, intel in items],
            "total": total, "limit": limit, "offset": offset,
        }
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
        kev_count = session.query(func.count(ThreatIntelligence.cve_id)).join(
            Vulnerability, Vulnerability.cve_id == ThreatIntelligence.cve_id
        ).filter(ThreatIntelligence.is_kev.is_(True)).scalar() or 0
        epss_high_count = session.query(func.count(ThreatIntelligence.cve_id)).join(
            Vulnerability, Vulnerability.cve_id == ThreatIntelligence.cve_id
        ).filter(ThreatIntelligence.epss_probability >= 0.1).scalar() or 0
        epss_coverage = session.query(func.count(ThreatIntelligence.cve_id)).join(
            Vulnerability, Vulnerability.cve_id == ThreatIntelligence.cve_id
        ).filter(ThreatIntelligence.epss_probability.isnot(None)).scalar() or 0
        return {
            "total": total, "critical": critical, "high": high,
            "kev_count": kev_count, "epss_high_count": epss_high_count,
            "epss_coverage": epss_coverage,
            "latest_published": latest.isoformat() if latest else None,
            "updated_at": datetime.utcnow().isoformat() + "Z",
        }
    finally:
        session.close()


@router.get("/vulns/{cve_id}")
def get_vuln(cve_id: str) -> dict:
    session = SessionLocal()
    try:
        row = session.query(Vulnerability, ThreatIntelligence).outerjoin(
            ThreatIntelligence, Vulnerability.cve_id == ThreatIntelligence.cve_id
        ).filter(Vulnerability.cve_id == cve_id.upper()).first()
        if not row:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        vuln, intel = row
        result = _record(vuln, intel)
        result["source"] = vuln.raw
        return result
    finally:
        session.close()
