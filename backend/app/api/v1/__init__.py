from fastapi import APIRouter
from app.db import SessionLocal
from app.models import Vulnerability
import csv
import os

router = APIRouter()

@router.get("/health")
async def health():
    return {"status": "ok"}

@router.get("/vulns")
def list_vulns(limit: int = 50):
    # simple approach: read scored.csv for MVP
    scored_path = os.path.join(os.getcwd(), '..', '..', 'data', 'scored.csv')
    scored_path = os.path.normpath(scored_path)
    results = []
    if os.path.exists(scored_path):
        with open(scored_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            rows_sorted = sorted(rows, key=lambda r: float(r['score']), reverse=True)
            for r in rows_sorted[:limit]:
                # fetch vuln details
                session = SessionLocal()
                v = session.query(Vulnerability).filter(Vulnerability.cve_id == r['cve_id']).first()
                if v:
                    results.append({
                        "cve_id": v.cve_id,
                        "cvss_v3": v.cvss_v3,
                        "published_date": str(v.published_date),
                        "score": float(r['score'])
                    })
                session.close()
    return {"vulns": results}
