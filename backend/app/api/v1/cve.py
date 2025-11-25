from fastapi import APIRouter
from app.db import SessionLocal
from app.models import Vulnerability

router = APIRouter()

@router.get("/list")
def list_cves(limit: int = 50, offset: int = 0):
    db = SessionLocal()
    items = db.query(Vulnerability).order_by(
        Vulnerability.published_date.desc()
    ).offset(offset).limit(limit).all()
    db.close()
    return items

@router.get("/{cve_id}")
def get_cve(cve_id: str):
    db = SessionLocal()
    item = db.query(Vulnerability).filter_by(cve_id=cve_id).first()
    db.close()
    return item
