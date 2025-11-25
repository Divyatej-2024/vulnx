from app.db import SessionLocal
from app.models import Vulnerability

session = SessionLocal()

count = session.query(Vulnerability).count()
latest = session.query(Vulnerability).order_by(Vulnerability.published_date.desc()).first()

print("Total CVEs in DB:", count)
if latest:
    print("Most recent:", latest.cve_id, latest.published_date)
session.close()
