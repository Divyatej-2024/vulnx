from db import SessionLocal
from models import Vulnerability
session = SessionLocal()
v = session.query(Vulnerability).limit(5).all()
for item in v:
    print(item.cve_id, item.cvss_v3, str(item.published_date)[:10])
session.close()
