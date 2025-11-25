import pandas as pd
from app.db import SessionLocal
from app.models import Vulnerability
from datetime import datetime
#import csv
#from app.db import get_db
#from app.models import Vuln

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # backend/app -> backend
DATA_DIR = os.path.join(BASE_DIR, "data")
def build_features():
    session = SessionLocal()
    rows = session.query(Vulnerability).all()
    data = []
    for v in rows:
        raw = v.raw or {}
        # references count
        refs = raw.get('cve', {}).get('references', {}).get('reference_data', [])
        num_refs = len(refs) if refs else 0
        # label heuristic: presence of "exploit" or known references — for initial labels
        description = (v.description or "").lower()
        label = 1 if ('exploit' in description or 'proof of concept' in description or num_refs > 5) else 0
        days_since = (datetime.utcnow() - v.published_date).days if v.published_date else None
        data.append({
            "cve_id": v.cve_id,
            "cvss_v3": v.cvss_v3 or 0.0,
            "num_refs": num_refs,
            "days_since_published": days_since or 0,
            "label": label
        })
    df = pd.DataFrame(data)
    os.makedirs(DATA_DIR, exist_ok=True)

    df.to_csv(os.path.join(DATA_DIR, "features.csv"), index=False)
    session.close()
    print("Wrote data/features.csv with", len(df), "rows.")

if __name__ == "__main__":
    build_features()
