import joblib
import pandas as pd
from app.db import SessionLocal
from app.models import Vulnerability
import os
from datetime import datetime

MODEL_PATH = os.path.join(os.getcwd(), '..', '..', 'ml_pipeline', 'models', 'vulnx_rf_v1.joblib')
MODEL_PATH = os.path.normpath(MODEL_PATH)

def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Model not found: " + MODEL_PATH)
    return joblib.load(MODEL_PATH)

def compute_features_for_vuln(v):
    # same features as training
    raw = v.raw or {}
    refs = raw.get('cve', {}).get('references', {}).get('reference_data', [])
    num_refs = len(refs) if refs else 0
    days_since = (datetime.utcnow() - v.published_date).days if v.published_date else 0
    return {"cvss_v3": v.cvss_v3 or 0.0, "num_refs": num_refs, "days_since_published": days_since}

def run_scoring():
    model = load_model()
    session = SessionLocal()
    vulns = session.query(Vulnerability).all()
    scored = []
    for v in vulns:
        feats = compute_features_for_vuln(v)
        X = [[feats['cvss_v3'], feats['num_refs'], feats['days_since_published']]]
        prob = float(model.predict_proba(X)[0][1])
        scored.append((v.cve_id, prob))
        # You can write the score back to DB or to a separate table. For MVP, print or store in file.
    session.close()
    print("Sample scored:", scored[:5])
    # Save a simple CSV
    import csv
    with open('../../data/scored.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['cve_id', 'score'])
        writer.writerows(scored)
    print("Wrote data/scored.csv")
