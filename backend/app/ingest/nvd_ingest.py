import gzip, json, os
from dateutil import parser
from app.db import SessionLocal
from app.models import Vulnerability

def ingest_nvd_gz(gz_path):
    if not os.path.exists(gz_path):
        raise FileNotFoundError(f"No such file: {gz_path}")
    # quick sanity: file not empty
    if os.path.getsize(gz_path) < 100:
        raise ValueError("File too small; likely invalid download.")

    print("Opening gz file:", gz_path)
    with gzip.open(gz_path, 'rt', encoding='utf-8') as f:
        try:
            doc = json.load(f)
        except Exception as e:
            raise ValueError("Failed to decode JSON from gz file: " + str(e))

    session = SessionLocal()
    count = 0
    for item in doc.get('CVE_Items', []):
        cve_id = item['cve']['CVE_data_meta']['ID']
        desc = ""
        desc_list = item.get('cve', {}).get('description', {}).get('description_data', [])
        if desc_list:
            desc = desc_list[0].get('value', "")
        published = item.get('publishedDate')
        try:
            published_dt = parser.isoparse(published) if published else None
        except:
            published_dt = None
        impact = item.get('impact', {})
        cvss_v3 = None
        if impact.get('baseMetricV3'):
            cvss_v3 = impact['baseMetricV3']['cvssV3'].get('baseScore')
        vuln = Vulnerability(
            cve_id=cve_id,
            title=cve_id,
            description=desc,
            published_date=published_dt,
            cvss_v3=cvss_v3,
            raw=item
        )
        session.merge(vuln)  # upsert by unique fields (cve_id)
        count += 1
    session.commit()
    session.close()
    print(f"Ingested {count} CVE items.")
