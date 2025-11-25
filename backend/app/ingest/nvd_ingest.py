import gzip, json
from dateutil import parser
from app.db import SessionLocal
from app.models import Vulnerability

def ingest_nvd_gz(gz_path):
    with gzip.open(gz_path, 'rt', encoding='utf-8') as f:
        doc = json.load(f)
    session = SessionLocal()
    for item in doc.get('CVE_Items', []):
        cve_id = item['cve']['CVE_data_meta']['ID']
        desc = item['cve']['description']['description_data'][0]['value']
        published = parser.isoparse(item['publishedDate'])
        impact = item.get('impact', {})
        cvss_v3 = None
        if impact.get('baseMetricV3'):
            cvss_v3 = impact['baseMetricV3']['cvssV3']['baseScore']
        vuln = Vulnerability(
            cve_id=cve_id, title=cve_id, description=desc,
            published_date=published, cvss_v3=cvss_v3, raw=item
        )
        session.merge(vuln)  # merge to update if exists
    session.commit()
    session.close()
