import gzip, json, os
from dateutil import parser
from app.db import SessionLocal
from app.models import Vulnerability

def ingest_nvd_gz(gz_path):
    if not os.path.exists(gz_path):
        raise FileNotFoundError(f"No such file: {gz_path}")

    if os.path.getsize(gz_path) < 100:
        raise ValueError("File too small; likely invalid download.")

    print("Opening gz file:", gz_path)
    with gzip.open(gz_path, "rt", encoding="utf-8") as f:
        try:
            doc = json.load(f)
        except Exception as e:
            raise ValueError(f"Failed to decode JSON from gz file: {e}")

    # Auto-detect new or old feed
    items = doc.get("CVE_Items") or doc.get("vulnerabilities") or []
    session = SessionLocal()
    count = 0
    try:
        for item in items:
        # Normalize structure for new feeds (where item['cve'] is nested)
            if not isinstance(item, dict):
                continue
            cve_block = item.get("cve", {})

        # Extract CVE ID from old or new format
            cve_id = (
                cve_block.get("CVE_data_meta", {}).get("ID")
                or cve_block.get("id")
            )
            if not cve_id:
                # skip malformed entries
                continue

        # Extract description (old: description_data[], new: descriptions[])
            desc = ""
            old_desc = cve_block.get("description", {}).get("description_data", [])
            new_desc = cve_block.get("descriptions", [])

            if old_desc:
                desc = old_desc[0].get("value", "")
            elif new_desc:
                desc = next((d.get("value") for d in new_desc if d.get("lang") == "en"), "") \
                    or new_desc[0].get("value", "")

        # Published date (old: publishedDate, new: cve.published)
            published = item.get("publishedDate") or cve_block.get("published") or None
            try:
                published_dt = parser.isoparse(published) if published else None
            except (TypeError, ValueError, OverflowError):
                published_dt = None

        # CVSS v3 (old: impact.baseMetricV3.cvssV3.baseScore, new: metrics.cvssMetricV31[])
            cvss_v3 = None

        # Old format
            impact = item.get("impact", {})
            if "baseMetricV3" in impact:
                cvss_v3 = impact["baseMetricV3"].get("cvssV3", {}).get("baseScore")

        # New format
            if cvss_v3 is None:
                metrics = cve_block.get("metrics", {})
                for metric_name in ("cvssMetricV31", "cvssMetricV30"):
                    candidates = metrics.get(metric_name, [])
                    if candidates:
                        cvss_v3 = candidates[0].get("cvssData", {}).get("baseScore")
                        if cvss_v3 is not None:
                            break

            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if vuln is None:
                vuln = Vulnerability(cve_id=cve_id)
                session.add(vuln)
            vuln.title = cve_id
            vuln.description = desc
            vuln.published_date = published_dt
            vuln.cvss_v3 = cvss_v3
            vuln.raw = item
            count += 1

        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    print(f"Ingested {count} CVE items.")
