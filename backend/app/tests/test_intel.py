import gzip
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.intel.sync import parse_epss_feed, parse_epss_gzip, parse_kev, sync_intelligence
from app.models import Base, ThreatIntelligence, Vulnerability


def test_parse_cisa_kev_catalogue():
    payload = json.dumps({"vulnerabilities": [{
        "cveID": "CVE-2025-1234",
        "vendorProject": "Example Vendor",
        "product": "Example Product",
        "dateAdded": "2025-01-02",
        "dueDate": "2025-02-01",
        "requiredAction": "Apply the vendor update.",
    }]}).encode()
    result = parse_kev(payload)
    assert result["CVE-2025-1234"]["is_kev"] is True
    assert result["CVE-2025-1234"]["kev_date_added"].isoformat() == "2025-01-02"
    assert result["CVE-2025-1234"]["kev_due_date"].isoformat() == "2025-02-01"


def test_parse_epss_current_csv():
    content = "cve,epss,percentile\nCVE-2025-1234,0.75,0.98\nCVE-2025-1235,1.2,0.5\n"
    payload = gzip.compress(content.encode())
    assert parse_epss_gzip(payload) == {"CVE-2025-1234": (0.75, 0.98)}


def test_rejects_invalid_epss_payload():
    with pytest.raises(ValueError):
        parse_epss_gzip(b"not gzip")


def test_sync_only_persists_vulnx_cves_and_is_repeatable(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'intel.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with factory() as session:
        session.add_all([
            Vulnerability(cve_id="CVE-2025-1234", description="Test CVE"),
            Vulnerability(cve_id="CVE-2025-9999", description="No EPSS result"),
        ])
        session.commit()

    kev_payload = json.dumps({"vulnerabilities": [{
        "cveID": "CVE-2025-1234", "vendorProject": "Vendor",
        "product": "Product", "dateAdded": "2025-01-02",
        "dueDate": "2025-02-01", "requiredAction": "Patch",
    }, {"cveID": "CVE-2099-0001"}]}).encode()
    epss_payload = gzip.compress(
        b"cve,epss,percentile\nCVE-2025-1234,0.75,0.98\nCVE-2025-0000,0.2,0.4\n"
    )
    payloads = {
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json": kev_payload,
        "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz": epss_payload,
    }
    result = sync_intelligence(factory, downloader=lambda url: payloads[url])
    assert result["vulnerabilities_checked"] == 2
    assert result["kev_matches"] == 1
    assert result["epss_matches"] == 1

    # A second sync updates the same rows rather than creating duplicates.
    sync_intelligence(factory, downloader=lambda url: payloads[url])
    with factory() as session:
        rows = session.query(ThreatIntelligence).all()
        assert len(rows) == 2
        matched = session.query(ThreatIntelligence).filter_by(cve_id="CVE-2025-1234").one()
        assert matched.is_kev is True
        assert matched.epss_probability == 0.75
        unmatched = session.query(ThreatIntelligence).filter_by(cve_id="CVE-2025-9999").one()
        assert unmatched.epss_probability is None
        assert unmatched.is_kev is False
    engine.dispose()



def test_parse_epss_feed_reads_first_metadata_and_scores():
    content = (
        "#model_version:v2026.01,score_date:2026-11-01\\n"
        "cve,epss,percentile\\n"
        "CVE-2026-1000,0.625,0.975\\n"
    )
    feed = parse_epss_feed(gzip.compress(content.encode()))
    assert feed.score_date.isoformat() == "2026-11-01"
    assert feed.model_version == "v2026.01"
    assert feed.scores == {"CVE-2026-1000": (0.625, 0.975)}


def test_sync_persists_daily_epss_history_and_provenance(tmp_path):
    from app.models import EPSSHistory

    engine = create_engine(f"sqlite:///{tmp_path / 'epss-history.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    with factory() as session:
        session.add(Vulnerability(cve_id="CVE-2026-1000"))
        session.commit()

    kev_payload = json.dumps({"vulnerabilities": []}).encode()
    epss_payload = gzip.compress(
        b"#model_version:v2026.01,score_date:2026-11-01\\n"
        b"cve,epss,percentile\\nCVE-2026-1000,0.625,0.975\\n"
    )
    payloads = {
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json": kev_payload,
        "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz": epss_payload,
    }
    result = sync_intelligence(factory, downloader=lambda url: payloads[url])
    assert result["epss_history_snapshots"] == 1
    assert result["epss_score_date"] == "2026-11-01"
    with factory() as session:
        current = session.query(ThreatIntelligence).one()
        assert current.epss_score_date.isoformat() == "2026-11-01"
        assert current.epss_model_version == "v2026.01"
        history = session.query(EPSSHistory).one()
        assert history.epss_probability == 0.625
        assert history.model_version == "v2026.01"
    # Re-running the same daily feed updates that date rather than duplicating it.
    sync_intelligence(factory, downloader=lambda url: payloads[url])
    with factory() as session:
        assert session.query(EPSSHistory).count() == 1
    engine.dispose()
