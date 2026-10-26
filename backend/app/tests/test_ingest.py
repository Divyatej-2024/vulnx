import gzip
import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.ingest import nvd_ingest
from app.models import Base, Vulnerability


def _write_feed(path, document):
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(document, handle)


def _test_session(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'ingest.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    monkeypatch.setattr(nvd_ingest, "SessionLocal", session_factory)
    return engine, session_factory


def test_ingests_current_nvd_format_and_is_idempotent(tmp_path, monkeypatch):
    engine, TestSessionLocal = _test_session(monkeypatch, tmp_path)
    feed_path = tmp_path / "current.json.gz"
    _write_feed(feed_path, {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2025-1234",
                "published": "2025-01-02T03:04:05",
                "descriptions": [{"lang": "en", "value": "Current-format test vulnerability."}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]
                },
            }
        }]
    })

    nvd_ingest.ingest_nvd_gz(str(feed_path))
    nvd_ingest.ingest_nvd_gz(str(feed_path))

    with TestSessionLocal() as session:
        rows = session.query(Vulnerability).all()
        assert len(rows) == 1
        assert rows[0].cve_id == "CVE-2025-1234"
        assert rows[0].description == "Current-format test vulnerability."
        assert rows[0].cvss_v3 == 9.8

    engine.dispose()


def test_ingests_legacy_nvd_format(tmp_path, monkeypatch):
    engine, TestSessionLocal = _test_session(monkeypatch, tmp_path)
    feed_path = tmp_path / "legacy.json.gz"
    _write_feed(feed_path, {
        "CVE_Items": [{
            "cve": {
                "CVE_data_meta": {"ID": "CVE-2017-0001"},
                "description": {
                    "description_data": [{"lang": "en", "value": "Legacy-format test vulnerability."}]
                },
            },
            "publishedDate": "2017-01-01T00:00:00",
            "impact": {"baseMetricV3": {"cvssV3": {"baseScore": 8.0}}},
        }]
    })

    nvd_ingest.ingest_nvd_gz(str(feed_path))

    with TestSessionLocal() as session:
        row = session.query(Vulnerability).filter_by(cve_id="CVE-2017-0001").one()
        assert row.description == "Legacy-format test vulnerability."
        assert row.cvss_v3 == 8.0

    engine.dispose()
