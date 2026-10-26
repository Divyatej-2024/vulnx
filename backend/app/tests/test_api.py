from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import main
from app.api import v1 as api_v1
from app.models import Base, Vulnerability


@pytest.fixture
def client(tmp_path, monkeypatch):
    database_path = tmp_path / "api-test.db"
    engine = create_engine(f"sqlite:///{database_path}")
    Base.metadata.create_all(engine)
    TestSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    with TestSessionLocal() as session:
        session.add_all([
            Vulnerability(
                cve_id="CVE-2025-0001",
                title="CVE-2025-0001",
                description="Critical sample vulnerability",
                published_date=datetime(2025, 1, 1),
                cvss_v3=9.8,
                raw={"cve": {"id": "CVE-2025-0001"}},
            ),
            Vulnerability(
                cve_id="CVE-2025-0002",
                title="CVE-2025-0002",
                description="High sample vulnerability",
                published_date=datetime(2025, 2, 1),
                cvss_v3=7.5,
                raw={"cve": {"id": "CVE-2025-0002"}},
            ),
            Vulnerability(
                cve_id="CVE-2025-0003",
                title="CVE-2025-0003",
                description="Unscored sample vulnerability",
                published_date=datetime(2025, 3, 1),
                cvss_v3=None,
                raw={"cve": {"id": "CVE-2025-0003"}},
            ),
        ])
        session.commit()

    monkeypatch.setattr(api_v1, "SessionLocal", TestSessionLocal)
    monkeypatch.setattr(main, "init_db", lambda: None)

    with TestClient(main.app) as test_client:
        yield test_client

    engine.dispose()


def test_security_headers_are_present(client):
    response = client.get("/api/v1/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert response.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"


def test_health_endpoint(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_summary_counts_total_and_severity(client):
    response = client.get("/api/v1/summary")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert data["critical"] == 1
    assert data["high"] == 1
    assert data["latest_published"] == "2025-03-01T00:00:00"


def test_list_supports_search_severity_and_pagination(client):
    response = client.get("/api/v1/vulns", params={"search": "Critical", "limit": 1})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert len(data["vulns"]) == 1
    assert data["vulns"][0]["cve_id"] == "CVE-2025-0001"

    high = client.get("/api/v1/vulns", params={"severity": "high"}).json()
    assert [row["cve_id"] for row in high["vulns"]] == ["CVE-2025-0002"]

    unknown = client.get("/api/v1/vulns", params={"severity": "unknown"}).json()
    assert [row["cve_id"] for row in unknown["vulns"]] == ["CVE-2025-0003"]

    page = client.get("/api/v1/vulns", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 3
    assert len(page["vulns"]) == 1


def test_detail_returns_source_and_missing_record_is_404(client):
    response = client.get("/api/v1/vulns/cve-2025-0001")
    assert response.status_code == 200
    assert response.json()["cve_id"] == "CVE-2025-0001"
    assert response.json()["source"] == {"cve": {"id": "CVE-2025-0001"}}

    missing = client.get("/api/v1/vulns/CVE-2099-9999")
    assert missing.status_code == 404


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 0},
        {"limit": 201},
        {"offset": -1},
        {"severity": "severe"},
        {"search": "x" * 201},
    ],
)
def test_invalid_query_parameters_return_422(client, params):
    response = client.get("/api/v1/vulns", params=params)
    assert response.status_code == 422
