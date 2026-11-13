from sqlalchemy import Column, String, Integer, Float, DateTime, Date, Boolean, Text, JSON, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
import datetime
from pydantic import BaseModel

Base = declarative_base()


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (UniqueConstraint("cve_id", name="uq_vulnerabilities_cve_id"),)
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, index=True, nullable=False)
    title = Column(String)
    description = Column(String)
    published_date = Column(DateTime)
    cvss_v3 = Column(Float)
    raw = Column(JSON)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class ThreatIntelligence(Base):
    """Latest external exploitation intelligence associated with a CVE."""
    __tablename__ = "threat_intelligence"

    cve_id = Column(String, primary_key=True, index=True)
    epss_probability = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)
    epss_score_date = Column(Date, nullable=True)
    epss_model_version = Column(String(40), nullable=True)
    is_kev = Column(Boolean, nullable=False, default=False, index=True)
    kev_date_added = Column(Date, nullable=True)
    kev_due_date = Column(Date, nullable=True)
    kev_required_action = Column(Text, nullable=True)
    kev_vendor_project = Column(String, nullable=True)
    kev_product = Column(String, nullable=True)
    synced_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)


class EPSSHistory(Base):
    """Daily EPSS snapshots retained for trend analysis."""
    __tablename__ = "epss_history"
    __table_args__ = (UniqueConstraint("cve_id", "score_date", name="uq_epss_history_cve_score_date"),)

    id = Column(Integer, primary_key=True)
    cve_id = Column(String, nullable=False, index=True)
    score_date = Column(Date, nullable=False, index=True)
    epss_probability = Column(Float, nullable=False)
    epss_percentile = Column(Float, nullable=False)
    model_version = Column(String(40), nullable=True)
    recorded_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)


class ShodanCVEIntelligence(Base):
    """Cached CVE metadata from Shodan's public CVEDB API (not host-scan results)."""
    __tablename__ = "shodan_cve_intelligence"

    cve_id = Column(String, primary_key=True, index=True)
    summary = Column(Text, nullable=True)
    cvss = Column(Float, nullable=True)
    cvss_version = Column(String(20), nullable=True)
    cvss_v2 = Column(Float, nullable=True)
    cvss_v3 = Column(Float, nullable=True)
    cvss_v4 = Column(Float, nullable=True)
    epss = Column(Float, nullable=True)
    ranking_epss = Column(Float, nullable=True)
    kev = Column(Boolean, nullable=True)
    propose_action = Column(Text, nullable=True)
    ransomware_campaign = Column(String(120), nullable=True)
    references = Column(JSON, nullable=True)
    cpes = Column(JSON, nullable=True)
    published_time = Column(String(40), nullable=True)
    fetched_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
