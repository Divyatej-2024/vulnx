from sqlalchemy import Column, String, Integer, Float, DateTime, JSON, UniqueConstraint
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
