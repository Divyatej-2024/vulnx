from sqlalchemy import Column, String, Integer, Float, DateTime, JSON, Boolean
from sqlalchemy.ext.declarative import declarative_base
import datetime
Base = declarative_base()

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, index=True, nullable=True)
    title = Column(String)
    description = Column(String)
    published_date = Column(DateTime)
    cvss_v3 = Column(Float)
    raw = Column(JSON)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
