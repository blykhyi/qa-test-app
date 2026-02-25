from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, ForeignKey, Text
from sqlalchemy.sql import func
from .database import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), nullable=False)
    ip_address = Column(String(45))
    asset_type = Column(String(50), nullable=False)
    environment = Column(String(50), nullable=False)
    os = Column(String(100))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(20), unique=True, nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)
    cvss_score = Column(Float)
    published_date = Column(DateTime)
    created_at = Column(DateTime, server_default=func.now())


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False)
    status = Column(String(50), nullable=False, default="open")
    detected_at = Column(DateTime, server_default=func.now())
    resolved_at = Column(DateTime)
    scanner = Column(String(100))
    notes = Column(Text)
    is_dismissed = Column(Boolean, default=False)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    scanner_name = Column(String(100), nullable=False)
    status = Column(String(50), nullable=False, default="running")
    started_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime)
    findings_count = Column(Integer, default=0)
