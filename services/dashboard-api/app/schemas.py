from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class VulnerabilityResponse(BaseModel):
    id: int
    cve_id: str
    title: str
    description: Optional[str] = None
    severity: str
    cvss_score: Optional[float] = None
    published_date: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class FindingCreate(BaseModel):
    asset_id: int
    vulnerability_id: int
    scanner: Optional[str] = None
    notes: Optional[str] = None


class FindingStatusUpdate(BaseModel):
    status: str
    notes: Optional[str] = None


class FindingResponse(BaseModel):
    id: int
    asset_id: int
    vulnerability_id: int
    status: str
    detected_at: datetime
    resolved_at: Optional[datetime] = None
    scanner: Optional[str] = None
    notes: Optional[str] = None
    is_dismissed: bool

    class Config:
        from_attributes = True


class FindingDetail(FindingResponse):
    vulnerability: Optional[VulnerabilityResponse] = None
    asset_hostname: Optional[str] = None


class PaginatedFindings(BaseModel):
    items: list[FindingResponse]
    total: int
    page: int
    per_page: int


class RiskScoreResponse(BaseModel):
    risk_score: float
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    average_cvss: float


class SummaryResponse(BaseModel):
    total_findings: int
    open_findings: int
    confirmed_findings: int
    in_progress_findings: int
    resolved_findings: int
    false_positive_findings: int
    by_severity: dict
    by_environment: dict
