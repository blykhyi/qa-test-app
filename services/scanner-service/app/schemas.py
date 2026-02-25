from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class AssetBase(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255)
    ip_address: Optional[str] = None
    asset_type: str = Field(..., pattern="^(server|container|application)$")
    environment: str = Field(..., pattern="^(production|staging|development)$")
    os: Optional[str] = None


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    hostname: Optional[str] = Field(None, min_length=1, max_length=255)
    ip_address: Optional[str] = None
    asset_type: Optional[str] = Field(None, pattern="^(server|container|application)$")
    environment: Optional[str] = Field(None, pattern="^(production|staging|development)$")
    os: Optional[str] = None


class AssetResponse(AssetBase):
    id: int
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class PaginatedAssets(BaseModel):
    items: list[AssetResponse]
    total: int
    page: int
    per_page: int
    pages: int


class ScanCreate(BaseModel):
    asset_id: int
    scanner_name: str = Field(..., min_length=1, max_length=100)
    vulnerability_ids: list[int] = Field(default=[], description="Vulnerability IDs found in this scan")


class ScanResponse(BaseModel):
    id: int
    asset_id: int
    scanner_name: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    findings_count: int

    class Config:
        from_attributes = True


class PaginatedScans(BaseModel):
    items: list[ScanResponse]
    total: int
    page: int
    per_page: int
