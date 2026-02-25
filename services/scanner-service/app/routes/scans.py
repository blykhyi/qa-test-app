from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Scan, Finding, Asset, Vulnerability
from ..schemas import ScanCreate, ScanResponse, PaginatedScans

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=PaginatedScans)
def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    asset_id: int = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(Scan)
    if asset_id:
        query = query.filter(Scan.asset_id == asset_id)

    total = query.count()
    items = query.order_by(Scan.id.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return PaginatedScans(items=items, total=total, page=page, per_page=per_page)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("", response_model=ScanResponse, status_code=201)
def create_scan(scan_data: ScanCreate, db: Session = Depends(get_db)):
    """Run a scan on an asset. Creates findings for each vulnerability ID provided."""

    # Validate asset exists
    asset = db.query(Asset).filter(
        Asset.id == scan_data.asset_id,
        Asset.is_active == True,
    ).first()
    if not asset:
        raise HTTPException(status_code=400, detail="Asset not found or inactive")

    # Create scan record
    scan = Scan(
        asset_id=scan_data.asset_id,
        scanner_name=scan_data.scanner_name,
        status="running",
    )
    db.add(scan)
    db.flush()

    findings_created = 0

    for vuln_id in scan_data.vulnerability_ids:
        vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        if not vuln:
            continue

        # BUG #7: No check for existing finding with same asset_id + vulnerability_id
        # No unique constraint in DB either. Concurrent scans create duplicates.
        finding = Finding(
            asset_id=scan_data.asset_id,
            vulnerability_id=vuln_id,
            status="open",
            scanner=scan_data.scanner_name,
        )
        db.add(finding)
        findings_created += 1

    scan.status = "completed"
    scan.completed_at = datetime.utcnow()
    scan.findings_count = findings_created

    db.commit()
    db.refresh(scan)
    return scan
