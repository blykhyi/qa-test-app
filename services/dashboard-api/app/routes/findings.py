from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import text
from ..database import get_db
from ..models import Finding, Vulnerability, Asset
from ..schemas import (
    FindingCreate,
    FindingResponse,
    FindingDetail,
    FindingStatusUpdate,
    PaginatedFindings,
    VulnerabilityResponse,
)

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=PaginatedFindings)
def list_findings(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: str = Query(None),
    severity: str = Query(None),
    asset_id: int = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(Finding).filter(Finding.is_dismissed == False)

    if status:
        query = query.filter(Finding.status == status)
    if asset_id:
        query = query.filter(Finding.asset_id == asset_id)
    if severity:
        query = query.join(Vulnerability).filter(Vulnerability.severity == severity)

    total = query.count()
    items = query.order_by(Finding.id.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return PaginatedFindings(items=items, total=total, page=page, per_page=per_page)


@router.get("/search")
def search_findings(
    q: str = Query("", min_length=0),
    db: Session = Depends(get_db),
):
    """Search findings by CVE ID, asset hostname, or notes."""
    if not q:
        return []

    # BUG #3: SQL injection — f-string formatting instead of parameterized query
    raw_sql = f"""
        SELECT f.id, f.status, f.scanner, v.cve_id, v.severity, a.hostname
        FROM findings f
        JOIN vulnerabilities v ON f.vulnerability_id = v.id
        JOIN assets a ON f.asset_id = a.id
        WHERE v.cve_id LIKE '%{q}%'
           OR a.hostname LIKE '%{q}%'
           OR f.notes LIKE '%{q}%'
    """
    result = db.execute(text(raw_sql))
    rows = result.fetchall()
    return [
        {
            "finding_id": row[0],
            "status": row[1],
            "scanner": row[2],
            "cve_id": row[3],
            "severity": row[4],
            "hostname": row[5],
        }
        for row in rows
    ]


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    # BUG #1: doesn't filter by is_dismissed — dismissed findings still return 200
    finding = db.query(Finding).filter(Finding.id == finding_id).first()

    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Enrich with vulnerability and asset data
    vuln = db.query(Vulnerability).filter(Vulnerability.id == finding.vulnerability_id).first()
    asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()

    result = FindingDetail(
        id=finding.id,
        asset_id=finding.asset_id,
        vulnerability_id=finding.vulnerability_id,
        status=finding.status,
        detected_at=finding.detected_at,
        resolved_at=finding.resolved_at,
        scanner=finding.scanner,
        notes=finding.notes,
        is_dismissed=finding.is_dismissed,
        vulnerability=VulnerabilityResponse.model_validate(vuln) if vuln else None,
        asset_hostname=asset.hostname if asset else None,
    )
    return result


@router.post("", response_model=FindingResponse, status_code=201)
def create_finding(finding_data: FindingCreate, db: Session = Depends(get_db)):
    # Validate references
    asset = db.query(Asset).filter(Asset.id == finding_data.asset_id).first()
    if not asset:
        raise HTTPException(status_code=400, detail="Asset not found")

    vuln = db.query(Vulnerability).filter(Vulnerability.id == finding_data.vulnerability_id).first()
    if not vuln:
        raise HTTPException(status_code=400, detail="Vulnerability not found")

    finding = Finding(
        asset_id=finding_data.asset_id,
        vulnerability_id=finding_data.vulnerability_id,
        status="open",
        scanner=finding_data.scanner,
        notes=finding_data.notes,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


@router.put("/{finding_id}/status", response_model=FindingResponse)
def update_finding_status(
    finding_id: int,
    status_data: FindingStatusUpdate,
    db: Session = Depends(get_db),
):
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.is_dismissed == False,
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    valid_statuses = ["open", "confirmed", "in_progress", "resolved", "false_positive"]
    if status_data.status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}",
        )

    # BUG #2: No transition validation — allows ANY status change
    # e.g., resolved → open, false_positive → confirmed
    # Valid transitions should be:
    #   open → confirmed, confirmed → in_progress, in_progress → resolved, any → false_positive
    finding.status = status_data.status

    if status_data.status == "resolved":
        finding.resolved_at = datetime.utcnow()
    else:
        finding.resolved_at = None

    if status_data.notes:
        finding.notes = status_data.notes

    db.commit()
    db.refresh(finding)
    return finding


@router.delete("/{finding_id}", status_code=204)
def dismiss_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.is_dismissed == False,
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.is_dismissed = True
    db.commit()
    return None
