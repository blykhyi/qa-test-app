from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Vulnerability
from ..schemas import VulnerabilityResponse

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("", response_model=list[VulnerabilityResponse])
def list_vulnerabilities(
    severity: str = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(Vulnerability)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    return query.order_by(Vulnerability.cvss_score.desc()).all()


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
def get_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln
