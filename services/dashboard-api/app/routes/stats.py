from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from ..database import get_db
from ..models import Finding, Vulnerability, Asset
from ..schemas import RiskScoreResponse, SummaryResponse

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/risk-score", response_model=RiskScoreResponse)
def get_risk_score(db: Session = Depends(get_db)):
    """Calculate overall risk score based on open findings' CVSS scores."""

    # Get all non-dismissed, non-resolved findings with their CVSS
    active_findings = (
        db.query(Finding, Vulnerability)
        .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
        .filter(Finding.is_dismissed == False)
        .filter(Finding.status.notin_(["resolved", "false_positive"]))
        .all()
    )

    if not active_findings:
        return RiskScoreResponse(
            risk_score=0.0,
            total_findings=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            average_cvss=0.0,
        )

    # BUG #5: Float precision — using Python float accumulation instead of Decimal
    # Also returning unrounded float values
    total_cvss = 0.0
    critical = high = medium = low = 0

    for finding, vuln in active_findings:
        if vuln.cvss_score is not None:
            total_cvss += float(vuln.cvss_score)

        if vuln.severity == "critical":
            critical += 1
        elif vuln.severity == "high":
            high += 1
        elif vuln.severity == "medium":
            medium += 1
        elif vuln.severity == "low":
            low += 1

    total = len(active_findings)
    average_cvss = total_cvss / total

    # Weighted risk score: critical*4 + high*3 + medium*2 + low*1, normalized
    # Using float arithmetic throughout — no rounding
    weighted = (critical * 4.0 + high * 3.0 + medium * 2.0 + low * 1.0)
    max_possible = total * 4.0
    risk_score = (weighted / max_possible) * 10.0 * (average_cvss / 10.0)

    return RiskScoreResponse(
        risk_score=risk_score,
        total_findings=total,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        average_cvss=average_cvss,
    )


@router.get("/summary", response_model=SummaryResponse)
def get_summary(db: Session = Depends(get_db)):
    """Get summary counts of findings by status, severity, and environment."""

    findings = (
        db.query(Finding)
        .filter(Finding.is_dismissed == False)
        .all()
    )

    status_counts = {
        "open": 0,
        "confirmed": 0,
        "in_progress": 0,
        "resolved": 0,
        "false_positive": 0,
    }
    for f in findings:
        if f.status in status_counts:
            status_counts[f.status] += 1

    # Severity breakdown for non-resolved findings
    severity_query = (
        db.query(Vulnerability.severity, func.count(Finding.id))
        .join(Finding, Finding.vulnerability_id == Vulnerability.id)
        .filter(Finding.is_dismissed == False)
        .filter(Finding.status.notin_(["resolved", "false_positive"]))
        .group_by(Vulnerability.severity)
        .all()
    )
    by_severity = {row[0]: row[1] for row in severity_query}

    # By environment
    env_query = (
        db.query(Asset.environment, func.count(Finding.id))
        .join(Finding, Finding.asset_id == Asset.id)
        .filter(Finding.is_dismissed == False)
        .filter(Finding.status.notin_(["resolved", "false_positive"]))
        .group_by(Asset.environment)
        .all()
    )
    by_environment = {row[0]: row[1] for row in env_query}

    return SummaryResponse(
        total_findings=len(findings),
        open_findings=status_counts["open"],
        confirmed_findings=status_counts["confirmed"],
        in_progress_findings=status_counts["in_progress"],
        resolved_findings=status_counts["resolved"],
        false_positive_findings=status_counts["false_positive"],
        by_severity=by_severity,
        by_environment=by_environment,
    )
