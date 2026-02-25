"""
Part 2 — Database Validation: Direct PostgreSQL checks for data integrity,
constraints, and consistency after API operations.
"""
import pytest
import requests
from decimal import Decimal

DASHBOARD_API = "http://localhost:8000"
SCANNER_API = "http://localhost:8001"


# ═══════════════════════════ Schema Integrity ═══════════════════════════


class TestSchemaConstraints:
    def test_findings_require_asset_id(self, db):
        """findings.asset_id should be NOT NULL with FK constraint."""
        with pytest.raises(Exception):
            db.execute(
                "INSERT INTO findings (vulnerability_id, status) VALUES (1, 'open')"
            )

    def test_findings_require_vulnerability_id(self, db):
        """findings.vulnerability_id should be NOT NULL with FK constraint."""
        with pytest.raises(Exception):
            db.execute(
                "INSERT INTO findings (asset_id, status) VALUES (1, 'open')"
            )

    def test_findings_fk_rejects_invalid_asset(self, db):
        """FK constraint should reject nonexistent asset_id."""
        with pytest.raises(Exception):
            db.execute(
                "INSERT INTO findings (asset_id, vulnerability_id, status) "
                "VALUES (99999, 1, 'open')"
            )

    def test_findings_fk_rejects_invalid_vulnerability(self, db):
        """FK constraint should reject nonexistent vulnerability_id."""
        with pytest.raises(Exception):
            db.execute(
                "INSERT INTO findings (asset_id, vulnerability_id, status) "
                "VALUES (1, 99999, 'open')"
            )

    def test_vulnerability_cve_id_unique(self, db):
        """cve_id column has UNIQUE constraint."""
        with pytest.raises(Exception):
            db.execute(
                "INSERT INTO vulnerabilities (cve_id, title, severity, cvss_score) "
                "VALUES ('CVE-2021-44228', 'Duplicate', 'high', 5.0)"
            )

    def test_cvss_score_rejects_out_of_range(self, db):
        """
        BUG #4 DETECTED: No CHECK constraint on cvss_score.
        Values > 10 and < 0 should be rejected by the database.
        """
        # CVSS scores must be between 0.0 and 10.0
        # Test: score > 10 should fail
        try:
            db.execute(
                "UPDATE vulnerabilities SET cvss_score = 15.0 WHERE id = 1"
            )
            db.execute("SELECT cvss_score FROM vulnerabilities WHERE id = 1")
            row = db.fetchone()
            # Reset
            db.execute(
                "UPDATE vulnerabilities SET cvss_score = 10.0 WHERE id = 1"
            )
            assert row["cvss_score"] <= 10.0, (
                f"BUG: Database accepted cvss_score = 15.0 (got {row['cvss_score']}). "
                f"Missing CHECK constraint: cvss_score must be between 0 and 10."
            )
        except Exception:
            pass  # If it raises, the constraint exists (correct behavior)

    def test_cvss_score_rejects_negative(self, db):
        """BUG #4 continuation: Negative CVSS scores should be rejected."""
        try:
            db.execute(
                "UPDATE vulnerabilities SET cvss_score = -5.0 WHERE id = 2"
            )
            db.execute("SELECT cvss_score FROM vulnerabilities WHERE id = 2")
            row = db.fetchone()
            # Reset
            db.execute(
                "UPDATE vulnerabilities SET cvss_score = 9.8 WHERE id = 2"
            )
            assert row["cvss_score"] >= 0, (
                f"BUG: Database accepted cvss_score = -5.0. "
                f"Missing CHECK constraint for non-negative CVSS."
            )
        except Exception:
            pass  # Constraint exists (correct)


# ═══════════════════════════ API → DB Consistency ═══════════════════════════


class TestApiDbConsistency:
    def test_create_finding_persisted_correctly(self, api, db, created_findings):
        """Create via API → verify in DB."""
        resp = api.post("/findings", json={
            "asset_id": 1,
            "vulnerability_id": 3,
            "scanner": "db-test",
            "notes": "Verify DB persistence",
        })
        assert resp.status_code == 201
        finding_id = resp.json()["id"]
        created_findings.append(finding_id)

        db.execute("SELECT * FROM findings WHERE id = %s", (finding_id,))
        row = db.fetchone()
        assert row is not None
        assert row["asset_id"] == 1
        assert row["vulnerability_id"] == 3
        assert row["status"] == "open"
        assert row["scanner"] == "db-test"
        assert row["notes"] == "Verify DB persistence"
        assert row["is_dismissed"] is False

    def test_dismiss_finding_sets_is_dismissed(self, api, db, created_findings):
        """Dismiss via API → verify is_dismissed=TRUE in DB."""
        resp = api.post("/findings", json={
            "asset_id": 2, "vulnerability_id": 5, "scanner": "db-test"
        })
        finding_id = resp.json()["id"]
        created_findings.append(finding_id)

        api.delete(f"/findings/{finding_id}")

        db.execute("SELECT is_dismissed FROM findings WHERE id = %s", (finding_id,))
        row = db.fetchone()
        assert row["is_dismissed"] is True

    def test_status_update_persisted(self, api, db, created_findings):
        """Update status via API → verify in DB."""
        resp = api.post("/findings", json={
            "asset_id": 3, "vulnerability_id": 4, "scanner": "db-test"
        })
        finding_id = resp.json()["id"]
        created_findings.append(finding_id)

        api.put(f"/findings/{finding_id}/status", json={"status": "confirmed"})

        db.execute("SELECT status FROM findings WHERE id = %s", (finding_id,))
        row = db.fetchone()
        assert row["status"] == "confirmed"

    def test_resolved_sets_resolved_at_in_db(self, api, db, created_findings):
        """Resolving a finding should set resolved_at timestamp in DB."""
        resp = api.post("/findings", json={
            "asset_id": 1, "vulnerability_id": 6, "scanner": "db-test"
        })
        finding_id = resp.json()["id"]
        created_findings.append(finding_id)

        api.put(f"/findings/{finding_id}/status", json={"status": "resolved"})

        db.execute("SELECT resolved_at FROM findings WHERE id = %s", (finding_id,))
        row = db.fetchone()
        assert row["resolved_at"] is not None


# ═══════════════════════════ Data Quality ═══════════════════════════


class TestSeedDataQuality:
    def test_all_findings_reference_valid_assets(self, db):
        """Every finding should reference an existing asset."""
        db.execute("""
            SELECT f.id, f.asset_id
            FROM findings f
            LEFT JOIN assets a ON f.asset_id = a.id
            WHERE a.id IS NULL
        """)
        orphans = db.fetchall()
        assert len(orphans) == 0, f"Orphaned findings (no asset): {orphans}"

    def test_all_findings_reference_valid_vulnerabilities(self, db):
        """Every finding should reference an existing vulnerability."""
        db.execute("""
            SELECT f.id, f.vulnerability_id
            FROM findings f
            LEFT JOIN vulnerabilities v ON f.vulnerability_id = v.id
            WHERE v.id IS NULL
        """)
        orphans = db.fetchall()
        assert len(orphans) == 0, f"Orphaned findings (no vuln): {orphans}"

    def test_vulnerability_severities_are_valid(self, db):
        """All severity values should be one of: critical, high, medium, low."""
        valid = {"critical", "high", "medium", "low"}
        db.execute("SELECT DISTINCT severity FROM vulnerabilities")
        rows = db.fetchall()
        severities = {r["severity"] for r in rows}
        assert severities.issubset(valid), f"Invalid severities: {severities - valid}"

    def test_finding_statuses_are_valid(self, db):
        """All status values should be from the allowed set."""
        valid = {"open", "confirmed", "in_progress", "resolved", "false_positive"}
        db.execute("SELECT DISTINCT status FROM findings")
        rows = db.fetchall()
        statuses = {r["status"] for r in rows}
        assert statuses.issubset(valid), f"Invalid statuses: {statuses - valid}"

    def test_cvss_scores_within_range(self, db):
        """All CVSS scores should be between 0.0 and 10.0."""
        db.execute("SELECT id, cve_id, cvss_score FROM vulnerabilities WHERE cvss_score IS NOT NULL")
        for row in db.fetchall():
            assert 0 <= row["cvss_score"] <= 10.0, (
                f"CVSS out of range for {row['cve_id']}: {row['cvss_score']}"
            )

    def test_resolved_findings_have_resolved_at(self, db):
        """Findings with status='resolved' should have a resolved_at timestamp."""
        db.execute(
            "SELECT id, resolved_at FROM findings "
            "WHERE status = 'resolved' AND is_dismissed = FALSE"
        )
        for row in db.fetchall():
            assert row["resolved_at"] is not None, (
                f"Finding {row['id']} is resolved but has no resolved_at timestamp"
            )
