"""Part 2 — PostgreSQL validation: integrity after API calls, FK/NOT NULL constraints, consistency."""

from __future__ import annotations

import pytest
import requests

pytestmark = pytest.mark.usefixtures("postgres_available")

SEED_ASSET_ID = 3
SEED_VULNERABILITY_ID = 4


def _findings_url(base: str, suffix: str = "") -> str:
    return f"{base}/findings{suffix}"


@pytest.mark.usefixtures("dashboard_available")
class TestFindingLifecycleDbIntegrity:
    def test_dismiss_via_api_sets_is_dismissed_in_db(
        self,
        dashboard_base_url: str,
        db_cursor,
    ) -> None:
        payload = {
            "asset_id": SEED_ASSET_ID,
            "vulnerability_id": SEED_VULNERABILITY_ID,
            "scanner": "pytest-db-dismiss",
            "notes": "db dismiss check",
        }
        created = requests.post(
            _findings_url(dashboard_base_url),
            json=payload,
            timeout=15,
        )
        assert created.status_code == 201
        fid = created.json()["id"]

        db_cursor.execute(
            "SELECT is_dismissed FROM findings WHERE id = %s",
            (fid,),
        )
        row = db_cursor.fetchone()
        assert row is not None
        assert row[0] is False

        dismiss = requests.delete(_findings_url(dashboard_base_url, f"/{fid}"), timeout=15)
        assert dismiss.status_code == 204

        db_cursor.execute(
            "SELECT is_dismissed FROM findings WHERE id = %s",
            (fid,),
        )
        row = db_cursor.fetchone()
        assert row is not None
        assert row[0] is True

    def test_create_via_api_persists_expected_columns(
        self,
        dashboard_base_url: str,
        db_cursor,
    ) -> None:
        payload = {
            "asset_id": SEED_ASSET_ID,
            "vulnerability_id": SEED_VULNERABILITY_ID,
            "scanner": "pytest-db-create",
            "notes": "row shape",
        }
        r = requests.post(_findings_url(dashboard_base_url), json=payload, timeout=15)
        assert r.status_code == 201
        body = r.json()
        fid = body["id"]

        db_cursor.execute(
            """
            SELECT asset_id, vulnerability_id, status, scanner, notes, is_dismissed
            FROM findings WHERE id = %s
            """,
            (fid,),
        )
        row = db_cursor.fetchone()
        assert row is not None
        asset_id, vuln_id, status, scanner, notes, is_dismissed = row
        assert asset_id == SEED_ASSET_ID
        assert vuln_id == SEED_VULNERABILITY_ID
        assert status == "open"
        assert scanner == "pytest-db-create"
        assert notes == "row shape"
        assert is_dismissed is False

    def test_update_status_via_api_persists_in_db(
        self,
        dashboard_base_url: str,
        db_cursor,
    ) -> None:
        payload = {
            "asset_id": SEED_ASSET_ID,
            "vulnerability_id": SEED_VULNERABILITY_ID,
            "scanner": "pytest-db-status",
            "notes": "status sync",
        }
        created = requests.post(
            _findings_url(dashboard_base_url),
            json=payload,
            timeout=15,
        )
        assert created.status_code == 201
        fid = created.json()["id"]

        upd = requests.put(
            _findings_url(dashboard_base_url, f"/{fid}/status"),
            json={"status": "in_progress", "notes": "picked up by team"},
            timeout=15,
        )
        assert upd.status_code == 200

        db_cursor.execute(
            "SELECT status, notes FROM findings WHERE id = %s",
            (fid,),
        )
        row = db_cursor.fetchone()
        assert row == ("in_progress", "picked up by team")


class TestReferentialConsistency:
    def test_no_orphan_findings_against_assets_and_vulnerabilities(self, db_cursor) -> None:
        db_cursor.execute(
            """
            SELECT COUNT(*) FROM findings f
            LEFT JOIN assets a ON f.asset_id = a.id
            LEFT JOIN vulnerabilities v ON f.vulnerability_id = v.id
            WHERE a.id IS NULL OR v.id IS NULL
            """
        )
        (orphans,) = db_cursor.fetchone()
        assert orphans == 0

    def test_finding_counts_match_asset_hostnames(self, db_cursor) -> None:
        db_cursor.execute(
            """
            SELECT f.id, a.hostname FROM findings f
            JOIN assets a ON f.asset_id = a.id
            WHERE f.is_dismissed = FALSE
            LIMIT 5
            """
        )
        rows = db_cursor.fetchall()
        assert rows
        for _fid, hostname in rows:
            assert hostname


class TestForeignKeyEnforcement:
    def test_findings_reject_unknown_asset_id(self, db_cursor) -> None:
        import psycopg2

        with pytest.raises(psycopg2.errors.ForeignKeyViolation):
            db_cursor.execute(
                """
                INSERT INTO findings (asset_id, vulnerability_id, status)
                VALUES (%s, %s, 'open')
                """,
                (999_999, 1),
            )

    def test_findings_reject_unknown_vulnerability_id(self, db_cursor) -> None:
        import psycopg2

        with pytest.raises(psycopg2.errors.ForeignKeyViolation):
            db_cursor.execute(
                """
                INSERT INTO findings (asset_id, vulnerability_id, status)
                VALUES (%s, %s, 'open')
                """,
                (1, 999_999),
            )


class TestNotNullAndUniqueConstraints:
    def test_assets_require_hostname(self, db_cursor) -> None:
        import psycopg2

        with pytest.raises(psycopg2.errors.NotNullViolation):
            db_cursor.execute(
                """
                INSERT INTO assets (hostname, asset_type, environment)
                VALUES (NULL, 'server', 'production')
                """
            )

    def test_vulnerabilities_cve_id_is_unique(self, db_cursor) -> None:
        import psycopg2

        db_cursor.execute(
            "SELECT cve_id FROM vulnerabilities LIMIT 1",
        )
        (existing_cve,) = db_cursor.fetchone()

        with pytest.raises(psycopg2.errors.UniqueViolation):
            db_cursor.execute(
                """
                INSERT INTO vulnerabilities (cve_id, title, severity)
                VALUES (%s, 'dup title', 'low')
                """,
                (existing_cve,),
            )


class TestCvssScoreConstraint:
    """CVSS should be constrained to a valid range (e.g. 0–10); see BUG #4 / init.sql."""

    def test_cvss_out_of_range_insert_is_rejected(self, db_cursor) -> None:
        import psycopg2

        cve = "CVE-TEST-DB-CVSS"
        db_cursor.execute("DELETE FROM vulnerabilities WHERE cve_id = %s", (cve,))
        try:
            db_cursor.execute(
                """
                INSERT INTO vulnerabilities (cve_id, title, severity, cvss_score)
                VALUES (%s, 'test row', 'low', %s)
                """,
                (cve, 99.0),
            )
        except psycopg2.errors.CheckViolation:
            db_cursor.execute("DELETE FROM vulnerabilities WHERE cve_id = %s", (cve,))
            return

        db_cursor.execute("DELETE FROM vulnerabilities WHERE cve_id = %s", (cve,))
        pytest.fail(
            "BUG #4: out-of-range CVSS was accepted — add CHECK (cvss_score BETWEEN 0 AND 10)"
        )
