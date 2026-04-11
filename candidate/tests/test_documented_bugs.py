"""Expected-correctness tests for known issues (BUG #1–#8 and related).

These assertions describe how the system **should** behave. They **fail** on the
current codebase until each bug is fixed; when a test turns green, that bug is
addressed for that behavior.

Run: ``pytest tests/test_documented_bugs.py`` (expect failures until fixes land).
"""

from __future__ import annotations

import uuid

import pytest
import requests


def _findings(base: str, suffix: str = "") -> str:
    return f"{base}/findings{suffix}"


@pytest.mark.usefixtures("dashboard_available")
class TestDismissedFindingNotExposedByGetDetail:
    """BUG #1: GET /findings/{id} should not return soft-deleted (dismissed) findings."""

    def test_get_dismissed_finding_returns_404(self, dashboard_base_url: str) -> None:
        payload = {
            "asset_id": 3,
            "vulnerability_id": 4,
            "scanner": "pytest-bug1",
            "notes": "dismiss then get",
        }
        c = requests.post(_findings(dashboard_base_url), json=payload, timeout=15)
        assert c.status_code == 201
        fid = c.json()["id"]

        requests.delete(_findings(dashboard_base_url, f"/{fid}"), timeout=15)

        r = requests.get(_findings(dashboard_base_url, f"/{fid}"), timeout=15)
        assert r.status_code == 404


@pytest.mark.usefixtures("dashboard_available")
class TestStatusWorkflowEnforced:
    """BUG #2: Invalid transitions (e.g. resolved → open) should be rejected."""

    def test_resolved_to_open_returns_400(self, dashboard_base_url: str) -> None:
        payload = {
            "asset_id": 3,
            "vulnerability_id": 4,
            "scanner": "pytest-bug2",
            "notes": "workflow",
        }
        c = requests.post(_findings(dashboard_base_url), json=payload, timeout=15)
        assert c.status_code == 201
        fid = c.json()["id"]

        r1 = requests.put(
            _findings(dashboard_base_url, f"/{fid}/status"),
            json={"status": "resolved"},
            timeout=15,
        )
        assert r1.status_code == 200

        r2 = requests.put(
            _findings(dashboard_base_url, f"/{fid}/status"),
            json={"status": "open"},
            timeout=15,
        )
        assert r2.status_code == 400


@pytest.mark.usefixtures("dashboard_available")
class TestSearchIsSafeAndParameterized:
    """BUG #3: Search must not crash or inject SQL; quotes are literal in LIKE."""

    def test_search_with_single_quote_returns_200(self, dashboard_base_url: str) -> None:
        r = requests.get(
            _findings(dashboard_base_url, "/search"),
            params={"q": "x'"},
            timeout=15,
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_search_normal_query_succeeds(self, dashboard_base_url: str) -> None:
        r = requests.get(
            _findings(dashboard_base_url, "/search"),
            params={"q": "CVE"},
            timeout=15,
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)


@pytest.mark.usefixtures("dashboard_available")
class TestAssetListPaginationComplete:
    """BUG #6: Page 1 must include every asset from the start of the ordered list."""

    def test_first_page_includes_lowest_id_asset(self, scanner_base_url: str) -> None:
        r = requests.get(
            f"{scanner_base_url}/assets",
            params={"page": 1, "per_page": 100},
            timeout=15,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["total"] >= 1
        ids = {a["id"] for a in body["items"]}
        assert 1 in ids


@pytest.mark.usefixtures("dashboard_available", "scanner_available")
class TestScansDoNotCreateDuplicateFindings:
    """BUG #7: If a finding already exists for (asset, vuln), rescans should not insert more."""

    def test_two_identical_scans_do_not_increase_count_when_pair_already_exists(
        self,
        dashboard_base_url: str,
        scanner_base_url: str,
    ) -> None:
        list_params = {"asset_id": 1, "per_page": 100}
        before = requests.get(
            _findings(dashboard_base_url),
            params=list_params,
            timeout=15,
        )
        assert before.status_code == 200
        n_before = sum(
            1 for x in before.json()["items"] if x["vulnerability_id"] == 10
        )
        assert n_before >= 1, "seed should include asset 1 + vuln 10; adjust test data if empty"

        payload = {
            "asset_id": 1,
            "scanner_name": "DedupeCheck",
            "vulnerability_ids": [10],
        }
        r1 = requests.post(f"{scanner_base_url}/scans", json=payload, timeout=15)
        r2 = requests.post(f"{scanner_base_url}/scans", json=payload, timeout=15)
        assert r1.status_code == 201 and r2.status_code == 201

        after = requests.get(
            _findings(dashboard_base_url),
            params=list_params,
            timeout=15,
        )
        assert after.status_code == 200
        n_after = sum(
            1 for x in after.json()["items"] if x["vulnerability_id"] == 10
        )
        assert n_after == n_before


@pytest.mark.usefixtures("dashboard_available")
class TestSearchExcludesDismissedFindings:
    """Dismissed findings must not appear in /findings/search."""

    def test_search_does_not_return_dismissed_finding(self, dashboard_base_url: str) -> None:
        token = f"DISMISS_SEARCH_{uuid.uuid4().hex[:10]}"
        payload = {
            "asset_id": 3,
            "vulnerability_id": 4,
            "scanner": "pytest-search-dismiss",
            "notes": token,
        }
        c = requests.post(_findings(dashboard_base_url), json=payload, timeout=15)
        assert c.status_code == 201
        fid = c.json()["id"]

        requests.delete(_findings(dashboard_base_url, f"/{fid}"), timeout=15)

        sr = requests.get(
            _findings(dashboard_base_url, "/search"),
            params={"q": token},
            timeout=15,
        )
        assert sr.status_code == 200
        ids = {row["finding_id"] for row in sr.json()}
        assert fid not in ids


@pytest.mark.usefixtures("dashboard_available", "scanner_available")
class TestCreateFindingRejectsInactiveAsset:
    """Manual create should reject inactive assets (same rule as scanner)."""

    def test_create_finding_on_deactivated_asset_returns_400(
        self,
        dashboard_base_url: str,
        scanner_base_url: str,
    ) -> None:
        host = f"inactive-{uuid.uuid4().hex[:12]}"
        c = requests.post(
            f"{scanner_base_url}/assets",
            json={
                "hostname": host,
                "asset_type": "server",
                "environment": "staging",
            },
            timeout=15,
        )
        assert c.status_code == 201
        aid = c.json()["id"]
        requests.delete(f"{scanner_base_url}/assets/{aid}", timeout=15)

        r = requests.post(
            _findings(dashboard_base_url),
            json={
                "asset_id": aid,
                "vulnerability_id": 1,
                "scanner": "dash-after-delete",
                "notes": "inactive asset",
            },
            timeout=15,
        )
        assert r.status_code == 400


@pytest.mark.usefixtures("scanner_available")
class TestScannerExposesCorsForDashboardOrigin:
    """Browser UI on :8000 must be allowed to call scanner API."""

    def test_health_includes_access_control_allow_origin_for_dashboard(
        self,
        scanner_base_url: str,
    ) -> None:
        r = requests.get(
            f"{scanner_base_url}/health",
            headers={"Origin": "http://localhost:8000"},
            timeout=10,
        )
        assert r.status_code == 200
        acao = r.headers.get("access-control-allow-origin")
        assert acao in ("http://localhost:8000", "*")


@pytest.mark.usefixtures("dashboard_available", "postgres_available")
class TestVulnerabilityCatalogOrdersNullCvssLast:
    """NULL CVSS should not appear before real scores when sorting by CVSS DESC."""

    def test_null_cvss_not_first_when_other_rows_have_scores(
        self,
        dashboard_base_url: str,
        db_cursor,
    ) -> None:
        cve = "CVE-BUG-NULL-CVSS"
        db_cursor.execute("DELETE FROM vulnerabilities WHERE cve_id = %s", (cve,))
        db_cursor.execute(
            """
            INSERT INTO vulnerabilities (cve_id, title, severity, cvss_score)
            VALUES (%s, 'null cvss row', 'low', NULL)
            """,
            (cve,),
        )
        try:
            r = requests.get(f"{dashboard_base_url}/vulnerabilities", timeout=15)
            assert r.status_code == 200
            data = r.json()
            assert data
            first = data[0]
            assert first["cvss_score"] is not None
        finally:
            db_cursor.execute("DELETE FROM vulnerabilities WHERE cve_id = %s", (cve,))
