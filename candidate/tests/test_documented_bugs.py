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

pytestmark = [pytest.mark.known_bug]


def _findings(base: str, suffix: str = "") -> str:
    return f"{base}/findings{suffix}"


@pytest.mark.usefixtures("dashboard_available")
class TestDismissedFindingNotExposedByGetDetail:
    """BUG #1: GET /findings/{id} should not return soft-deleted (dismissed) findings."""

    @pytest.mark.xfail(reason="BUG #1: dismissed finding still accessible by id", strict=False)
    def test_get_dismissed_finding_returns_404(self, dashboard_base_url: str, api_testdata) -> None:
        asset = api_testdata.create_asset()
        created = api_testdata.create_finding(asset_id=asset["id"], scanner="pytest-bug1", notes="dismiss then get")
        fid = created["id"]

        requests.delete(_findings(dashboard_base_url, f"/{fid}"), timeout=15)

        r = requests.get(_findings(dashboard_base_url, f"/{fid}"), timeout=15)
        assert r.status_code == 404


@pytest.mark.usefixtures("dashboard_available")
class TestStatusWorkflowEnforced:
    """BUG #2: Invalid transitions (e.g. resolved → open) should be rejected."""

    @pytest.mark.xfail(reason="BUG #2: invalid status transitions are accepted", strict=False)
    def test_resolved_to_open_returns_400(self, dashboard_base_url: str, api_testdata) -> None:
        asset = api_testdata.create_asset()
        created = api_testdata.create_finding(asset_id=asset["id"], scanner="pytest-bug2", notes="workflow")
        fid = created["id"]

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

    @pytest.mark.xfail(reason="BUG #3: single-quote query can crash search (HTTP 500)", strict=False)
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

    @pytest.mark.xfail(reason="BUG #6: first page may skip lowest id", strict=False)
    def test_first_page_includes_lowest_id_asset(self, scanner_base_url: str, db_cursor, db_testdata) -> None:
        db_testdata.create_asset()
        db_cursor.execute("SELECT MIN(id) FROM assets WHERE is_active = TRUE")
        (min_id,) = db_cursor.fetchone()
        assert min_id is not None
        r = requests.get(
            f"{scanner_base_url}/assets",
            params={"page": 1, "per_page": 100},
            timeout=15,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["total"] >= 1
        ids = {a["id"] for a in body["items"]}
        assert int(min_id) in ids


@pytest.mark.usefixtures("dashboard_available", "scanner_available")
class TestScansDoNotCreateDuplicateFindings:
    """BUG #7: If a finding already exists for (asset, vuln), rescans should not insert more."""

    @pytest.mark.xfail(reason="BUG #7: rescans can insert duplicate findings", strict=False)
    def test_two_identical_scans_do_not_increase_count_when_pair_already_exists(
        self,
        dashboard_base_url: str,
        scanner_base_url: str,
        db_testdata,
    ) -> None:
        asset = db_testdata.create_asset()
        vuln = db_testdata.create_vulnerability(severity="high")
        db_testdata.create_finding(asset_id=asset["id"], vulnerability_id=vuln["id"], scanner="precreate", notes="seed pair")

        list_params = {"asset_id": asset["id"], "per_page": 100}
        before = requests.get(_findings(dashboard_base_url), params=list_params, timeout=15)
        assert before.status_code == 200
        n_before = sum(1 for x in before.json()["items"] if x["vulnerability_id"] == vuln["id"])
        assert n_before >= 1

        payload = {
            "asset_id": asset["id"],
            "scanner_name": "DedupeCheck",
            "vulnerability_ids": [vuln["id"]],
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
        n_after = sum(1 for x in after.json()["items"] if x["vulnerability_id"] == vuln["id"])
        assert n_after == n_before


@pytest.mark.usefixtures("dashboard_available")
class TestSearchExcludesDismissedFindings:
    """Dismissed findings must not appear in /findings/search."""

    @pytest.mark.xfail(reason="Dismissed findings may still appear in search", strict=False)
    def test_search_does_not_return_dismissed_finding(self, dashboard_base_url: str, api_testdata) -> None:
        token = f"DISMISS_SEARCH_{uuid.uuid4().hex[:10]}"
        asset = api_testdata.create_asset()
        created = api_testdata.create_finding(asset_id=asset["id"], scanner="pytest-search-dismiss", notes=token)
        fid = created["id"]

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

    @pytest.mark.xfail(reason="Manual create may allow inactive asset", strict=False)
    def test_create_finding_on_deactivated_asset_returns_400(
        self,
        dashboard_base_url: str,
        scanner_base_url: str,
        api_testdata,
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
                "vulnerability_id": api_testdata.any_vulnerability_id(),
                "scanner": "dash-after-delete",
                "notes": "inactive asset",
            },
            timeout=15,
        )
        assert r.status_code == 400


@pytest.mark.usefixtures("scanner_available")
class TestScannerExposesCorsForDashboardOrigin:
    """Browser UI on :8000 must be allowed to call scanner API."""

    @pytest.mark.xfail(reason="BUG: scanner health missing CORS allow-origin header", strict=False)
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

    @pytest.mark.xfail(reason="BUG: vulnerability list can sort NULL CVSS first", strict=False)
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
