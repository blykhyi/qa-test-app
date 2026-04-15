"""Part 3 — Integration: Scanner → Dashboard, status ↔ DB, concurrent scans."""

from __future__ import annotations

import concurrent.futures

import pytest
import requests

pytestmark = [
    pytest.mark.integration,
    pytest.mark.usefixtures("dashboard_available"),
    pytest.mark.usefixtures("scanner_available"),
]


def _dashboard_findings_url(base: str, suffix: str = "") -> str:
    return f"{base}/findings{suffix}"


def _count_open_findings_for_asset_vuln(
    dashboard_base_url: str,
    asset_id: int,
    vulnerability_id: int,
) -> int:
    r = requests.get(
        _dashboard_findings_url(dashboard_base_url),
        params={"asset_id": asset_id, "per_page": 100},
        timeout=15,
    )
    assert r.status_code == 200
    return sum(
        1
        for x in r.json()["items"]
        if x["vulnerability_id"] == vulnerability_id
    )


class TestScannerToDashboard:
    def test_scan_creates_findings_visible_in_dashboard(
        self,
        dashboard_base_url: str,
        scanner_base_url: str,
        db_testdata,
    ) -> None:
        asset = db_testdata.create_asset()
        vuln = db_testdata.create_vulnerability(severity="medium")
        before = _count_open_findings_for_asset_vuln(
            dashboard_base_url,
            asset["id"],
            vuln["id"],
        )

        payload = {
            "asset_id": asset["id"],
            "scanner_name": "IntegrationNessus",
            "vulnerability_ids": [vuln["id"]],
        }
        r = requests.post(f"{scanner_base_url}/scans", json=payload, timeout=15)
        assert r.status_code == 201
        scan = r.json()
        assert scan["findings_count"] == 1
        assert scan["status"] == "completed"

        after = _count_open_findings_for_asset_vuln(
            dashboard_base_url,
            asset["id"],
            vuln["id"],
        )
        assert after == before + 1

        lst = requests.get(
            _dashboard_findings_url(dashboard_base_url),
            params={"asset_id": asset["id"], "per_page": 100},
            timeout=15,
        ).json()["items"]
        matches = [
            x
            for x in lst
            if x["vulnerability_id"] == vuln["id"]
            and x.get("scanner") == "IntegrationNessus"
        ]
        assert matches


class TestStatusUpdateMatchesDatabase:
    @pytest.mark.usefixtures("postgres_available")
    @pytest.mark.db
    def test_update_status_after_scan_matches_postgres(
        self,
        dashboard_base_url: str,
        scanner_base_url: str,
        db_cursor,
        db_testdata,
    ) -> None:
        asset = db_testdata.create_asset()
        vuln = db_testdata.create_vulnerability(severity="low")
        payload = {
            "asset_id": asset["id"],
            "scanner_name": "Integration-Status",
            "vulnerability_ids": [vuln["id"]],
        }
        r = requests.post(f"{scanner_base_url}/scans", json=payload, timeout=15)
        assert r.status_code == 201

        lst = requests.get(
            _dashboard_findings_url(dashboard_base_url),
            params={"asset_id": asset["id"], "per_page": 100},
            timeout=15,
        )
        items = lst.json()["items"]
        candidates = [
            x
            for x in items
            if x["vulnerability_id"] == vuln["id"] and x.get("scanner") == "Integration-Status"
        ]
        assert candidates, "expected a finding from the scan in Dashboard list"
        fid = max(x["id"] for x in candidates)

        upd = requests.put(
            _dashboard_findings_url(dashboard_base_url, f"/{fid}/status"),
            json={"status": "confirmed"},
            timeout=15,
        )
        assert upd.status_code == 200

        db_cursor.execute("SELECT status FROM findings WHERE id = %s", (fid,))
        (status,) = db_cursor.fetchone()
        assert status == "confirmed"


class TestConcurrentScans:
    @pytest.mark.known_bug
    @pytest.mark.xfail(reason="BUG #7: duplicates can be inserted under concurrency", strict=False)
    def test_concurrent_scans_should_not_double_insert_same_finding(
        self,
        dashboard_base_url: str,
        scanner_base_url: str,
        db_testdata,
    ) -> None:
        """BUG #7: Even under concurrency, at most one new row per (asset, vuln) if already present."""
        asset = db_testdata.create_asset()
        vuln = db_testdata.create_vulnerability(severity="high")
        before = _count_open_findings_for_asset_vuln(
            dashboard_base_url,
            asset["id"],
            vuln["id"],
        )

        payload = {
            "asset_id": asset["id"],
            "scanner_name": "ConcurrentProbe",
            "vulnerability_ids": [vuln["id"]],
        }

        def post_scan():
            return requests.post(f"{scanner_base_url}/scans", json=payload, timeout=30)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(post_scan) for _ in range(2)]
            results = [f.result() for f in futures]

        for res in results:
            assert res.status_code == 201

        after = _count_open_findings_for_asset_vuln(
            dashboard_base_url,
            asset["id"],
            vuln["id"],
        )
        assert after == before + 1
