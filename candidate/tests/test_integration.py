"""
Part 3 — Integration Testing: Cross-service flows (scan → findings),
concurrent scan imports, and data consistency.
"""
import pytest
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

DASHBOARD_API = "http://localhost:8000"
SCANNER_API = "http://localhost:8001"


# ═══════════════════════════ Scan → Findings Flow ═══════════════════════════


class TestScanToFindingsFlow:
    def test_scan_creates_findings(self, scanner_api, api):
        """Running a scan via Scanner Service should create findings visible in Dashboard API."""
        # Create a fresh asset for isolation
        asset_resp = scanner_api.post("/assets", json={
            "hostname": "integration-test-host",
            "ip_address": "10.99.0.1",
            "asset_type": "server",
            "environment": "development",
            "os": "Ubuntu 22.04",
        })
        assert asset_resp.status_code == 201
        asset_id = asset_resp.json()["id"]

        # Run scan with 2 known vulnerability IDs
        scan_resp = scanner_api.post("/scans", json={
            "asset_id": asset_id,
            "scanner_name": "IntegrationTest",
            "vulnerability_ids": [1, 3],
        })
        assert scan_resp.status_code == 201
        scan_data = scan_resp.json()
        assert scan_data["status"] == "completed"
        assert scan_data["findings_count"] == 2

        # Verify findings appear in dashboard API
        findings_resp = api.get("/findings", params={"asset_id": asset_id, "per_page": 50})
        assert findings_resp.status_code == 200
        findings = findings_resp.json()["items"]
        assert len(findings) >= 2

        vuln_ids_found = {f["vulnerability_id"] for f in findings}
        assert 1 in vuln_ids_found, "Finding for vulnerability 1 not created"
        assert 3 in vuln_ids_found, "Finding for vulnerability 3 not created"

        # All findings from this scan should be 'open'
        for f in findings:
            assert f["status"] == "open"
            assert f["scanner"] == "IntegrationTest"

        # Cleanup
        scanner_api.delete(f"/assets/{asset_id}")

    def test_scan_with_invalid_asset_rejected(self, scanner_api):
        resp = scanner_api.post("/scans", json={
            "asset_id": 99999,
            "scanner_name": "TestScanner",
            "vulnerability_ids": [1],
        })
        assert resp.status_code == 400

    def test_scan_with_invalid_vuln_ids_skipped(self, scanner_api):
        """Scan should skip non-existent vulnerability IDs gracefully."""
        resp = scanner_api.post("/scans", json={
            "asset_id": 1,
            "scanner_name": "TestScanner",
            "vulnerability_ids": [99999],
        })
        assert resp.status_code == 201
        assert resp.json()["findings_count"] == 0

    def test_scan_record_stored_correctly(self, scanner_api):
        """Verify scan metadata is persisted."""
        resp = scanner_api.post("/scans", json={
            "asset_id": 3,
            "scanner_name": "ScanRecordTest",
            "vulnerability_ids": [2],
        })
        scan_id = resp.json()["id"]

        detail = scanner_api.get(f"/scans/{scan_id}")
        assert detail.status_code == 200
        data = detail.json()
        assert data["scanner_name"] == "ScanRecordTest"
        assert data["asset_id"] == 3
        assert data["status"] == "completed"
        assert data["completed_at"] is not None


# ═══════════════════════════ Status Update → DB ═══════════════════════════


class TestStatusUpdateFlow:
    def test_full_finding_lifecycle(self, api, created_findings):
        """Walk a finding through the full expected lifecycle."""
        # Create
        resp = api.post("/findings", json={
            "asset_id": 1, "vulnerability_id": 5, "scanner": "lifecycle-test"
        })
        finding_id = resp.json()["id"]
        created_findings.append(finding_id)
        assert resp.json()["status"] == "open"

        # open → confirmed
        resp = api.put(f"/findings/{finding_id}/status", json={
            "status": "confirmed", "notes": "Verified by team"
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "confirmed"

        # confirmed → in_progress
        resp = api.put(f"/findings/{finding_id}/status", json={
            "status": "in_progress", "notes": "Patch being applied"
        })
        assert resp.json()["status"] == "in_progress"

        # in_progress → resolved
        resp = api.put(f"/findings/{finding_id}/status", json={
            "status": "resolved", "notes": "Patch deployed"
        })
        assert resp.json()["status"] == "resolved"
        assert resp.json()["resolved_at"] is not None

        # Verify in summary stats
        summary = api.get("/stats/summary").json()
        assert summary["resolved_findings"] > 0


# ═══════════════════════════ Duplicate / Concurrency ═══════════════════════════


class TestDuplicateFindings:
    def test_repeated_scan_creates_duplicates(self, scanner_api, api, db):
        """
        BUG #7 DETECTED: Running the same scan twice creates duplicate findings.
        There should be a unique constraint on (asset_id, vulnerability_id)
        or the scan should check for existing findings.
        """
        # Use asset 5 (dev-backend-01) and a vuln we know about
        asset_id = 5
        vuln_id = 9  # GnuTLS — not already linked to asset 5 in seed

        # Count existing findings for this combo
        db.execute(
            "SELECT COUNT(*) as cnt FROM findings "
            "WHERE asset_id = %s AND vulnerability_id = %s AND is_dismissed = FALSE",
            (asset_id, vuln_id),
        )
        before = db.fetchone()["cnt"]

        # Run scan twice
        for _ in range(2):
            scanner_api.post("/scans", json={
                "asset_id": asset_id,
                "scanner_name": "DuplicateTest",
                "vulnerability_ids": [vuln_id],
            })

        # Check count after
        db.execute(
            "SELECT COUNT(*) as cnt FROM findings "
            "WHERE asset_id = %s AND vulnerability_id = %s AND is_dismissed = FALSE",
            (asset_id, vuln_id),
        )
        after = db.fetchone()["cnt"]

        new_findings = after - before
        assert new_findings <= 1, (
            f"BUG: {new_findings} findings created for same asset/vuln combo. "
            f"Expected at most 1. Duplicate findings are not prevented."
        )

    def test_concurrent_scans_create_duplicates(self, scanner_api, db):
        """
        BUG #7 continuation: Concurrent scan requests should not
        create duplicate findings for the same asset + vulnerability.
        """
        asset_id = 4  # k8s-payments
        vuln_id = 6   # curl vuln — pick one not linked to asset 4

        # Count before
        db.execute(
            "SELECT COUNT(*) as cnt FROM findings "
            "WHERE asset_id = %s AND vulnerability_id = %s",
            (asset_id, vuln_id),
        )
        before = db.fetchone()["cnt"]

        # Send 5 concurrent scan requests
        def run_scan():
            return requests.post(f"{SCANNER_API}/scans", json={
                "asset_id": asset_id,
                "scanner_name": "ConcurrentTest",
                "vulnerability_ids": [vuln_id],
            })

        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(run_scan) for _ in range(5)]
            results = [f.result() for f in as_completed(futures)]

        # All should succeed (201)
        for r in results:
            assert r.status_code == 201

        # But only 1 new finding should exist
        db.execute(
            "SELECT COUNT(*) as cnt FROM findings "
            "WHERE asset_id = %s AND vulnerability_id = %s",
            (asset_id, vuln_id),
        )
        after = db.fetchone()["cnt"]
        new_findings = after - before

        assert new_findings <= 1, (
            f"BUG: {new_findings} duplicate findings created by concurrent scans. "
            f"Expected at most 1. Race condition: no unique constraint or locking."
        )


# ═══════════════════════════ Assets (Scanner Service) ═══════════════════════════


class TestAssetsApi:
    def test_list_assets(self, scanner_api):
        resp = scanner_api.get("/assets")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data

    def test_asset_pagination_total_matches_actual(self, scanner_api):
        """
        BUG #6 DETECTED: Pagination off-by-one — total says 6 but
        only 5 items returned on page 1.
        """
        resp = scanner_api.get("/assets", params={"per_page": 50})
        data = resp.json()
        assert len(data["items"]) == data["total"], (
            f"BUG: Pagination says total={data['total']} but returned "
            f"{len(data['items'])} items. Off-by-one in offset calculation."
        )

    def test_create_and_get_asset(self, scanner_api, created_assets):
        resp = scanner_api.post("/assets", json={
            "hostname": "test-asset-crud",
            "ip_address": "192.168.1.100",
            "asset_type": "server",
            "environment": "development",
            "os": "CentOS 9",
        })
        assert resp.status_code == 201
        asset_id = resp.json()["id"]
        created_assets.append(asset_id)

        get_resp = scanner_api.get(f"/assets/{asset_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["hostname"] == "test-asset-crud"

    def test_deactivate_asset(self, scanner_api, created_assets):
        resp = scanner_api.post("/assets", json={
            "hostname": "to-delete",
            "asset_type": "container",
            "environment": "staging",
        })
        asset_id = resp.json()["id"]
        created_assets.append(asset_id)

        del_resp = scanner_api.delete(f"/assets/{asset_id}")
        assert del_resp.status_code == 204

        get_resp = scanner_api.get(f"/assets/{asset_id}")
        assert get_resp.status_code == 404

    def test_filter_assets_by_environment(self, scanner_api):
        resp = scanner_api.get("/assets", params={"environment": "production", "per_page": 50})
        assert resp.status_code == 200
        for asset in resp.json()["items"]:
            assert asset["environment"] == "production"
