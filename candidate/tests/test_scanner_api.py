"""Scanner Service API tests — aligned with http://localhost:8001/docs (OpenAPI)."""

from __future__ import annotations

import uuid

import pytest
import requests

pytestmark = pytest.mark.usefixtures("scanner_available")


def _u(base: str, path: str) -> str:
    p = path if path.startswith("/") else f"/{path}"
    return f"{base.rstrip('/')}{p}"


def assert_paginated_assets(body: dict) -> None:
    for key in ("items", "total", "page", "per_page", "pages"):
        assert key in body, f"missing {key}"
    assert isinstance(body["items"], list)


def assert_asset_response(item: dict) -> None:
    for key in ("id", "hostname", "asset_type", "environment", "is_active", "created_at"):
        assert key in item, f"missing {key}"


def assert_scan_response(item: dict) -> None:
    for key in (
        "id",
        "asset_id",
        "scanner_name",
        "status",
        "started_at",
        "findings_count",
    ):
        assert key in item, f"missing {key}"


class TestScannerHealth:
    def test_health_returns_service_metadata(self, scanner_base_url: str) -> None:
        r = requests.get(_u(scanner_base_url, "/health"), timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data.get("status") == "healthy"
        assert data.get("service") == "scanner-service"


class TestScannerAssetsList:
    def test_list_returns_paginated_structure(self, scanner_base_url: str) -> None:
        r = requests.get(
            _u(scanner_base_url, "/assets"),
            params={"page": 1, "per_page": 10},
            timeout=15,
        )
        assert r.status_code == 200
        body = r.json()
        assert_paginated_assets(body)
        if body["items"]:
            assert_asset_response(body["items"][0])

    def test_list_page_one_includes_first_asset_in_order(self, scanner_base_url: str) -> None:
        """Page 1 should start at the first row (lowest id), not skip it (see BUG #6)."""
        r = requests.get(
            _u(scanner_base_url, "/assets"),
            params={"page": 1, "per_page": 100},
            timeout=15,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["total"] >= 1
        ids = {a["id"] for a in body["items"]}
        assert 1 in ids

    def test_list_filter_by_environment_and_asset_type(self, scanner_base_url: str) -> None:
        r = requests.get(
            _u(scanner_base_url, "/assets"),
            params={
                "page": 1,
                "per_page": 50,
                "environment": "production",
                "asset_type": "server",
            },
            timeout=15,
        )
        assert r.status_code == 200
        for item in r.json()["items"]:
            assert item["environment"] == "production"
            assert item["asset_type"] == "server"

    def test_list_invalid_page_returns_422(self, scanner_base_url: str) -> None:
        r = requests.get(
            _u(scanner_base_url, "/assets"),
            params={"page": 0, "per_page": 10},
            timeout=15,
        )
        assert r.status_code == 422


class TestScannerAssetDetail:
    def test_get_existing_asset(self, scanner_base_url: str) -> None:
        r = requests.get(_u(scanner_base_url, "/assets/1"), timeout=15)
        assert r.status_code == 200
        assert_asset_response(r.json())
        assert r.json()["id"] == 1

    def test_get_nonexistent_returns_404(self, scanner_base_url: str) -> None:
        r = requests.get(_u(scanner_base_url, "/assets/999999"), timeout=15)
        assert r.status_code == 404


class TestScannerAssetWrite:
    def test_create_update_deactivate_flow(self, scanner_base_url: str) -> None:
        host = f"pytest-asset-{uuid.uuid4().hex[:12]}"
        create = requests.post(
            _u(scanner_base_url, "/assets"),
            json={
                "hostname": host,
                "ip_address": "10.99.0.1",
                "asset_type": "server",
                "environment": "staging",
                "os": "Test OS",
            },
            timeout=15,
        )
        assert create.status_code == 201
        created = create.json()
        aid = created["id"]
        assert created["hostname"] == host
        assert created["is_active"] is True

        upd = requests.put(
            _u(scanner_base_url, f"/assets/{aid}"),
            json={"hostname": f"{host}-renamed", "environment": "development"},
            timeout=15,
        )
        assert upd.status_code == 200
        assert upd.json()["hostname"] == f"{host}-renamed"
        assert upd.json()["environment"] == "development"

        de = requests.delete(_u(scanner_base_url, f"/assets/{aid}"), timeout=15)
        assert de.status_code == 204

        gone = requests.get(_u(scanner_base_url, f"/assets/{aid}"), timeout=15)
        assert gone.status_code == 404

    def test_create_invalid_asset_type_returns_422(self, scanner_base_url: str) -> None:
        r = requests.post(
            _u(scanner_base_url, "/assets"),
            json={
                "hostname": "bad-type",
                "asset_type": "invalid-type",
                "environment": "production",
            },
            timeout=15,
        )
        assert r.status_code == 422


class TestScannerScansList:
    def test_list_returns_paginated_structure(self, scanner_base_url: str) -> None:
        r = requests.get(
            _u(scanner_base_url, "/scans"),
            params={"page": 1, "per_page": 10},
            timeout=15,
        )
        assert r.status_code == 200
        body = r.json()
        for key in ("items", "total", "page", "per_page"):
            assert key in body
        if body["items"]:
            assert_scan_response(body["items"][0])

    def test_list_filter_by_asset_id(self, scanner_base_url: str) -> None:
        r = requests.get(
            _u(scanner_base_url, "/scans"),
            params={"page": 1, "per_page": 50, "asset_id": 1},
            timeout=15,
        )
        assert r.status_code == 200
        for item in r.json()["items"]:
            assert item["asset_id"] == 1


class TestScannerScanDetail:
    def test_get_existing_scan_matches_list_item(self, scanner_base_url: str) -> None:
        lst = requests.get(
            _u(scanner_base_url, "/scans"),
            params={"page": 1, "per_page": 1},
            timeout=15,
        )
        assert lst.status_code == 200
        items = lst.json()["items"]
        assert items, "expected at least one scan (seed data or earlier tests)"
        sid = items[0]["id"]
        r = requests.get(_u(scanner_base_url, f"/scans/{sid}"), timeout=15)
        assert r.status_code == 200
        body = r.json()
        assert_scan_response(body)
        assert body["id"] == sid

    def test_get_nonexistent_scan_returns_404(self, scanner_base_url: str) -> None:
        r = requests.get(_u(scanner_base_url, "/scans/999999"), timeout=15)
        assert r.status_code == 404


class TestScannerScanCreate:
    def test_create_scan_happy_path_counts_findings(self, scanner_base_url: str) -> None:
        r = requests.post(
            _u(scanner_base_url, "/scans"),
            json={
                "asset_id": 1,
                "scanner_name": "OpenAPITest",
                "vulnerability_ids": [1, 2],
            },
            timeout=15,
        )
        assert r.status_code == 201
        body = r.json()
        assert_scan_response(body)
        assert body["status"] == "completed"
        assert body["findings_count"] == 2
        assert body["scanner_name"] == "OpenAPITest"

    def test_create_scan_unknown_asset_returns_400(self, scanner_base_url: str) -> None:
        r = requests.post(
            _u(scanner_base_url, "/scans"),
            json={
                "asset_id": 999_999,
                "scanner_name": "NoAsset",
                "vulnerability_ids": [1],
            },
            timeout=15,
        )
        assert r.status_code == 400
        assert "asset" in r.json()["detail"].lower()

    def test_create_scan_empty_vulnerabilities_zero_findings(self, scanner_base_url: str) -> None:
        r = requests.post(
            _u(scanner_base_url, "/scans"),
            json={
                "asset_id": 1,
                "scanner_name": "EmptyVulns",
                "vulnerability_ids": [],
            },
            timeout=15,
        )
        assert r.status_code == 201
        assert r.json()["findings_count"] == 0

    def test_create_scan_skips_unknown_vulnerability_ids(self, scanner_base_url: str) -> None:
        r = requests.post(
            _u(scanner_base_url, "/scans"),
            json={
                "asset_id": 1,
                "scanner_name": "SkipBadVuln",
                "vulnerability_ids": [999_999, 1],
            },
            timeout=15,
        )
        assert r.status_code == 201
        assert r.json()["findings_count"] == 1

    def test_create_scan_inactive_asset_returns_400(self, scanner_base_url: str) -> None:
        host = f"pytest-inactive-{uuid.uuid4().hex[:12]}"
        c = requests.post(
            _u(scanner_base_url, "/assets"),
            json={
                "hostname": host,
                "asset_type": "server",
                "environment": "staging",
            },
            timeout=15,
        )
        assert c.status_code == 201
        aid = c.json()["id"]
        requests.delete(_u(scanner_base_url, f"/assets/{aid}"), timeout=15)

        r = requests.post(
            _u(scanner_base_url, "/scans"),
            json={
                "asset_id": aid,
                "scanner_name": "Inactive",
                "vulnerability_ids": [1],
            },
            timeout=15,
        )
        assert r.status_code == 400

    def test_create_scan_invalid_body_returns_422(self, scanner_base_url: str) -> None:
        r = requests.post(
            _u(scanner_base_url, "/scans"),
            json={
                "asset_id": 1,
                "scanner_name": "",
                "vulnerability_ids": [],
            },
            timeout=15,
        )
        assert r.status_code == 422
