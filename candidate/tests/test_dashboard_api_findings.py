"""Part 1 — Dashboard API tests: findings CRUD, errors, search, pagination."""

from __future__ import annotations

import pytest
import requests

pytestmark = pytest.mark.usefixtures("dashboard_available")

# Seed data: see db/init.sql — any existing asset (1–6) and vulnerability (1–10)
SEED_ASSET_ID = 3
SEED_VULNERABILITY_ID = 4


def _findings_url(base: str, suffix: str = "") -> str:
    return f"{base}/findings{suffix}"


def assert_finding_response_shape(data: dict) -> None:
    required = {
        "id",
        "asset_id",
        "vulnerability_id",
        "status",
        "detected_at",
        "scanner",
        "notes",
        "is_dismissed",
    }
    missing = required - set(data.keys())
    assert not missing, f"Missing keys: {missing}"


def assert_finding_detail_shape(data: dict) -> None:
    assert_finding_response_shape(data)
    assert "vulnerability" in data
    assert "asset_hostname" in data
    if data["vulnerability"] is not None:
        v = data["vulnerability"]
        for key in ("id", "cve_id", "title", "severity", "created_at"):
            assert key in v, f"vulnerability missing {key}"


class TestListFindings:
    def test_list_returns_paginated_structure(self, dashboard_base_url: str) -> None:
        r = requests.get(
            _findings_url(dashboard_base_url),
            params={"page": 1, "per_page": 10},
            timeout=15,
        )
        assert r.status_code == 200
        body = r.json()
        assert "items" in body and isinstance(body["items"], list)
        assert "total" in body and isinstance(body["total"], int)
        assert body["page"] == 1
        assert body["per_page"] == 10
        if body["items"]:
            assert_finding_response_shape(body["items"][0])

    def test_list_filter_by_status(self, dashboard_base_url: str) -> None:
        r = requests.get(
            _findings_url(dashboard_base_url),
            params={"status": "open", "per_page": 50},
            timeout=15,
        )
        assert r.status_code == 200
        for item in r.json()["items"]:
            assert item["status"] == "open"

    def test_list_filter_by_severity(self, dashboard_base_url: str) -> None:
        r = requests.get(
            _findings_url(dashboard_base_url),
            params={"severity": "critical", "per_page": 50},
            timeout=15,
        )
        assert r.status_code == 200
        # Detail not in list response — spot-check via GET detail for first item
        items = r.json()["items"]
        assert isinstance(items, list)
        if items:
            fid = items[0]["id"]
            d = requests.get(_findings_url(dashboard_base_url, f"/{fid}"), timeout=15)
            assert d.status_code == 200
            assert d.json()["vulnerability"]["severity"] == "critical"

    def test_list_filter_by_asset_id(self, dashboard_base_url: str) -> None:
        r = requests.get(
            _findings_url(dashboard_base_url),
            params={"asset_id": 1, "per_page": 50},
            timeout=15,
        )
        assert r.status_code == 200
        for item in r.json()["items"]:
            assert item["asset_id"] == 1


class TestPaginationValidation:
    def test_page_below_minimum_returns_422(self, dashboard_base_url: str) -> None:
        r = requests.get(
            _findings_url(dashboard_base_url),
            params={"page": 0, "per_page": 10},
            timeout=15,
        )
        assert r.status_code == 422

    def test_per_page_above_max_returns_422(self, dashboard_base_url: str) -> None:
        r = requests.get(
            _findings_url(dashboard_base_url),
            params={"page": 1, "per_page": 101},
            timeout=15,
        )
        assert r.status_code == 422

    def test_per_page_below_minimum_returns_422(self, dashboard_base_url: str) -> None:
        r = requests.get(
            _findings_url(dashboard_base_url),
            params={"page": 1, "per_page": 0},
            timeout=15,
        )
        assert r.status_code == 422


class TestGetFinding:
    def test_get_existing_returns_detail(self, dashboard_base_url: str) -> None:
        lst = requests.get(
            _findings_url(dashboard_base_url),
            params={"per_page": 1},
            timeout=15,
        )
        assert lst.status_code == 200
        items = lst.json()["items"]
        assert items, "seed data should include at least one finding"
        fid = items[0]["id"]

        r = requests.get(_findings_url(dashboard_base_url, f"/{fid}"), timeout=15)
        assert r.status_code == 200
        body = r.json()
        assert_finding_detail_shape(body)
        assert body["id"] == fid

    def test_get_nonexistent_returns_404(self, dashboard_base_url: str) -> None:
        r = requests.get(_findings_url(dashboard_base_url, "/999999"), timeout=15)
        assert r.status_code == 404
        assert "detail" in r.json()


class TestCreateFinding:
    def test_create_valid_returns_201_and_open_status(self, dashboard_base_url: str) -> None:
        payload = {
            "asset_id": SEED_ASSET_ID,
            "vulnerability_id": SEED_VULNERABILITY_ID,
            "scanner": "pytest-api",
            "notes": "Created by automated API test",
        }
        r = requests.post(_findings_url(dashboard_base_url), json=payload, timeout=15)
        assert r.status_code == 201
        body = r.json()
        assert_finding_response_shape(body)
        assert body["status"] == "open"
        assert body["asset_id"] == SEED_ASSET_ID
        assert body["vulnerability_id"] == SEED_VULNERABILITY_ID
        assert body["scanner"] == "pytest-api"
        assert body["notes"] == "Created by automated API test"
        assert body["is_dismissed"] is False

    def test_create_unknown_asset_returns_400(self, dashboard_base_url: str) -> None:
        payload = {
            "asset_id": 999999,
            "vulnerability_id": SEED_VULNERABILITY_ID,
        }
        r = requests.post(_findings_url(dashboard_base_url), json=payload, timeout=15)
        assert r.status_code == 400
        assert "asset" in r.json()["detail"].lower()

    def test_create_unknown_vulnerability_returns_400(self, dashboard_base_url: str) -> None:
        payload = {
            "asset_id": SEED_ASSET_ID,
            "vulnerability_id": 999999,
        }
        r = requests.post(_findings_url(dashboard_base_url), json=payload, timeout=15)
        assert r.status_code == 400
        assert "vulnerability" in r.json()["detail"].lower()


class TestUpdateFindingStatus:
    def test_update_status_valid(self, dashboard_base_url: str) -> None:
        payload_create = {
            "asset_id": SEED_ASSET_ID,
            "vulnerability_id": SEED_VULNERABILITY_ID,
            "scanner": "pytest-status",
            "notes": "status test",
        }
        created = requests.post(
            _findings_url(dashboard_base_url),
            json=payload_create,
            timeout=15,
        )
        assert created.status_code == 201
        fid = created.json()["id"]

        upd = requests.put(
            _findings_url(dashboard_base_url, f"/{fid}/status"),
            json={"status": "confirmed", "notes": "Verified"},
            timeout=15,
        )
        assert upd.status_code == 200
        body = upd.json()
        assert body["status"] == "confirmed"
        assert body["notes"] == "Verified"

    def test_update_status_invalid_value_returns_400(self, dashboard_base_url: str) -> None:
        lst = requests.get(
            _findings_url(dashboard_base_url),
            params={"per_page": 1},
            timeout=15,
        )
        fid = lst.json()["items"][0]["id"]
        r = requests.put(
            _findings_url(dashboard_base_url, f"/{fid}/status"),
            json={"status": "not_a_real_status"},
            timeout=15,
        )
        assert r.status_code == 400
        detail = r.json().get("detail", "")
        assert isinstance(detail, str)
        assert "status" in detail.lower()

    def test_update_nonexistent_finding_returns_404(self, dashboard_base_url: str) -> None:
        r = requests.put(
            _findings_url(dashboard_base_url, "/999999/status"),
            json={"status": "confirmed"},
            timeout=15,
        )
        assert r.status_code == 404


class TestDismissFinding:
    def test_dismiss_returns_204_and_excludes_from_list(self, dashboard_base_url: str) -> None:
        payload_create = {
            "asset_id": SEED_ASSET_ID,
            "vulnerability_id": SEED_VULNERABILITY_ID,
            "scanner": "pytest-dismiss",
            "notes": "dismiss flow",
        }
        created = requests.post(
            _findings_url(dashboard_base_url),
            json=payload_create,
            timeout=15,
        )
        assert created.status_code == 201
        fid = created.json()["id"]

        r = requests.delete(_findings_url(dashboard_base_url, f"/{fid}"), timeout=15)
        assert r.status_code == 204

        lst = requests.get(
            _findings_url(dashboard_base_url),
            params={"per_page": 100},
            timeout=15,
        )
        assert lst.status_code == 200
        ids = {x["id"] for x in lst.json()["items"]}
        assert fid not in ids

    def test_dismiss_nonexistent_returns_404(self, dashboard_base_url: str) -> None:
        r = requests.delete(_findings_url(dashboard_base_url, "/999999"), timeout=15)
        assert r.status_code == 404

    def test_update_status_after_dismiss_returns_404(self, dashboard_base_url: str) -> None:
        payload_create = {
            "asset_id": SEED_ASSET_ID,
            "vulnerability_id": SEED_VULNERABILITY_ID,
            "scanner": "pytest-dismiss2",
            "notes": "dismiss then update",
        }
        created = requests.post(
            _findings_url(dashboard_base_url),
            json=payload_create,
            timeout=15,
        )
        assert created.status_code == 201
        fid = created.json()["id"]
        requests.delete(_findings_url(dashboard_base_url, f"/{fid}"), timeout=15)

        r = requests.put(
            _findings_url(dashboard_base_url, f"/{fid}/status"),
            json={"status": "confirmed"},
            timeout=15,
        )
        assert r.status_code == 404


class TestSearchFindings:
    def test_search_by_cve_returns_matches_structure(self, dashboard_base_url: str) -> None:
        r = requests.get(
            _findings_url(dashboard_base_url, "/search"),
            params={"q": "CVE-2021-44228"},
            timeout=15,
        )
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        if data:
            row = data[0]
            for key in ("finding_id", "status", "scanner", "cve_id", "severity", "hostname"):
                assert key in row

    def test_search_empty_query_returns_empty_list(self, dashboard_base_url: str) -> None:
        r = requests.get(
            _findings_url(dashboard_base_url, "/search"),
            params={"q": ""},
            timeout=15,
        )
        assert r.status_code == 200
        assert r.json() == []

    def test_search_hostname(self, dashboard_base_url: str) -> None:
        r = requests.get(
            _findings_url(dashboard_base_url, "/search"),
            params={"q": "prod-web"},
            timeout=15,
        )
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        if data:
            assert any("prod-web" in (row.get("hostname") or "") for row in data)


class TestResolvedStatusClearsResolvedAt:
    def test_confirmed_clears_resolved_at(self, dashboard_base_url: str) -> None:
        """Regression: moving out of resolved should clear resolved_at (per API behavior)."""
        payload_create = {
            "asset_id": SEED_ASSET_ID,
            "vulnerability_id": SEED_VULNERABILITY_ID,
            "scanner": "pytest-resolved",
            "notes": "resolved at test",
        }
        created = requests.post(
            _findings_url(dashboard_base_url),
            json=payload_create,
            timeout=15,
        )
        assert created.status_code == 201
        fid = created.json()["id"]

        requests.put(
            _findings_url(dashboard_base_url, f"/{fid}/status"),
            json={"status": "resolved"},
            timeout=15,
        )
        r1 = requests.get(_findings_url(dashboard_base_url, f"/{fid}"), timeout=15)
        assert r1.json().get("resolved_at") is not None

        requests.put(
            _findings_url(dashboard_base_url, f"/{fid}/status"),
            json={"status": "confirmed"},
            timeout=15,
        )
        r2 = requests.get(_findings_url(dashboard_base_url, f"/{fid}"), timeout=15)
        assert r2.json().get("resolved_at") is None
