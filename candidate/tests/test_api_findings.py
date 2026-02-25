"""
Part 1 — API Testing: Dashboard API findings CRUD, search, and edge cases.
"""
import pytest


# ═══════════════════════════ Health ═══════════════════════════


class TestHealth:
    def test_dashboard_api_healthy(self, api):
        resp = api.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["service"] == "dashboard-api"

    def test_scanner_service_healthy(self, scanner_api):
        resp = scanner_api.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


# ═══════════════════════════ List Findings ═══════════════════════════


class TestListFindings:
    def test_list_returns_paginated_response(self, api):
        resp = api.get("/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
        assert isinstance(data["items"], list)
        assert data["total"] > 0

    def test_list_pagination(self, api):
        resp = api.get("/findings", params={"page": 1, "per_page": 3})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) <= 3
        assert data["page"] == 1
        assert data["per_page"] == 3

    def test_list_filter_by_status(self, api):
        resp = api.get("/findings", params={"status": "open"})
        assert resp.status_code == 200
        data = resp.json()
        for item in data["items"]:
            assert item["status"] == "open"

    def test_list_filter_by_severity(self, api):
        resp = api.get("/findings", params={"severity": "critical"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] > 0  # we know there are critical findings in seed

    def test_list_filter_by_asset_id(self, api):
        resp = api.get("/findings", params={"asset_id": 1})
        assert resp.status_code == 200
        data = resp.json()
        for item in data["items"]:
            assert item["asset_id"] == 1

    def test_list_excludes_dismissed_findings(self, api, created_findings):
        # Create a finding then dismiss it
        create_resp = api.post("/findings", json={
            "asset_id": 1, "vulnerability_id": 8, "scanner": "test"
        })
        finding_id = create_resp.json()["id"]
        created_findings.append(finding_id)

        api.delete(f"/findings/{finding_id}")

        # Listing should not include dismissed finding
        resp = api.get("/findings", params={"per_page": 100})
        ids_in_list = [f["id"] for f in resp.json()["items"]]
        assert finding_id not in ids_in_list


# ═══════════════════════════ Get Finding ═══════════════════════════


class TestGetFinding:
    def test_get_existing_finding(self, api):
        resp = api.get("/findings/1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == 1
        assert "status" in data
        assert "asset_id" in data
        assert "vulnerability_id" in data
        assert "vulnerability" in data  # enriched detail
        assert "asset_hostname" in data

    def test_get_finding_includes_vulnerability_detail(self, api):
        resp = api.get("/findings/1")
        data = resp.json()
        vuln = data["vulnerability"]
        assert vuln is not None
        assert "cve_id" in vuln
        assert "severity" in vuln
        assert "cvss_score" in vuln

    def test_get_nonexistent_finding_returns_404(self, api):
        resp = api.get("/findings/99999")
        assert resp.status_code == 404

    def test_get_dismissed_finding_should_return_404(self, api, created_findings):
        """
        BUG #1 DETECTED: Dismissed findings still return 200 instead of 404.
        """
        # Create and dismiss
        create_resp = api.post("/findings", json={
            "asset_id": 2, "vulnerability_id": 3, "scanner": "test"
        })
        finding_id = create_resp.json()["id"]
        created_findings.append(finding_id)

        dismiss_resp = api.delete(f"/findings/{finding_id}")
        assert dismiss_resp.status_code == 204

        # GET should return 404 for dismissed finding
        get_resp = api.get(f"/findings/{finding_id}")
        # BUG: returns 200 instead of 404
        assert get_resp.status_code == 404, (
            f"BUG: GET /findings/{finding_id} returned {get_resp.status_code} "
            f"for a dismissed finding. Expected 404."
        )


# ═══════════════════════════ Create Finding ═══════════════════════════


class TestCreateFinding:
    def test_create_valid_finding(self, api, created_findings):
        resp = api.post("/findings", json={
            "asset_id": 1,
            "vulnerability_id": 5,
            "scanner": "pytest",
            "notes": "Test finding",
        })
        assert resp.status_code == 201
        data = resp.json()
        created_findings.append(data["id"])
        assert data["asset_id"] == 1
        assert data["vulnerability_id"] == 5
        assert data["status"] == "open"
        assert data["scanner"] == "pytest"

    def test_create_finding_invalid_asset(self, api):
        resp = api.post("/findings", json={
            "asset_id": 99999,
            "vulnerability_id": 1,
        })
        assert resp.status_code == 400

    def test_create_finding_invalid_vulnerability(self, api):
        resp = api.post("/findings", json={
            "asset_id": 1,
            "vulnerability_id": 99999,
        })
        assert resp.status_code == 400

    def test_create_finding_missing_required_fields(self, api):
        resp = api.post("/findings", json={})
        assert resp.status_code == 422  # Pydantic validation error


# ═══════════════════════════ Update Status ═══════════════════════════


class TestUpdateFindingStatus:
    @pytest.mark.parametrize("new_status", [
        "open", "confirmed", "in_progress", "resolved", "false_positive"
    ])
    def test_valid_status_values_accepted(self, api, new_status, created_findings):
        # Create a fresh finding for each test
        create_resp = api.post("/findings", json={
            "asset_id": 3, "vulnerability_id": 4, "scanner": "test"
        })
        finding_id = create_resp.json()["id"]
        created_findings.append(finding_id)

        resp = api.put(f"/findings/{finding_id}/status", json={"status": new_status})
        assert resp.status_code == 200
        assert resp.json()["status"] == new_status

    def test_invalid_status_rejected(self, api):
        resp = api.put("/findings/1/status", json={"status": "banana"})
        assert resp.status_code == 400

    def test_update_nonexistent_finding(self, api):
        resp = api.put("/findings/99999/status", json={"status": "confirmed"})
        assert resp.status_code == 404

    def test_resolved_sets_resolved_at(self, api, created_findings):
        create_resp = api.post("/findings", json={
            "asset_id": 1, "vulnerability_id": 6, "scanner": "test"
        })
        finding_id = create_resp.json()["id"]
        created_findings.append(finding_id)

        resp = api.put(f"/findings/{finding_id}/status", json={"status": "resolved"})
        assert resp.status_code == 200
        assert resp.json()["resolved_at"] is not None

    def test_status_transition_resolved_to_open_should_fail(self, api, created_findings):
        """
        BUG #2 DETECTED: Invalid status transitions are allowed.
        resolved → open should not be permitted.
        """
        create_resp = api.post("/findings", json={
            "asset_id": 2, "vulnerability_id": 4, "scanner": "test"
        })
        finding_id = create_resp.json()["id"]
        created_findings.append(finding_id)

        # Move through valid workflow
        api.put(f"/findings/{finding_id}/status", json={"status": "confirmed"})
        api.put(f"/findings/{finding_id}/status", json={"status": "in_progress"})
        api.put(f"/findings/{finding_id}/status", json={"status": "resolved"})

        # This should be rejected — can't reopen a resolved finding
        resp = api.put(f"/findings/{finding_id}/status", json={"status": "open"})
        assert resp.status_code == 400, (
            f"BUG: resolved → open transition returned {resp.status_code}. "
            f"Expected 400. Invalid status transitions are allowed."
        )

    def test_status_transition_false_positive_to_confirmed_should_fail(self, api, created_findings):
        """BUG #2 continuation: false_positive → confirmed should not be permitted."""
        create_resp = api.post("/findings", json={
            "asset_id": 3, "vulnerability_id": 6, "scanner": "test"
        })
        finding_id = create_resp.json()["id"]
        created_findings.append(finding_id)

        api.put(f"/findings/{finding_id}/status", json={"status": "false_positive"})
        resp = api.put(f"/findings/{finding_id}/status", json={"status": "confirmed"})
        assert resp.status_code == 400, (
            f"BUG: false_positive → confirmed returned {resp.status_code}. Expected 400."
        )


# ═══════════════════════════ Dismiss Finding ═══════════════════════════


class TestDismissFinding:
    def test_dismiss_existing_finding(self, api, created_findings):
        create_resp = api.post("/findings", json={
            "asset_id": 1, "vulnerability_id": 9, "scanner": "test"
        })
        finding_id = create_resp.json()["id"]
        created_findings.append(finding_id)

        resp = api.delete(f"/findings/{finding_id}")
        assert resp.status_code == 204

    def test_dismiss_nonexistent_finding(self, api):
        resp = api.delete("/findings/99999")
        assert resp.status_code == 404

    def test_dismiss_already_dismissed_finding(self, api, created_findings):
        create_resp = api.post("/findings", json={
            "asset_id": 2, "vulnerability_id": 8, "scanner": "test"
        })
        finding_id = create_resp.json()["id"]
        created_findings.append(finding_id)

        api.delete(f"/findings/{finding_id}")
        resp = api.delete(f"/findings/{finding_id}")
        assert resp.status_code == 404  # already dismissed


# ═══════════════════════════ Search ═══════════════════════════


class TestSearchFindings:
    def test_search_by_cve_id(self, api):
        resp = api.get("/findings/search", params={"q": "CVE-2021-44228"})
        assert resp.status_code == 200
        results = resp.json()
        assert len(results) > 0
        assert all("CVE-2021-44228" in r["cve_id"] for r in results)

    def test_search_by_hostname(self, api):
        resp = api.get("/findings/search", params={"q": "prod-web"})
        assert resp.status_code == 200
        results = resp.json()
        assert len(results) > 0

    def test_search_empty_query_returns_empty(self, api):
        resp = api.get("/findings/search", params={"q": ""})
        assert resp.status_code == 200
        assert resp.json() == []

    def test_search_no_match(self, api):
        resp = api.get("/findings/search", params={"q": "NONEXISTENT-CVE-9999"})
        assert resp.status_code == 200
        assert resp.json() == []

    def test_search_sql_injection_should_be_prevented(self, api):
        """
        BUG #3 DETECTED: SQL injection on search endpoint.
        Malicious input should be safely escaped, not executed.
        """
        # This payload should return 0 results if properly escaped
        resp = api.get("/findings/search", params={"q": "' OR '1'='1"})
        assert resp.status_code == 200
        results = resp.json()

        # If SQL injection works, this returns ALL findings
        # A safe search with this gibberish input should return 0 results
        assert len(results) == 0, (
            f"BUG: SQL injection! Search returned {len(results)} results for "
            f"malicious input \"' OR '1'='1\". Expected 0. "
            f"The search endpoint is vulnerable to SQL injection."
        )


# ═══════════════════════════ Vulnerabilities ═══════════════════════════


class TestVulnerabilities:
    def test_list_vulnerabilities(self, api):
        resp = api.get("/vulnerabilities")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 10  # seed data has 10 CVEs

    def test_list_filter_by_severity(self, api):
        resp = api.get("/vulnerabilities", params={"severity": "critical"})
        assert resp.status_code == 200
        data = resp.json()
        assert all(v["severity"] == "critical" for v in data)

    def test_get_vulnerability(self, api):
        resp = api.get("/vulnerabilities/1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cve_id"] == "CVE-2021-44228"
        assert data["severity"] == "critical"
        assert data["cvss_score"] == 10.0

    def test_get_nonexistent_vulnerability(self, api):
        resp = api.get("/vulnerabilities/99999")
        assert resp.status_code == 404


# ═══════════════════════════ Stats ═══════════════════════════


class TestStats:
    def test_risk_score_returns_expected_fields(self, api):
        resp = api.get("/stats/risk-score")
        assert resp.status_code == 200
        data = resp.json()
        for field in ["risk_score", "total_findings", "critical_count",
                       "high_count", "medium_count", "low_count", "average_cvss"]:
            assert field in data

    def test_risk_score_values_are_reasonable(self, api):
        """
        BUG #5 DETECTED: Float precision — average_cvss and risk_score
        have excessive decimal places.
        """
        resp = api.get("/stats/risk-score")
        data = resp.json()

        # CVSS average should be rounded to a reasonable precision (1-2 decimals)
        avg_str = str(data["average_cvss"])
        decimal_places = len(avg_str.split(".")[-1]) if "." in avg_str else 0

        assert decimal_places <= 2, (
            f"BUG: average_cvss has {decimal_places} decimal places: "
            f"{data['average_cvss']}. Financial/score values should be "
            f"rounded to 1-2 decimal places."
        )

    def test_summary_returns_expected_fields(self, api):
        resp = api.get("/stats/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_findings" in data
        assert "open_findings" in data
        assert "by_severity" in data
        assert "by_environment" in data

    def test_summary_counts_are_consistent(self, api):
        resp = api.get("/stats/summary")
        data = resp.json()

        # Sum of status counts should equal total
        status_sum = (
            data["open_findings"]
            + data["confirmed_findings"]
            + data["in_progress_findings"]
            + data["resolved_findings"]
            + data["false_positive_findings"]
        )
        assert status_sum == data["total_findings"], (
            f"Status counts sum ({status_sum}) != total ({data['total_findings']})"
        )
