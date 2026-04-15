from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

from tests.helpers.api_clients import DashboardApiClient, ScannerApiClient


def _uuid_token(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _short_cve_id() -> str:
    # DB schema uses varchar(20) for cve_id; keep this safely under that.
    # Example length: len("CVE-") + 12 = 16
    return f"CVE-{uuid.uuid4().hex[:12].upper()}"


@dataclass
class CreatedRecords:
    asset_ids: list[int] = field(default_factory=list)
    finding_ids: list[int] = field(default_factory=list)
    scan_ids: list[int] = field(default_factory=list)
    vulnerability_ids: list[int] = field(default_factory=list)
    vulnerability_cve_ids: list[str] = field(default_factory=list)


class TestDataFactory:
    """Factory that creates data through APIs/DB and records cleanup tasks."""

    def __init__(
        self,
        *,
        dashboard: DashboardApiClient,
        scanner: ScannerApiClient,
        db_cursor: Any,
    ) -> None:
        self.dashboard = dashboard
        self.scanner = scanner
        self.db_cursor = db_cursor
        self.created = CreatedRecords()

    def create_asset(
        self,
        *,
        hostname: str | None = None,
        asset_type: str = "server",
        environment: str = "staging",
        ip_address: str | None = None,
        os: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "hostname": hostname or _uuid_token("pytest-asset"),
            "asset_type": asset_type,
            "environment": environment,
        }
        if ip_address is not None:
            payload["ip_address"] = ip_address
        if os is not None:
            payload["os"] = os

        r = self.scanner.create_asset(payload)
        assert r.status_code == 201, f"asset create failed: HTTP {r.status_code} {r.text}"
        asset = r.json()
        self.created.asset_ids.append(asset["id"])
        return asset

    def create_vulnerability(
        self,
        *,
        cve_id: str | None = None,
        title: str = "pytest vuln",
        severity: str = "low",
        cvss_score: float | None = 1.0,
        description: str | None = None,
    ) -> dict[str, Any]:
        cve = cve_id or _short_cve_id()
        self.db_cursor.execute("DELETE FROM vulnerabilities WHERE cve_id = %s", (cve,))
        self.db_cursor.execute(
            """
            INSERT INTO vulnerabilities (cve_id, title, severity, cvss_score, description)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id, cve_id, title, severity, cvss_score
            """,
            (cve, title, severity, cvss_score, description),
        )
        row = self.db_cursor.fetchone()
        assert row, "expected INSERT .. RETURNING to yield a row"
        vuln = {
            "id": int(row[0]),
            "cve_id": str(row[1]),
            "title": str(row[2]),
            "severity": str(row[3]),
            "cvss_score": row[4],
        }
        self.created.vulnerability_ids.append(vuln["id"])
        self.created.vulnerability_cve_ids.append(cve)
        return vuln

    def create_finding(
        self,
        *,
        asset_id: int,
        vulnerability_id: int,
        scanner: str = "pytest",
        notes: str | None = None,
    ) -> dict[str, Any]:
        payload = {
            "asset_id": asset_id,
            "vulnerability_id": vulnerability_id,
            "scanner": scanner,
            "notes": notes or _uuid_token("pytest-finding"),
        }
        r = self.dashboard.create_finding(payload)
        assert r.status_code == 201, f"finding create failed: HTTP {r.status_code} {r.text}"
        finding = r.json()
        self.created.finding_ids.append(finding["id"])
        return finding

    def run_scan(
        self,
        *,
        asset_id: int,
        vulnerability_ids: Iterable[int],
        scanner_name: str = "pytest-scan",
    ) -> dict[str, Any]:
        payload = {
            "asset_id": asset_id,
            "scanner_name": scanner_name,
            "vulnerability_ids": list(vulnerability_ids),
        }
        r = self.scanner.run_scan(payload)
        assert r.status_code == 201, f"scan run failed: HTTP {r.status_code} {r.text}"
        scan = r.json()
        self.created.scan_ids.append(scan["id"])
        return scan

    def cleanup(self) -> None:
        # Prefer DB cleanup for cross-service artifacts (findings/scans), then deactivate assets.
        # Scans create findings in the Dashboard DB; we may not know their ids.
        # First delete any findings tied to the vulns we created (covers scan-created rows too),
        # then delete explicitly-tracked findings as a fallback.
        if self.created.vulnerability_ids:
            self.db_cursor.execute(
                "DELETE FROM findings WHERE vulnerability_id = ANY(%s)",
                (self.created.vulnerability_ids,),
            )
        if self.created.finding_ids:
            self.db_cursor.execute("DELETE FROM findings WHERE id = ANY(%s)", (self.created.finding_ids,))
        if self.created.scan_ids:
            self.db_cursor.execute(
                "DELETE FROM scans WHERE id = ANY(%s)",
                (self.created.scan_ids,),
            )
        if self.created.vulnerability_ids:
            self.db_cursor.execute(
                "DELETE FROM vulnerabilities WHERE id = ANY(%s)",
                (self.created.vulnerability_ids,),
            )
        for aid in reversed(self.created.asset_ids):
            self.scanner.deactivate_asset(aid)


class ApiTestDataFactory:
    """API-only factory that avoids seed *IDs* but doesn't require direct DB access.

    It discovers an existing vulnerability id from the catalog, creates assets via
    the scanner API, and cleans up via API endpoints (dismiss + deactivate).
    """

    def __init__(self, *, dashboard: DashboardApiClient, scanner: ScannerApiClient) -> None:
        self.dashboard = dashboard
        self.scanner = scanner
        self.created = CreatedRecords()

    def any_vulnerability_id(self) -> int:
        r = self.dashboard.list_vulnerabilities()
        assert r.status_code == 200, f"vuln list failed: HTTP {r.status_code} {r.text}"
        data = r.json()
        assert isinstance(data, list) and data, "expected non-empty vulnerability catalog"
        return int(data[0]["id"])

    def create_asset(
        self,
        *,
        hostname: str | None = None,
        asset_type: str = "server",
        environment: str = "staging",
        ip_address: str | None = None,
        os: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "hostname": hostname or _uuid_token("pytest-asset"),
            "asset_type": asset_type,
            "environment": environment,
        }
        if ip_address is not None:
            payload["ip_address"] = ip_address
        if os is not None:
            payload["os"] = os

        r = self.scanner.create_asset(payload)
        assert r.status_code == 201, f"asset create failed: HTTP {r.status_code} {r.text}"
        asset = r.json()
        self.created.asset_ids.append(asset["id"])
        return asset

    def create_finding(
        self,
        *,
        asset_id: int,
        vulnerability_id: int | None = None,
        scanner: str = "pytest",
        notes: str | None = None,
    ) -> dict[str, Any]:
        vid = vulnerability_id if vulnerability_id is not None else self.any_vulnerability_id()
        payload = {
            "asset_id": asset_id,
            "vulnerability_id": vid,
            "scanner": scanner,
            "notes": notes or _uuid_token("pytest-finding"),
        }
        r = self.dashboard.create_finding(payload)
        assert r.status_code == 201, f"finding create failed: HTTP {r.status_code} {r.text}"
        finding = r.json()
        self.created.finding_ids.append(finding["id"])
        return finding

    def run_scan(
        self,
        *,
        asset_id: int,
        vulnerability_ids: Iterable[int] | None = None,
        scanner_name: str = "pytest-scan",
    ) -> dict[str, Any]:
        vids = list(vulnerability_ids) if vulnerability_ids is not None else [self.any_vulnerability_id()]
        payload = {"asset_id": asset_id, "scanner_name": scanner_name, "vulnerability_ids": vids}
        r = self.scanner.run_scan(payload)
        assert r.status_code == 201, f"scan run failed: HTTP {r.status_code} {r.text}"
        scan = r.json()
        self.created.scan_ids.append(scan["id"])
        return scan

    def cleanup(self) -> None:
        for fid in reversed(self.created.finding_ids):
            self.dashboard.dismiss_finding(fid)
        for aid in reversed(self.created.asset_ids):
            self.scanner.deactivate_asset(aid)

