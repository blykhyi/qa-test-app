from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests


def _join(base_url: str, path: str) -> str:
    base = base_url.rstrip("/")
    p = path if path.startswith("/") else f"/{path}"
    return f"{base}{p}"


@dataclass(frozen=True)
class DashboardApiClient:
    base_url: str
    timeout_s: float = 15

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))

    def get_health(self) -> requests.Response:
        return requests.get(_join(self.base_url, "/health"), timeout=self.timeout_s)

    def list_findings(self, **params: Any) -> requests.Response:
        return requests.get(
            _join(self.base_url, "/findings"),
            params=params or None,
            timeout=self.timeout_s,
        )

    def get_finding(self, finding_id: int) -> requests.Response:
        return requests.get(
            _join(self.base_url, f"/findings/{finding_id}"),
            timeout=self.timeout_s,
        )

    def create_finding(self, payload: dict[str, Any]) -> requests.Response:
        return requests.post(
            _join(self.base_url, "/findings"),
            json=payload,
            timeout=self.timeout_s,
        )

    def dismiss_finding(self, finding_id: int) -> requests.Response:
        return requests.delete(
            _join(self.base_url, f"/findings/{finding_id}"),
            timeout=self.timeout_s,
        )

    def update_finding_status(self, finding_id: int, payload: dict[str, Any]) -> requests.Response:
        return requests.put(
            _join(self.base_url, f"/findings/{finding_id}/status"),
            json=payload,
            timeout=self.timeout_s,
        )

    def search_findings(self, q: str) -> requests.Response:
        return requests.get(
            _join(self.base_url, "/findings/search"),
            params={"q": q},
            timeout=self.timeout_s,
        )

    def list_vulnerabilities(self) -> requests.Response:
        return requests.get(_join(self.base_url, "/vulnerabilities"), timeout=self.timeout_s)


@dataclass(frozen=True)
class ScannerApiClient:
    base_url: str
    timeout_s: float = 15

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))

    def get_health(self) -> requests.Response:
        return requests.get(_join(self.base_url, "/health"), timeout=self.timeout_s)

    def list_assets(self, **params: Any) -> requests.Response:
        return requests.get(
            _join(self.base_url, "/assets"),
            params=params or None,
            timeout=self.timeout_s,
        )

    def get_asset(self, asset_id: int) -> requests.Response:
        return requests.get(_join(self.base_url, f"/assets/{asset_id}"), timeout=self.timeout_s)

    def create_asset(self, payload: dict[str, Any]) -> requests.Response:
        return requests.post(
            _join(self.base_url, "/assets"),
            json=payload,
            timeout=self.timeout_s,
        )

    def update_asset(self, asset_id: int, payload: dict[str, Any]) -> requests.Response:
        return requests.put(
            _join(self.base_url, f"/assets/{asset_id}"),
            json=payload,
            timeout=self.timeout_s,
        )

    def deactivate_asset(self, asset_id: int) -> requests.Response:
        return requests.delete(_join(self.base_url, f"/assets/{asset_id}"), timeout=self.timeout_s)

    def list_scans(self, **params: Any) -> requests.Response:
        return requests.get(
            _join(self.base_url, "/scans"),
            params=params or None,
            timeout=self.timeout_s,
        )

    def get_scan(self, scan_id: int) -> requests.Response:
        return requests.get(_join(self.base_url, f"/scans/{scan_id}"), timeout=self.timeout_s)

    def run_scan(self, payload: dict[str, Any]) -> requests.Response:
        return requests.post(
            _join(self.base_url, "/scans"),
            json=payload,
            timeout=self.timeout_s,
        )

