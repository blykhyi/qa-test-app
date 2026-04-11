"""Part 4 — Playwright UI smoke: dashboard loads; status change via dropdown (refresh to reflect BUG #8)."""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.usefixtures("dashboard_available")


def _parse_status_from_row(status_text: str) -> str:
    """Map badge text (e.g. 'in progress', 'false positive') to API value."""
    raw = status_text.strip().lower()
    mapping = {
        "open": "open",
        "confirmed": "confirmed",
        "in progress": "in_progress",
        "resolved": "resolved",
        "false positive": "false_positive",
    }
    return mapping.get(raw, raw.replace(" ", "_"))


def _next_status(current: str) -> str:
    order = ["open", "confirmed", "in_progress", "resolved", "false_positive"]
    if current not in order:
        return "confirmed"
    return order[(order.index(current) + 1) % len(order)]


def test_dashboard_loads_with_findings(page: Page, dashboard_base_url: str) -> None:
    page.goto(f"{dashboard_base_url}/")
    expect(page.get_by_role("heading", name="Vulnerability Dashboard")).to_be_visible()
    expect(page.locator("#total-count")).not_to_have_text("-", timeout=20_000)
    expect(page.locator("#findings-table")).not_to_contain_text(
        "No findings match your filters", timeout=20_000
    )
    data_row = page.locator("#findings-table tr").filter(
        has=page.locator("select.status-select")
    ).first
    expect(data_row).to_be_visible()


def test_change_finding_status_reflects_after_refresh(page: Page, dashboard_base_url: str) -> None:
    """UI does not reload the table after PUT (BUG #8); Refresh reloads from API so the badge matches."""
    page.goto(f"{dashboard_base_url}/")
    row = page.locator("#findings-table tr").filter(
        has=page.locator("select.status-select")
    ).first
    expect(row).to_be_visible(timeout=20_000)

    id_cell = row.locator("td").first
    id_match = re.search(r"#(\d+)", id_cell.inner_text())
    assert id_match, "finding id cell should look like #123"
    fid = int(id_match.group(1))

    current = _parse_status_from_row(row.locator("span.status").first.inner_text())
    target = _next_status(current)

    row.locator("select.status-select").select_option(value=target)
    expect(page.locator(".message-success")).to_contain_text(
        f"Finding #{fid} updated to {target}", timeout=15_000
    )

    page.get_by_role("button", name="Refresh").click()
    refreshed = page.locator("#findings-table tr").filter(has_text=f"#{fid}").first
    expect(refreshed).to_be_visible()

    label = target.replace("_", " ")
    expect(refreshed.locator("span.status")).to_have_text(
        re.compile("^" + re.escape(label) + "$", re.IGNORECASE)
    )


def test_status_badge_updates_after_change_without_manual_refresh(
    page: Page,
    dashboard_base_url: str,
) -> None:
    """BUG #8: Table should reload after PUT; badge must match API without clicking Refresh."""
    page.goto(f"{dashboard_base_url}/")
    row = page.locator("#findings-table tr").filter(
        has=page.locator("select.status-select")
    ).first
    expect(row).to_be_visible(timeout=20_000)

    current = _parse_status_from_row(row.locator("span.status").first.inner_text())
    target = _next_status(current)
    label = target.replace("_", " ")

    row.locator("select.status-select").select_option(value=target)
    expect(page.locator(".message-success")).to_be_visible(timeout=15_000)

    expect(row.locator("span.status").first).to_have_text(
        re.compile("^" + re.escape(label) + "$", re.IGNORECASE)
    )
