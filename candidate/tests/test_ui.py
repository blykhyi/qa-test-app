"""
Part 4 — UI Smoke Tests: Playwright tests for the vulnerability dashboard.
"""
import pytest
import re
from playwright.sync_api import sync_playwright, expect


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture
def page(browser):
    context = browser.new_context()
    page = context.new_page()
    yield page
    context.close()


class TestDashboardLoads:
    def test_dashboard_page_loads(self, page):
        """Dashboard should load and show the title."""
        page.goto("http://localhost:8000/")
        expect(page.locator("h1")).to_contain_text("Vulnerability Dashboard")

    def test_summary_cards_populated(self, page):
        """Summary cards should show numeric values, not dashes."""
        page.goto("http://localhost:8000/")
        page.wait_for_timeout(1000)  # wait for API calls

        # The "Active Findings" card should have a number
        total = page.locator("#total-count")
        expect(total).not_to_have_text("-")

    def test_findings_table_has_rows(self, page):
        """Findings table should display rows from seed data."""
        page.goto("http://localhost:8000/")
        page.wait_for_timeout(1000)

        rows = page.locator("#findings-table tr")
        count = rows.count()
        assert count > 0, "Findings table should have at least one row"

    def test_findings_table_shows_cve_ids(self, page):
        """Each finding row should include a CVE ID."""
        page.goto("http://localhost:8000/")
        page.wait_for_timeout(1000)

        first_row = page.locator("#findings-table tr").first
        cve_text = first_row.locator(".cve-link").text_content()
        assert cve_text.startswith("CVE-"), f"Expected CVE ID, got: {cve_text}"


class TestStatusUpdateUI:
    def test_status_change_shows_success_message(self, page):
        """Changing a finding status should show a success message."""
        page.goto("http://localhost:8000/")
        page.wait_for_timeout(1000)

        # Find the first status dropdown and change it
        select = page.locator(".status-select").first
        select.select_option("confirmed")

        # Success message should appear
        page.wait_for_timeout(500)
        msg = page.locator(".message-success")
        expect(msg).to_be_visible()

    def test_status_change_should_refresh_table(self, page):
        """
        BUG #8 DETECTED: After changing status, the table doesn't refresh.
        The new status should be visible immediately without manual refresh.
        """
        page.goto("http://localhost:8000/")
        page.wait_for_timeout(1500)

        # Get the first finding's current status text
        first_status = page.locator("#findings-table tr .status").first
        old_status = first_status.text_content().strip()

        # Choose a different status
        new_status = "in progress" if old_status != "in progress" else "confirmed"
        new_status_value = new_status.replace(" ", "_")

        select = page.locator(".status-select").first
        select.select_option(new_status_value)
        page.wait_for_timeout(1000)

        # The status badge in the table should now show the new status
        updated_status = page.locator("#findings-table tr .status").first.text_content().strip()
        assert updated_status == new_status, (
            f"BUG: After changing status to '{new_status}', table still shows "
            f"'{updated_status}'. UI doesn't refresh after status update."
        )
