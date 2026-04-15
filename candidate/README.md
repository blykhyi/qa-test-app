# QA Test Suite — Candidate Solution Guide

This repository contains a pytest + Playwright test suite for the Vulnerability Management Dashboard (Dashboard API + Scanner Service + Postgres).

The suite is designed to be **order-independent**, **seed-independent**, and to produce a clear CI signal by separating:

- **Health signal tests** (default `pytest` run)
- **Known defect regressions** (run explicitly via markers)

## Project structure

- `tests/conftest.py`
  - **Environment-driven URLs** for services (`DASHBOARD_API_URL`, `SCANNER_SERVICE_URL`)
  - Postgres connectivity helpers
  - Test data fixtures:
    - `api_testdata`: API-only factories (no direct DB dependency)
    - `db_testdata`: DB-backed factories with deterministic cleanup (recommended for integration)
- `tests/helpers/api_clients.py`
  - `DashboardApiClient` and `ScannerApiClient` thin wrappers around raw HTTP calls
- `tests/helpers/factories.py`
  - `ApiTestDataFactory`: creates assets/findings/scans via APIs; cleans up via API (dismiss/deactivate)
  - `TestDataFactory`: creates assets via API + vulnerabilities via DB; cleans up via DB (findings/scans/vulns) + API for assets
- Test layers:
  - `tests/test_dashboard_api_findings.py` (**api**)
  - `tests/test_scanner_api.py` (**api**)
  - `tests/test_database_validation.py` (**db**)
  - `tests/test_integration.py` (**integration**)
  - `tests/test_ui_dashboard.py` (**ui**, **smoke**, plus known bug coverage)
  - `tests/test_documented_bugs.py` (**known_bug**)

## Assumptions & test data strategy

- Tests do **not** rely on fixed seed IDs (e.g. asset id `3` or vuln id `4`).
- When we need a vulnerability id but don’t require a special row, the suite uses the **existing catalog** via `GET /vulnerabilities` (API-only mode).
- For integration/regression tests that must create specific vulnerability rows, we insert via Postgres and clean up in teardown (`db_testdata`).
- Cleanup is **per-test**:
  - API-only tests clean their own created assets/findings (dismiss + deactivate).
  - DB-backed tests delete created findings/scans/vulns directly, then deactivate assets.

## Markers & execution model

Markers are defined in `pytest.ini`:

- `smoke`: merge-blocking happy-path checks
- `known_bug`: expected failures documenting known defects
- `api`, `db`, `integration`, `ui`: execution layers

Default behavior excludes `known_bug` so CI reflects product health:

```bash
pytest
```

Run known bug regressions explicitly:

```bash
pytest -m known_bug
```

Run only smoke:

```bash
pytest -m smoke
```

## Expected failures (known defects)

Tests marked `known_bug` are expected to fail (or be `xfail`) until product fixes land. These are intentionally excluded from the default run so the suite’s main signal remains actionable.

## Running locally

```bash
python -m venv venv
./venv/Scripts/activate
pip install -r requirements.txt
playwright install chromium

# Default (health signal)
pytest

# Known bugs
pytest -m known_bug
```
