"""Shared fixtures for QA assessment tests."""

import os
from typing import Any, Generator

import pytest
import requests

from tests.helpers.api_clients import DashboardApiClient, ScannerApiClient
from tests.helpers.factories import ApiTestDataFactory, TestDataFactory

DEFAULT_DASHBOARD_URL = os.environ.get("DASHBOARD_API_URL", "http://localhost:8000").rstrip("/")
DEFAULT_SCANNER_URL = os.environ.get("SCANNER_SERVICE_URL", "http://localhost:8001").rstrip("/")


def _postgres_conn_params() -> dict[str, Any]:
    return {
        "host": os.environ.get("POSTGRES_HOST", "localhost"),
        "port": int(os.environ.get("POSTGRES_PORT", "5433")),
        "dbname": os.environ.get("POSTGRES_DB", "qa_test"),
        "user": os.environ.get("POSTGRES_USER", "qa_user"),
        "password": os.environ.get("POSTGRES_PASSWORD", "qa_password"),
    }


@pytest.fixture(scope="session")
def postgres_conn_params() -> dict[str, Any]:
    """Connection kwargs for psycopg2.connect."""
    return _postgres_conn_params()


@pytest.fixture(scope="session")
def postgres_available(postgres_conn_params: dict[str, Any]) -> None:
    """Skip DB tests when PostgreSQL is not reachable (requires psycopg2)."""
    psycopg2 = pytest.importorskip("psycopg2")
    try:
        conn = psycopg2.connect(**postgres_conn_params)
        conn.close()
    except Exception as exc:  # noqa: BLE001 — surface any connect failure
        pytest.skip(f"PostgreSQL not reachable: {exc}")


@pytest.fixture
def db_cursor(
    postgres_conn_params: dict[str, Any],
    postgres_available: None,
) -> Generator[Any, None, None]:
    """Autocommit cursor; each test gets a fresh connection."""
    import psycopg2

    conn = psycopg2.connect(**postgres_conn_params)
    conn.autocommit = True
    cur = conn.cursor()
    try:
        yield cur
    finally:
        cur.close()
        conn.close()


@pytest.fixture(scope="session")
def dashboard_base_url() -> str:
    return DEFAULT_DASHBOARD_URL


@pytest.fixture(scope="session")
def scanner_base_url() -> str:
    return DEFAULT_SCANNER_URL


@pytest.fixture(scope="session")
def dashboard_client(dashboard_base_url: str) -> DashboardApiClient:
    return DashboardApiClient(base_url=dashboard_base_url)


@pytest.fixture(scope="session")
def scanner_client(scanner_base_url: str) -> ScannerApiClient:
    return ScannerApiClient(base_url=scanner_base_url)


@pytest.fixture(scope="session")
def scanner_available(scanner_base_url: str) -> None:
    """Skip integration tests when the Scanner service is not running."""
    try:
        r = requests.get(f"{scanner_base_url}/health", timeout=5)
    except requests.RequestException as exc:
        pytest.skip(f"Scanner service unreachable: {exc}")
    if r.status_code != 200:
        pytest.skip(f"Scanner service unhealthy: HTTP {r.status_code}")


@pytest.fixture(scope="session")
def dashboard_available(dashboard_base_url: str) -> None:
    """Skip API tests when the Dashboard service is not running."""
    try:
        r = requests.get(f"{dashboard_base_url}/health", timeout=5)
    except requests.RequestException as exc:
        pytest.skip(f"Dashboard API unreachable: {exc}")
    if r.status_code != 200:
        pytest.skip(f"Dashboard API unhealthy: HTTP {r.status_code}")


@pytest.fixture
def api_testdata(
    dashboard_client: DashboardApiClient,
    scanner_client: ScannerApiClient,
) -> Generator[ApiTestDataFactory, None, None]:
    factory = ApiTestDataFactory(dashboard=dashboard_client, scanner=scanner_client)
    try:
        yield factory
    finally:
        factory.cleanup()


@pytest.fixture
def db_testdata(
    dashboard_client: DashboardApiClient,
    scanner_client: ScannerApiClient,
    db_cursor,
) -> Generator[TestDataFactory, None, None]:
    factory = TestDataFactory(dashboard=dashboard_client, scanner=scanner_client, db_cursor=db_cursor)
    try:
        yield factory
    finally:
        factory.cleanup()
