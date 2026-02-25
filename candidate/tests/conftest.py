"""
Shared fixtures for the Vulnerability Dashboard test suite.
"""
import pytest
import requests
import psycopg2
import psycopg2.extras

DASHBOARD_API = "http://localhost:8000"
SCANNER_API = "http://localhost:8001"

DB_CONFIG = {
    "host": "localhost",
    "port": 5433,
    "dbname": "qa_test",
    "user": "qa_user",
    "password": "qa_password",
}


# ──────────────────────────── API helpers ────────────────────────────


@pytest.fixture(scope="session")
def dashboard_url():
    return DASHBOARD_API


@pytest.fixture(scope="session")
def scanner_url():
    return SCANNER_API


@pytest.fixture(scope="session")
def api(dashboard_url):
    """Requests session pre-configured for the Dashboard API."""
    s = requests.Session()
    s.base_url = dashboard_url
    # Monkey-patch convenience so tests can do api.get("/findings")
    _orig_request = s.request

    def _patched_request(method, url, *args, **kwargs):
        if url.startswith("/"):
            url = dashboard_url + url
        return _orig_request(method, url, *args, **kwargs)

    s.request = _patched_request
    return s


@pytest.fixture(scope="session")
def scanner_api(scanner_url):
    """Requests session pre-configured for the Scanner Service."""
    s = requests.Session()
    s.base_url = scanner_url
    _orig_request = s.request

    def _patched_request(method, url, *args, **kwargs):
        if url.startswith("/"):
            url = scanner_url + url
        return _orig_request(method, url, *args, **kwargs)

    s.request = _patched_request
    return s


# ──────────────────────────── Database ────────────────────────────


@pytest.fixture(scope="session")
def db_conn():
    """Session-scoped raw psycopg2 connection for DB validation."""
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = True
    yield conn
    conn.close()


@pytest.fixture
def db(db_conn):
    """Per-test cursor (dict rows) that auto-closes."""
    cur = db_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    yield cur
    cur.close()


# ──────────────────────────── Cleanup helpers ────────────────────────────


@pytest.fixture
def created_findings(api):
    """Track findings created during a test so they can be cleaned up."""
    ids = []
    yield ids
    for fid in ids:
        try:
            api.delete(f"/findings/{fid}")
        except Exception:
            pass


@pytest.fixture
def created_assets(scanner_api):
    """Track assets created during a test so they can be cleaned up."""
    ids = []
    yield ids
    for aid in ids:
        try:
            scanner_api.delete(f"/assets/{aid}")
        except Exception:
            pass
