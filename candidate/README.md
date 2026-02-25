# QA Automation Engineer — Technical Assessment

**Duration:** 2 hours
**Language:** Python

---

## Overview

You are given a running **Vulnerability Management Dashboard** composed of two microservices and a PostgreSQL database. The system tracks security vulnerabilities detected across your organization's assets (servers, containers, applications).

Your task is to write automated tests that verify the system works correctly — and find any bugs.

The system is already running via Docker. You don't need to modify the application code.

---

## System Architecture

```
┌──────────────┐      ┌───────────────────┐      ┌────────────────────┐
│  Dashboard UI │─────▶│  Dashboard API     │      │  Scanner Service    │
│  localhost/   │      │  localhost:8000    │      │  localhost:8001     │
└──────────────┘      └────────┬──────────┘      └──────────┬─────────┘
                               │                             │
                           ┌───▼─────────────────────────────▼───┐
                           │           PostgreSQL                 │
                           │     localhost:5433 / qa_test         │
                           └─────────────────────────────────────┘
```

---

## Connection Details

| Service            | URL / Connection                                  |
|--------------------|---------------------------------------------------|
| Dashboard API      | `http://localhost:8000`                            |
| Scanner Service    | `http://localhost:8001`                            |
| Dashboard UI       | `http://localhost:8000/`                           |
| PostgreSQL         | Host: `localhost`, Port: `5433`, DB: `qa_test`, User: `qa_user`, Password: `qa_password` |

---

## API Reference

### Scanner Service (port 8001)

Manages assets and scan operations.

| Method | Endpoint               | Description                              |
|--------|------------------------|------------------------------------------|
| GET    | `/assets`              | List assets (paginated)                  |
| GET    | `/assets/{id}`         | Get a single asset                       |
| POST   | `/assets`              | Create an asset                          |
| PUT    | `/assets/{id}`         | Update an asset                          |
| DELETE | `/assets/{id}`         | Deactivate an asset                      |
| POST   | `/scans`               | Run a scan (creates findings)            |
| GET    | `/scans`               | List scans                               |
| GET    | `/scans/{id}`          | Get scan details                         |
| GET    | `/health`              | Health check                             |

**Pagination params:** `?page=1&per_page=10`
**Filter params (assets):** `?environment=production&asset_type=server`

**Create asset payload:**
```json
{
  "hostname": "web-server-03",
  "ip_address": "10.0.1.50",
  "asset_type": "server",
  "environment": "production",
  "os": "Ubuntu 22.04"
}
```

**Run scan payload:**
```json
{
  "asset_id": 1,
  "scanner_name": "Nessus",
  "vulnerability_ids": [1, 3, 5]
}
```

### Dashboard API (port 8000)

Manages findings lifecycle, statistics, and serves the UI.

| Method | Endpoint                     | Description                              |
|--------|------------------------------|------------------------------------------|
| GET    | `/findings`                  | List findings (paginated, filterable)    |
| GET    | `/findings/{id}`             | Get finding detail with CVE info         |
| POST   | `/findings`                  | Create a finding manually                |
| PUT    | `/findings/{id}/status`      | Update finding status                    |
| DELETE | `/findings/{id}`             | Dismiss a finding                        |
| GET    | `/findings/search?q=`        | Search findings by CVE, hostname, notes  |
| GET    | `/stats/risk-score`          | Calculate overall risk score             |
| GET    | `/stats/summary`             | Summary counts by status and severity    |
| GET    | `/vulnerabilities`           | List vulnerability catalog               |
| GET    | `/vulnerabilities/{id}`      | Get vulnerability detail                 |
| GET    | `/health`                    | Health check                             |

**Filter params (findings):** `?status=open&severity=critical&asset_id=1`

**Create finding payload:**
```json
{
  "asset_id": 1,
  "vulnerability_id": 3,
  "scanner": "Nessus",
  "notes": "Detected during routine scan"
}
```

**Update status payload:**
```json
{"status": "confirmed", "notes": "Verified by security team"}
```

Valid statuses: `open`, `confirmed`, `in_progress`, `resolved`, `false_positive`

### Database Schema

```sql
assets:           id, hostname, ip_address, asset_type, environment, os, is_active, created_at
vulnerabilities:  id, cve_id, title, description, severity, cvss_score, published_date, created_at
findings:         id, asset_id, vulnerability_id, status, detected_at, resolved_at, scanner, notes, is_dismissed
scans:            id, asset_id, scanner_name, status, started_at, completed_at, findings_count
```

---

## Your Tasks

### Part 1 — API Testing (45 min)
Write pytest-based tests for the **Dashboard API**:
- Findings CRUD operations (create, read, update status, dismiss)
- Error handling (invalid inputs, non-existent resources)
- Edge cases (invalid status values, boundary values)
- Validate response status codes, response structure, and data correctness
- Test the search endpoint

### Part 2 — Database Validation (30 min)
Connect directly to PostgreSQL and write tests that:
- Verify data integrity after API operations (e.g., dismiss a finding via API → query DB → verify `is_dismissed` is TRUE)
- Check that database constraints enforce data quality (e.g., CVSS score ranges, required fields)
- Validate consistency between findings, vulnerabilities, and assets tables

### Part 3 — Integration Testing (25 min)
Test cross-service flows:
- Run a scan via Scanner Service → verify findings created in Dashboard API
- Update finding status → verify DB state matches
- Test what happens with concurrent scan imports (optional but valuable)

### Part 4 — UI Smoke Test with Playwright (10 min)
Write 1-2 Playwright tests:
- Navigate to `http://localhost:8000/`, verify the dashboard loads with findings
- Change a finding's status through the UI dropdown and verify the change is reflected

### Part 5 — Bug Report (10 min)
Document any bugs you found during testing. For each bug:
- **Title** — short description
- **Severity** — Critical / High / Medium / Low
- **Steps to reproduce**
- **Expected vs actual behavior**

---

## Getting Started

```bash
# Create a virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium

# Run your tests
pytest
```

Place all test files in the `tests/` directory. You're free to create any folder structure, conftest files, or helper modules you need.

---

## Tips
- The application **has bugs** — finding and documenting them is part of the assessment
- Code quality matters: clean structure, good naming, proper assertions
- Don't spend all your time on one section — coverage across all parts is important
- You can use the interactive API docs at `http://localhost:8000/docs` and `http://localhost:8001/docs`
- The seed data includes real-world CVE references — familiarize yourself with the data before writing tests

Good luck!
