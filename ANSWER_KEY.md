# ANSWER KEY — Internal Use Only

**Do NOT share this file with candidates.**

---

## Seeded Bugs (8 total)

### Bug #1: Dismissed finding still returns 200 (should be 404)
- **File:** `services/dashboard-api/app/routes/findings.py` → `get_finding()`
- **Description:** `GET /findings/{id}` does not check the `is_dismissed` flag. Dismissed findings are still returned with HTTP 200 instead of 404.
- **Severity:** High
- **How to find it:**
  1. Pick any finding (e.g., ID 1)
  2. Dismiss it: `DELETE /findings/1` → 204
  3. `GET /findings/1` → returns 200 with full data (should be 404)
  4. Note: `GET /findings` (list) correctly excludes dismissed findings, but the detail endpoint doesn't
- **Fix:** Add `Finding.is_dismissed == False` filter to the query in `get_finding()`

---

### Bug #2: Invalid finding status transitions allowed
- **File:** `services/dashboard-api/app/routes/findings.py` → `update_finding_status()`
- **Description:** Any status transition is accepted. You can go from `resolved` → `open` or `false_positive` → `confirmed`, which violates the expected workflow.
- **Severity:** High
- **How to find it:**
  1. Find a finding with status `open` (e.g., ID 3)
  2. Update to `resolved`: `PUT /findings/3/status {"status": "resolved"}` → 200
  3. Update to `open`: `PUT /findings/3/status {"status": "open"}` → 200 (should fail)
  4. Or: set to `false_positive`, then to `in_progress` → succeeds (should fail)
- **Valid transitions should be:**
  - open → confirmed
  - confirmed → in_progress
  - in_progress → resolved
  - any → false_positive
- **Fix:** Add a transition map and validate `current_status → new_status`

---

### Bug #3: SQL injection on findings search
- **File:** `services/dashboard-api/app/routes/findings.py` → `search_findings()`
- **Description:** The search endpoint uses f-string formatting to build SQL, allowing SQL injection.
- **Severity:** Critical
- **How to find it:**
  ```
  GET /findings/search?q=CVE           → normal results
  GET /findings/search?q=' OR '1'='1   → returns ALL findings (injection)
  GET /findings/search?q=' UNION SELECT 1,2,3,4,5,6 --  → union attack
  ```
- **Fix:** Use SQLAlchemy parameterized queries instead of f-strings

---

### Bug #4: No CVSS score range constraint
- **File:** `db/init.sql` → `vulnerabilities` table
- **Description:** The `cvss_score` column (DOUBLE PRECISION) has no CHECK constraint. CVSS scores should be between 0.0 and 10.0, but the database accepts any value.
- **Severity:** Medium
- **How to find it:**
  1. Connect directly to PostgreSQL
  2. `UPDATE vulnerabilities SET cvss_score = 15.0 WHERE id = 1;` → succeeds
  3. `UPDATE vulnerabilities SET cvss_score = -5.0 WHERE id = 2;` → succeeds
  4. Both should be rejected
- **Fix:** `ALTER TABLE vulnerabilities ADD CONSTRAINT cvss_range CHECK (cvss_score >= 0 AND cvss_score <= 10);`

---

### Bug #5: Float precision on risk score / CVSS calculations
- **File:** `services/dashboard-api/app/routes/stats.py` → `get_risk_score()`
- **Also:** `db/init.sql` uses `DOUBLE PRECISION` for cvss_score instead of `NUMERIC(3,1)`
- **Description:** Risk score and average CVSS are calculated using Python float arithmetic with no rounding. The API returns values with 15+ decimal places like `7.566666666666666` or `6.128571428571428`.
- **Severity:** Medium
- **How to find it:**
  1. `GET /stats/risk-score`
  2. Observe `average_cvss` and `risk_score` fields have excessive decimal places
  3. Compare to expected: CVSS averages should be rounded to 1-2 decimal places
- **Fix:** Use `Decimal` arithmetic and `round()` on output, change DB column to `NUMERIC(3,1)`

---

### Bug #6: Pagination off-by-one in assets listing
- **File:** `services/scanner-service/app/routes/assets.py` → `list_assets()`
- **Description:** Offset uses `(page - 1) * per_page + 1` instead of `(page - 1) * per_page`. This skips the first asset on every page.
- **Severity:** Medium
- **How to find it:**
  1. There are 6 assets in seed data (IDs 1-6)
  2. `GET /assets?per_page=10` → returns 5 items but `total` says 6
  3. Asset ID=1 ("prod-web-01") never appears in paginated results
  4. `GET /assets/1` works fine (direct lookup doesn't use pagination)
- **Fix:** Change `offset((page - 1) * per_page + 1)` to `offset((page - 1) * per_page)`

---

### Bug #7: Duplicate findings on concurrent scan imports
- **File:** `services/scanner-service/app/routes/scans.py` → `create_scan()`
- **Also:** `db/init.sql` — no UNIQUE constraint on `(asset_id, vulnerability_id)` in findings
- **Description:** When running a scan, findings are created without checking if a finding already exists for the same asset + vulnerability combination. No DB-level unique constraint prevents duplicates either. Two concurrent scans (or even sequential ones) create duplicate findings.
- **Severity:** High
- **How to find it:**
  1. Run a scan: `POST /scans {"asset_id": 1, "scanner_name": "TestScan", "vulnerability_ids": [1]}`
  2. Run the same scan again → creates another duplicate finding
  3. `GET /findings?asset_id=1` now shows duplicates
  4. **Concurrent test:** Send two identical scan requests simultaneously using threads → both create findings
- **Fix:** Add `UNIQUE(asset_id, vulnerability_id)` constraint to findings table, or check for existing findings before insert with `SELECT ... FOR UPDATE`

---

### Bug #8: UI doesn't refresh after finding status change
- **File:** `services/dashboard-api/app/static/app.js` → `updateStatus()`
- **Description:** After changing a finding's status via the dropdown, the UI shows a success message but doesn't refresh the findings table or summary cards. The old status still shows until manual page reload or clicking "Refresh".
- **Severity:** Low
- **How to find it:**
  1. Open the UI at http://localhost:8000/
  2. Change a finding's status using the dropdown
  3. Success message appears, but the table still shows the old status
  4. Click "Refresh" — now the new status appears
- **Fix:** Add `loadFindings()` and `loadSummary()` calls after successful status update

---

## Scoring Guide

| Category | Max Points | Notes |
|----------|-----------|-------|
| **Part 1: API Tests** | 30 | Findings CRUD, search, error cases, code quality |
| **Part 2: DB Tests** | 20 | Direct SQL validation, constraint testing, data consistency |
| **Part 3: Integration** | 20 | Scan→findings flow, concurrent test (bonus) |
| **Part 4: Playwright** | 10 | Working UI tests, proper waits/selectors |
| **Part 5: Bug Report** | 20 | Number found, quality of descriptions, severity accuracy |

### Bug Finding Score
- 1-2 bugs: Below expectations
- 3-4 bugs: Meets expectations
- 5-6 bugs: Exceeds expectations
- 7-8 bugs: Exceptional

### Red Flags (immediate concerns)
- No assertions in tests (just calling APIs without checking)
- Hardcoded sleep instead of proper waits in Playwright
- No test isolation / tests depend on each other's execution order
- Can't connect to PostgreSQL at all
- Zero bugs found
- Doesn't understand HTTP status codes

### Green Flags (strong signals)
- Uses pytest fixtures and conftest.py for DB connections and API base URL
- Parametrized tests for edge cases
- Tests concurrent scenarios with threading
- Finds the SQL injection
- Clean bug reports with clear reproduction steps
- Uses proper Decimal comparisons for CVSS scores
- Validates data consistency across tables (findings ↔ vulnerabilities ↔ assets)
- Tests negative cases (invalid CVSS values, missing required fields)
