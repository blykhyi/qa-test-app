# Bug Report — Vulnerability Dashboard

## Bug 1: Dismissed findings still accessible via GET endpoint

**Severity:** High

**Steps to reproduce:**
1. `POST /findings` — create a new finding (note the ID)
2. `DELETE /findings/{id}` — dismiss the finding (returns 204)
3. `GET /findings/{id}` — fetch the dismissed finding

**Expected:** HTTP 404 — finding was dismissed and should not be accessible
**Actual:** HTTP 200 — full finding data returned, including `is_dismissed: true`

**Note:** The list endpoint (`GET /findings`) correctly excludes dismissed findings, but the detail endpoint does not check the `is_dismissed` flag.

---

## Bug 2: Invalid finding status transitions allowed

**Severity:** High

**Steps to reproduce:**
1. Create a finding (status = `open`)
2. `PUT /findings/{id}/status {"status": "resolved"}` — skip workflow steps (returns 200)
3. `PUT /findings/{id}/status {"status": "open"}` — reopen a resolved finding (returns 200)

**Expected:** Status transitions should follow a defined workflow:
- `open` → `confirmed` → `in_progress` → `resolved`
- Any status → `false_positive`
- Reverse transitions (e.g., `resolved` → `open`, `false_positive` → `confirmed`) should return HTTP 400.

**Actual:** Any status transition is accepted. You can go from `resolved` → `open`, `false_positive` → `in_progress`, etc.

---

## Bug 3: SQL injection vulnerability on search endpoint

**Severity:** Critical

**Steps to reproduce:**
1. `GET /findings/search?q=CVE-2021` — returns expected results
2. `GET /findings/search?q=' OR '1'='1` — returns ALL findings (including dismissed)

**Expected:** Malicious input should be escaped. The search should return 0 results for nonsensical input.
**Actual:** The query is interpolated directly into SQL using f-strings. An attacker can extract arbitrary data from the database.

**Impact:** Full database read access. An attacker could extract all vulnerability data, asset information, and potentially use UNION-based injection to read any table.

---

## Bug 4: No database constraint on CVSS score range

**Severity:** Medium

**Steps to reproduce:**
1. Connect to PostgreSQL directly
2. `UPDATE vulnerabilities SET cvss_score = 15.0 WHERE id = 1;` — succeeds
3. `UPDATE vulnerabilities SET cvss_score = -5.0 WHERE id = 2;` — succeeds

**Expected:** CVSS scores must be between 0.0 and 10.0. The database should enforce this with a CHECK constraint.
**Actual:** No CHECK constraint exists. Any numeric value is accepted, which corrupts risk score calculations.

---

## Bug 5: Float precision errors in risk score and CVSS calculations

**Severity:** Medium

**Steps to reproduce:**
1. `GET /stats/risk-score`
2. Observe the `average_cvss` field: `8.007692307692308` (15 decimal places)
3. Observe `risk_score`: similar excessive precision

**Expected:** Numeric scores should be rounded to 1-2 decimal places (e.g., `8.01`). Financial and scoring calculations should use Decimal arithmetic.
**Actual:** Python float arithmetic produces imprecise values. The `cvss_score` DB column uses `DOUBLE PRECISION` instead of `NUMERIC`, and the Python code uses `float()` accumulation.

---

## Bug 6: Pagination off-by-one in assets listing

**Severity:** Medium

**Steps to reproduce:**
1. `GET /assets?per_page=50`
2. Response shows `total: 6` but `items` array contains only 5 assets
3. Asset ID 1 (`prod-web-01`) is never returned in any paginated page
4. `GET /assets/1` works fine (direct lookup bypasses pagination)

**Expected:** Page 1 with per_page=50 should return all 6 assets.
**Actual:** The offset calculation uses `(page - 1) * per_page + 1` instead of `(page - 1) * per_page`, skipping the first record on every page.

---

## Bug 7: Duplicate findings created by repeated/concurrent scans

**Severity:** High

**Steps to reproduce:**
1. `POST /scans {"asset_id": 1, "scanner_name": "Test", "vulnerability_ids": [1]}` — creates 1 finding
2. Run the exact same request again — creates another finding for the same asset + vulnerability
3. Query DB: `SELECT COUNT(*) FROM findings WHERE asset_id=1 AND vulnerability_id=1` — returns 3+ (1 from seed + duplicates)

**Expected:** A finding for the same (asset_id, vulnerability_id) combination should not be duplicated. Either a UNIQUE constraint should prevent it, or the scan logic should check for existing findings.
**Actual:** No uniqueness check at the DB or application level. Each scan blindly creates new finding rows, leading to inflated finding counts and incorrect dashboard statistics.

---

## Bug 8: UI does not refresh after changing finding status

**Severity:** Low

**Steps to reproduce:**
1. Open `http://localhost:8000/`
2. Use the status dropdown on any finding to change its status (e.g., to "Confirmed")
3. A success message appears ("Finding #X updated to confirmed")
4. The findings table still shows the old status
5. Click "Refresh" — now the new status appears

**Expected:** After a successful status update, the findings table and summary cards should automatically refresh to reflect the change.
**Actual:** Only the success message is shown. The table and summary cards remain stale until manually refreshed.
