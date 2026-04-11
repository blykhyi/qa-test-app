# Part 5 — Bug Report

Bugs observed during automated and exploratory testing of the Vulnerability Management Dashboard (Dashboard API `:8000`, Scanner Service `:8001`, PostgreSQL). Severities reflect impact to confidentiality, integrity, availability, and data quality for this assessment scope.

---

## 1. SQL injection in findings search

| Field | Details |
|--------|---------|
| **Title** | Unparameterized SQL in `GET /findings/search` allows injection via `q` |
| **Severity** | **Critical** |
| **Steps to reproduce** | 1. Ensure the Dashboard API is running.<br>2. `GET http://localhost:8000/findings/search?q=x'`<br>3. Observe HTTP 500 and server error (invalid SQL).<br>4. (Advanced) Craft `q` to alter `WHERE` logic—input is concatenated into raw SQL in `findings.py`. |
| **Expected** | Query parameters are bound safely; metacharacters in `q` are literals; response **200** with JSON list (possibly empty). |
| **Actual** | User input is embedded with an f-string into `text(raw_sql)`, breaking quoting and enabling classic SQL injection patterns. |

---

## 2. Dismissed findings still returned by `GET /findings/{id}`

| Field | Details |
|--------|---------|
| **Title** | GET detail does not treat dismissed findings as removed |
| **Severity** | **Medium** |
| **Steps to reproduce** | 1. `POST /findings` with valid `asset_id` / `vulnerability_id`.<br>2. `DELETE /findings/{id}` (dismiss).<br>3. `GET /findings/{id}`. |
| **Expected** | **404** (or equivalent “gone”) so clients cannot retrieve soft-deleted findings by id. |
| **Actual** | **200** with body including `is_dismissed: true`, inconsistent with list endpoints that exclude dismissed rows. |

---

## 3. No validation of status transitions

| Field | Details |
|--------|---------|
| **Title** | Any status can change to any other status |
| **Severity** | **Medium** |
| **Steps to reproduce** | 1. Create a finding; set status to `resolved` via `PUT /findings/{id}/status`.<br>2. `PUT` the same id to `open` (or other arbitrary transitions). |
| **Expected** | **400** for disallowed transitions (e.g. resolved → open) per workflow rules. |
| **Actual** | **200**; comments in code note missing transition validation. |

---

## 4. Database accepts out-of-range CVSS scores

| Field | Details |
|--------|---------|
| **Title** | No CHECK constraint on `vulnerabilities.cvss_score` |
| **Severity** | **Low** (data quality); higher if scores drive compliance reporting |
| **Steps to reproduce** | 1. Insert a row into `vulnerabilities` with `cvss_score = 99` (e.g. via SQL or test).<br>2. Row inserts successfully. |
| **Expected** | DB rejects values outside 0–10 (or documented scale). |
| **Actual** | `DOUBLE PRECISION` column with no `CHECK`; invalid values persist. |

---

## 5. Risk score uses floating-point accumulation

| Field | Details |
|--------|---------|
| **Title** | `/stats/risk-score` uses Python `float` for aggregates |
| **Severity** | **Low** |
| **Steps to reproduce** | 1. `GET http://localhost:8000/stats/risk-score`.<br>2. Inspect implementation in `stats.py` (float sums, composite formula). |
| **Expected** | Documented precision (e.g. `Decimal` or rounded values) for financial/risk metrics. |
| **Actual** | Float arithmetic throughout; unrounded values in JSON. |

---

## 6. Asset list pagination skips the first asset

| Field | Details |
|--------|---------|
| **Title** | Off-by-one in `GET /assets` offset |
| **Severity** | **Medium** |
| **Steps to reproduce** | 1. `GET http://localhost:8001/assets?page=1&per_page=100`.<br>2. Compare returned `items` to known seed data (`assets.id = 1` exists). |
| **Expected** | Page 1 includes the first asset when ordered by id. |
| **Actual** | Offset is `(page - 1) * per_page + 1`, so the lowest-id asset never appears and pagination is wrong. |

---

## 7. Duplicate findings for same asset and vulnerability

| Field | Details |
|--------|---------|
| **Title** | Scanner creates a new finding row on every scan; no deduplication |
| **Severity** | **High** (data integrity / noise) |
| **Steps to reproduce** | 1. Run `POST /scans` with the same `asset_id` and `vulnerability_ids` twice.<br>2. `GET /findings?asset_id=…` and count rows for that vulnerability. |
| **Expected** | At most one open finding per `(asset_id, vulnerability_id)`, or explicit merge/versioning. |
| **Actual** | Each scan inserts additional rows; concurrent scans can add duplicates (see integration tests). |

---

## 8. UI does not refresh findings or summary after status change

| Field | Details |
|--------|---------|
| **Title** | Successful status update leaves table and cards stale |
| **Severity** | **Medium** |
| **Steps to reproduce** | 1. Open `http://localhost:8000/`.<br>2. Change a finding’s status in the dropdown.<br>3. Observe success message; note row badge and summary cards until **Refresh** is clicked. |
| **Expected** | Table and summary reload (or targeted update) so the UI matches the API without a manual refresh. |
| **Actual** | `updateStatus` does not call `loadFindings()` / `loadSummary()` after success (noted in `app.js`). |

---

## 9. Search can return dismissed findings

| Field | Details |
|--------|---------|
| **Title** | `/findings/search` omits `is_dismissed` filter |
| **Severity** | **Medium** |
| **Steps to reproduce** | 1. Create a finding with a unique note string; dismiss it (`DELETE /findings/{id}`).<br>2. `GET /findings/search?q=<unique note>`. |
| **Expected** | Dismissed findings excluded, consistent with `GET /findings`. |
| **Actual** | Search SQL does not filter `is_dismissed`; row can still appear. |

---

## 10. Manual finding creation allows inactive assets

| Field | Details |
|--------|---------|
| **Title** | `POST /findings` does not require active asset |
| **Severity** | **Medium** |
| **Steps to reproduce** | 1. `POST /assets` on Scanner; `DELETE /assets/{id}` to deactivate.<br>2. `POST /findings` with that `asset_id` and a valid `vulnerability_id`. |
| **Expected** | **400** (align with Scanner, which rejects inactive assets for scans). |
| **Actual** | **201**; finding is created even though the asset is inactive. |

---

## 11. Scanner API does not send CORS headers for browser clients

| Field | Details |
|--------|---------|
| **Title** | Dashboard UI (origin `http://localhost:8000`) cannot reliably call Scanner (`:8001`) from the browser |
| **Severity** | **High** (for browser UI); **Low** for server-to-server or curl |
| **Steps to reproduce** | 1. Open DevTools Network on the dashboard.<br>2. Confirm requests to `http://localhost:8001/assets` (from `app.js`).<br>3. Inspect response headers for `Access-Control-Allow-Origin`. |
| **Expected** | CORS allows the dashboard origin (or proxy serves both under one host). |
| **Actual** | No `Access-Control-Allow-Origin` on typical GET responses; browser may block cross-origin fetches (Assets section empty or errored). |

---

## 12. Potential XSS via unsanitized HTML in findings table

| Field | Details |
|--------|---------|
| **Title** | Vulnerability titles/CVE text rendered with `innerHTML` |
| **Severity** | **High** if catalog text is ever attacker-controlled |
| **Steps to reproduce** | 1. If a vulnerability title in the DB contains HTML/JS (e.g. after bad import).<br>2. Load dashboard; observe rendering in the findings table. |
| **Expected** | Text escaped or DOM APIs that do not interpret HTML. |
| **Actual** | `renderFindings` builds rows with `innerHTML` from API strings. |

---

## 13. Vulnerability catalog ordering puts NULL CVSS first on DESC sort

| Field | Details |
|--------|---------|
| **Title** | `ORDER BY cvss_score DESC` surfaces NULL scores ahead of numeric scores |
| **Severity** | **Low** |
| **Steps to reproduce** | 1. Insert a vulnerability with `cvss_score` NULL.<br>2. `GET /vulnerabilities`. |
| **Expected** | Explicit `NULLS LAST` (or product-defined order). |
| **Actual** | PostgreSQL default for `DESC` sorts NULLs first; catalog order can be surprising. |

---

*End of report.*
