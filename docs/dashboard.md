# Read-only findings dashboard

The Flask dashboard reads the same SQLite results as the CLI and uses the shared
[schema 1 contract](data-contract.md). It cannot initiate scans, change findings,
create a database, or apply migrations.

## Run locally

Create results with a CLI scan first, then start the dashboard from the project
environment:

```bash
appsec --db results/appsec.db dashboard --host 127.0.0.1 --port 5000
```

Open <http://127.0.0.1:5000>. The factory is
`appsec.dashboard.create_app(database_path)` for Flask-compatible hosting.
Debug mode is disabled. This is a local companion without user authentication;
keep the default loopback binding. Scanned application credentials are unrelated
to access to this dashboard.

## Investigate a scan

The workspace shows recent scans, status and type filters, and up to 50 runs per
page. Its totals describe the current page, not the entire database. Scan detail
shows totals for the whole scan and a separately labelled count of filtered
findings. Failed, partial and unfinished scans retain visible warnings, errors
and limitations; zero findings does not imply a clean assessment.

Severity describes potential impact. Confidence describes verification:
`confirmed` has recorded verification; `suspected` requires manual review.
Every SAST finding remains suspected. Finding detail includes the location,
OWASP edition/category, observations, verification facts, reproduction steps,
remediation, and available redacted request/response or source evidence.
Unavailable or inapplicable values remain null in exported records.

Filters accept multiple severity, confidence, OWASP category and check values.
Selections within one group combine with OR; different groups combine with AND.
An empty selection means unfiltered. The export link carries exactly the current
selection. Clear filters to download the complete scan.

| Route | Purpose |
| --- | --- |
| `/` | Scan history; `status`, `scan_type`, `page` query parameters |
| `/scans/<id>` | Findings; repeated `severity`, `confidence`, `owasp`, `check_id` parameters |
| `/findings/<id>` | Full finding evidence and remediation |
| `/scans/<id>/export.json` | JSON attachment with the same finding filters |

Malformed filters return HTTP 400; unknown IDs return 404. Missing, unreadable or
incompatible databases return 503, not a misleading empty scan. Requests open a
short-lived repository connection in SQLite read-only mode. Refresh to see new
CLI results; there is no live polling.

## Shared export API

```python
from appsec.exporter import dumps_export, export_scan
from appsec.repository import Repository

with Repository("results/appsec.db", read_only=True) as repository:
    snapshot = export_scan(repository, scan_id, severity=["high", "critical"],
                           confidence="suspected")
text = dumps_export(snapshot)
```

The envelope contains `schema_version`, UTC millisecond `exported_at`, `scan`,
`filters`, and `findings`. `filters` records canonical lists or null for all four
dimensions, so a subset cannot be mistaken for the full scan. Python uses
`owasp_category`; the dashboard query parameter is `owasp`. Check IDs use 1–128
ASCII letters/digits plus dot, underscore, colon or hyphen, starting with a
letter/digit. Non-string filter values are rejected.

Exports preserve Unicode, explicit nulls and original redacted payload strings;
they contain no rendered HTML. `dumps_export` emits indented JSON with a trailing
newline. Missing scans raise `ScanNotFoundError` (a `ValueError`); malformed
filters raise `InvalidFilterError` (a `ValueError`). Storage and serialization
failures propagate instead of silently replacing findings with an empty list.

## Rendering and verification

All evidence is treated as untrusted text. Jinja autoescaping stays enabled.
The redaction highlighter escapes the complete value before adding fixed markup
around the redaction placeholder. Scanned URLs are displayed as text, never as
links or embedded resources. The dashboard serves local CSS/JavaScript only,
sets a restrictive Content Security Policy, disables caching, and downloads JSON
as an attachment with `nosniff`. Core navigation, filters and export work without
JavaScript; JavaScript only adds a loading notice while filters reload and copying
a finding's JSON. It never inserts HTML.

Run the component checks:

```bash
python -m pytest tests/test_exporter.py tests/test_dashboard.py tests/test_dashboard_security.py -q
python -m pytest tests/test_dashboard_browser.py -q   # needs Playwright Chromium (browser marker)
```

Fixtures in `tests/dashboard_data.py` are explicitly labelled synthetic records,
not results attributed to Juice Shop or DVWA. They exercise persisted DAST/SAST
records, malicious evidence, all scan states and unavailable fields. Tests cover
filter/export consistency, persistence across restarts, read-only access,
invalid identifiers, redaction, escaped payloads, safe headers and absence of
write routes.

Visual QA used local Chromium at 1440×1100 and 390×844 for history, scan and
finding views. It verified a filter interaction and export-link selection,
without script errors, injected dialogs or document-wide horizontal overflow.
`tests/test_dashboard_browser.py` repeats this in Chromium at 1280 and 390 px:
stored payloads never open a dialog or raise a page error, the browser requests
nothing outside the dashboard, and on narrow screens each row stacks so severity,
confidence and scan status stay beside the title rather than scrolling off-screen. The dashboard
loads all findings for a selected scan, so it is intended for bounded local
scans rather than very large multi-user deployments.
