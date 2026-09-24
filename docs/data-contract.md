# Data contract — schema 1

CX owns this contract, migrations and writes. CL explicitly agreed to this
interface on 2026-09-24 before implementation. CL owns serialization and UI.

## Migration and storage

SQLite `PRAGMA user_version=1`. Forward, transactional migrations only; reject
newer versions. Back up before any future migration; no automatic downgrade.
Foreign keys enabled. SQL parameters are always bound.

`scans`: `id TEXT PRIMARY KEY` (UUID), `scope TEXT NOT NULL` (redacted target URL
or source scope), `scan_type TEXT NOT NULL` (`DAST`, `SAST`),
`started_at TEXT NOT NULL`, `finished_at TEXT NULL`, `status TEXT NOT NULL`
(`running`, `completed`, `partial`, `failed`), `errors TEXT NOT NULL` and
`limitations TEXT NOT NULL` (JSON arrays of strings).

`findings`: `id TEXT PRIMARY KEY` (UUID), `scan_id TEXT NOT NULL REFERENCES
scans(id)`, `fingerprint TEXT NOT NULL` (internal SHA256 identity),
`check_id TEXT NOT NULL`, `title TEXT NOT NULL`, `severity TEXT NOT NULL`
(`critical`, `high`, `medium`, `low`, `informational`), `confidence TEXT NOT NULL`
(`confirmed`, `suspected`), `owasp TEXT NOT NULL` (JSON object),
`description TEXT NOT NULL`, `remediation TEXT NOT NULL`,
`reproduction_steps TEXT NOT NULL` (JSON string array), `location TEXT NOT NULL`
(JSON object), `evidence TEXT NOT NULL` (JSON object), `created_at TEXT NOT NULL`.
`UNIQUE(scan_id, fingerprint)`. Severity is impact; confidence is evidence quality.
Suspected means manual review required, including **all** SAST findings.

OWASP object: `edition: "2021"`, `category: "A03:2021"`, `name: "Injection"`
(other mappings documented in README). No mixing editions.

Location has all keys: `kind` (`DAST`/`SAST`), `url`, `method`, `parameter`,
`input_location` (`query`/`form`/`json`/null), `file_path`, `line`, `pattern_id`.
Except kind, all may be null. DAST uses URL, uppercase HTTP method, optional
parameter/input location. SAST uses source-relative POSIX path, 1-based integer
line and rule pattern ID. Unavailable or inapplicable = JSON null, never an empty
string or invented value.

Evidence has all keys: `request` (object/null), `response` (object/null), `source`
(string/null), `observations` (string array), `verification` (object with `method`
and check-specific facts). Request: method, redacted URL, parameter, payload as
applicable. Response: status, media type and relevant redacted excerpt as
applicable. Verification records probe identity, repeated observations and
limitations; reflection/database errors alone cannot establish confirmation.

Timestamps are UTC ISO 8601 with milliseconds and trailing `Z`.
Finding identity is scan + check + normalized, redacted location; repeated probes merge,
preserve original ID/time and never downgrade confirmed to suspected. Different
scans retain independent findings. Fingerprint is not exported.

Redact **before** persistence. Known configured credentials/tokens (including
URL-encoded variants), secret-bearing keys, Authorization/Cookie/Set-Cookie and
common password/token assignments use `[REDACTED]`. HTTP evidence is deliberately
minimal: matched probe/error excerpts or counts/digests, never full response
bodies. Secret-rule source evidence masks literal values. Exception messages
are sanitized; never log raw authentication responses. This is minimization,
not a general DLP guarantee; use local test data. Credentials stay in ignored
`local/` files or environment variables.

## Public repository interface

`from appsec.repository import Repository`

`Repository(path, redactor=None, *, read_only=False)` opens/initializes storage;
read_only uses SQLite URI `mode=ro` plus `query_only` and rejects missing or
noncurrent schemas without migration. `.close()` and context manager
supported. Returned values are ordinary JSON-compatible dicts, independent of
the connection. Dashboard and exporter use only these reads:

* `list_scans(*, status=None, scan_type=None, limit=100, offset=0)` returns scans
  newest first (started_at DESC, id DESC). Limit 1–1000, offset >=0.
* `get_scan(scan_id)` returns a scan or None.
* `list_findings(scan_id, *, severity=None, confidence=None, check_id=None)`
  returns findings ordered critical to informational, then created_at, id.
  Filters are exact equality, combined with AND; invalid enums raise ValueError.
  Unknown scan yields [].
* `get_finding(finding_id)` returns a finding or None.

Scan dict contains exactly the scan fields above, with JSON arrays decoded.
Finding dict contains all finding fields above except internal fingerprint,
with JSON structures decoded. Unknown identifiers are never synthesized.

Writes owned by CX: `start_scan(scope, scan_type) -> str`,
`finish_scan(scan_id, status, *, errors=None, limitations=None)`,
`add_finding(scan_id, finding) -> str` (finding normalized at persistence boundary).

## CL exporter (v0.1)

`from appsec.exporter import export_scan`

`export_scan(repository, scan_id, *, severity=None, owasp_category=None, confidence=None, check_id=None) -> dict` returns:
`{"schema_version": 1, "exported_at": "...Z", "scan": {...}, "filters": {...}, "findings": [...]}`.
The additive `filters` field was reviewed and accepted by CX and CL during the
v0.1 checkpoint. Both filter arguments accept a string or iterable of strings.
`filters` always contains `severity`, `owasp_category`, `confidence`, and `check_id`, each a canonical list
or null (unfiltered). OR within a dimension, AND across dimensions. No filters
means all findings. Invalid enum/category/type values raise ValueError. Check IDs
are exact identifiers; unknown IDs match nothing. These extra dimensions were
agreed by CX/CL during v0.2 integration. Dashboard
views and downloads must apply the same filters. `dumps_export(envelope)` returns
the shared UTF-8-compatible indented JSON string with trailing newline.
Missing scan raises ValueError. Include all findings, including suspected;
preserve nulls, Unicode, lists and numbers, no HTML markup or internal SQL.
CLI writes UTF-8 JSON with indentation and newline. Dashboard uses same function
at `/scans/<id>/export.json`; missing IDs produce HTTP 404. Export errors are not
silently converted to empty scans. Dashboard creates no scans and performs no
updates. Factory: `appsec.dashboard.create_app(database_path)`.
