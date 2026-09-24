"""Versioned JSON snapshots shared by the CLI and read-only dashboard.

Repository reads are already redacted. Export deliberately preserves their
values, including suspected findings and explicit nulls, without HTML rendering.

The dashboard renders the findings returned by ``export_scan`` and serves the
same call at ``/scans/<id>/export.json``, so the page and the download cannot
disagree about which findings are in scope.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any, Protocol

from .models import CONFIDENCES, SEVERITIES

SCHEMA_VERSION = 1
OWASP_CATEGORY = re.compile(r"A(0[1-9]|10):\d{4}")
CHECK_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")


class ExportRepository(Protocol):
    """The portion of the stable repository interface required for export."""

    def get_scan(self, scan_id: str) -> dict[str, Any] | None: ...

    def list_findings(self, scan_id: str) -> list[dict[str, Any]]: ...


class ScanNotFoundError(ValueError):
    """The requested scan does not exist; never exported as an empty scan."""


class InvalidFilterError(ValueError):
    """A filter value is not a contract enum or OWASP category."""


def normalize_filters(severity: Iterable[str] | None = None,
                      owasp_category: Iterable[str] | None = None,
                      confidence: Iterable[str] | None = None,
                      check_id: Iterable[str] | None = None) -> dict[str, list[str] | None]:
    """Validate filter values and return their canonical envelope form.

    ``None`` or an empty selection means the dimension is unfiltered. Values
    within a dimension are alternatives (OR); dimensions combine with AND.
    """
    severities = _selection(severity)
    if severities is not None:
        unknown = sorted(set(severities) - set(SEVERITIES))
        if unknown:
            raise InvalidFilterError(f"Unknown severity: {', '.join(unknown)}")
        severities = [s for s in SEVERITIES if s in severities]
    categories = _selection(owasp_category)
    if categories is not None:
        invalid = sorted(c for c in set(categories) if not OWASP_CATEGORY.fullmatch(c))
        if invalid:
            raise InvalidFilterError(f"Invalid OWASP category: {', '.join(invalid)}")
        categories = sorted(set(categories))
    confidences = _selection(confidence)
    if confidences is not None:
        unknown = sorted(set(confidences) - set(CONFIDENCES))
        if unknown:
            raise InvalidFilterError(f"Unknown confidence: {', '.join(unknown)}")
        confidences = [c for c in CONFIDENCES if c in confidences]
    checks = _selection(check_id)
    if checks is not None:
        if any(not CHECK_ID.fullmatch(value) for value in checks):
            raise InvalidFilterError("Check identifiers must be 1–128 letters, digits, dots, underscores, colons or hyphens.")
        checks = sorted(set(checks))
    return {"severity": severities, "owasp_category": categories, "confidence": confidences, "check_id": checks}


def _selection(values: Iterable[str] | None) -> list[str] | None:
    if values is None:
        return None
    if isinstance(values, str):
        values = [values]
    try:
        values = list(values)
    except TypeError as exc:
        raise InvalidFilterError("Filters must be a string or an iterable of strings.") from exc
    if any(not isinstance(value, str) for value in values):
        raise InvalidFilterError("Filter values must be strings.")
    selected = [v.strip() for v in values if v.strip()]
    return selected or None


def matches_filters(finding: dict[str, Any], filters: dict[str, list[str] | None]) -> bool:
    if filters["severity"] is not None and finding["severity"] not in filters["severity"]:
        return False
    if filters["owasp_category"] is not None and finding["owasp"]["category"] not in filters["owasp_category"]:
        return False
    for field in ("confidence", "check_id"):
        if filters[field] is not None and finding[field] not in filters[field]:
            return False
    return True


def export_scan(repository: ExportRepository, scan_id: str, *,
                severity: Iterable[str] | None = None,
                owasp_category: Iterable[str] | None = None,
                confidence: Iterable[str] | None = None,
                check_id: Iterable[str] | None = None) -> dict[str, Any]:
    """Return an independent JSON-compatible snapshot of one stored scan.

    Without filters every finding is exported, including suspected ones. The
    envelope's ``filters`` object always records the applied selection, so a
    filtered export cannot be mistaken for the complete scan.

    Raises ``ScanNotFoundError`` (a ``ValueError``) for an unknown scan and
    ``InvalidFilterError`` (a ``ValueError``) for invalid filter values.
    Storage and serialization failures propagate so callers cannot mistake an
    incomplete export for a clean scan.
    """
    filters = normalize_filters(severity, owasp_category, confidence, check_id)
    scan = repository.get_scan(scan_id)
    if scan is None:
        raise ScanNotFoundError(f"Scan not found: {scan_id}")

    result = {
        "schema_version": SCHEMA_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "scan": scan,
        "filters": filters,
        "findings": [f for f in repository.list_findings(scan_id) if matches_filters(f, filters)],
    }
    # Round-tripping also rejects non-JSON repository data and non-finite floats.
    # It avoids leaking shared mutable values to callers of this public API.
    return json.loads(json.dumps(result, ensure_ascii=False, allow_nan=False))


def dumps_export(export: dict[str, Any]) -> str:
    """Serialize an export exactly as the CLI and dashboard download write it."""
    return json.dumps(export, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
