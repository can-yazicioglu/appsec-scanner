"""GET-only dashboard routes. There are deliberately no scan or write endpoints."""

from __future__ import annotations

import json
import re
from collections import Counter

from flask import Blueprint, Response, abort, render_template, request

from ..exporter import InvalidFilterError, dumps_export, export_scan
from ..models import CONFIDENCES, SEVERITIES, STATUSES
from . import get_repository

bp = Blueprint("dashboard", __name__)
SCANS_PER_PAGE = 50


def _requested_filters():
    return {"severity": request.args.getlist("severity"), "owasp_category": request.args.getlist("owasp"),
            "confidence": request.args.getlist("confidence"), "check_id": request.args.getlist("check_id")}


def _query(filters):
    """Query-string values reproducing a canonical filter selection."""
    return {"severity": filters["severity"] or [], "owasp": filters["owasp_category"] or [],
            "confidence": filters["confidence"] or [], "check_id": filters["check_id"] or []}


@bp.get("/")
def scans():
    try:
        page = int(request.args.get("page", "1"))
        if not 1 <= page <= 100_000:
            raise ValueError
    except ValueError:
        raise InvalidFilterError("Page must be a whole number between 1 and 100000.") from None
    status, scan_type = request.args.get("status") or None, request.args.get("scan_type") or None
    if status is not None and status not in STATUSES:
        raise InvalidFilterError("Unknown scan status.")
    if scan_type is not None and scan_type not in ("DAST", "SAST"):
        raise InvalidFilterError("Unknown scan type.")
    repository = get_repository()
    rows = repository.list_scans(status=status, scan_type=scan_type,
                                 limit=SCANS_PER_PAGE + 1, offset=(page - 1) * SCANS_PER_PAGE)
    counts = {scan["id"]: Counter(f["severity"] for f in repository.list_findings(scan["id"]))
              for scan in rows[:SCANS_PER_PAGE]}
    return render_template("scans.html", scans=rows[:SCANS_PER_PAGE], counts=counts, severities=SEVERITIES,
                           page=page, has_next=len(rows) > SCANS_PER_PAGE, statuses=STATUSES,
                           status=status, scan_type=scan_type,
                           total_findings=sum(sum(c.values()) for c in counts.values()))


@bp.get("/scans/<scan_id>")
def scan(scan_id):
    repository = get_repository()
    # The table shows exactly what the export route returns for this query.
    export = export_scan(repository, scan_id, **_requested_filters())
    everything = export_scan(repository, scan_id)["findings"]
    categories = {f["owasp"]["category"]: f["owasp"]["name"] for f in everything}
    for category in export["filters"]["owasp_category"] or []:
        categories.setdefault(category, None)
    checks = sorted({f["check_id"] for f in everything} | set(export["filters"]["check_id"] or []))
    return render_template(
        "scan.html", scan=export["scan"], findings=export["findings"], filters=export["filters"],
        query=_query(export["filters"]), total=len(everything), severities=SEVERITIES,
        severity_counts=Counter(f["severity"] for f in everything),
        owasp_options=sorted(categories.items()), checks=checks, confidences=CONFIDENCES,
        confirmed_count=sum(f["confidence"] == "confirmed" for f in everything))


@bp.get("/scans/<scan_id>/export.json")
def export(scan_id):
    result = export_scan(get_repository(), scan_id, **_requested_filters())
    filtered = any(result["filters"].values())
    name = re.sub(r"[^A-Za-z0-9-]", "", scan_id)[:36] or "scan"
    response = Response(dumps_export(result), mimetype="application/json")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="appsec-scan-{name}{"-filtered" if filtered else ""}.json"')
    return response


@bp.get("/findings/<finding_id>")
def finding(finding_id):
    repository = get_repository()
    item = repository.get_finding(finding_id)
    if item is None:
        abort(404)
    scan = repository.get_scan(item["scan_id"])
    return render_template("finding.html", finding=item, scan=scan,
                           record_json=json.dumps(item, ensure_ascii=False, indent=2))
