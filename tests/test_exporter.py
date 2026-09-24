import json
import re
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from appsec.exporter import InvalidFilterError, dumps_export, export_scan


class MemoryReads:
    """Only public reads: exporter must not rely on connection/SQL internals."""

    def __init__(self):
        self.scan = {
            "id": "scan-1",
            "scope": "http://localhost:3000",
            "scan_type": "DAST",
            "started_at": "2026-09-24T10:00:00.000Z",
            "finished_at": None,
            "status": "partial",
            "errors": ["A verification request timed out"],
            "limitations": ["Browser verification unavailable"],
        }
        self.findings = [{
            "id": "finding-1",
            "scan_id": "scan-1",
            "check_id": "xss.reflected",
            "title": "Reflected input — café",
            "severity": "high",
            "confidence": "suspected",
            "owasp": {"edition": "2021", "category": "A03:2021", "name": "Injection"},
            "description": "Reflection requires manual review.",
            "remediation": "Apply context-aware output encoding.",
            "reproduction_steps": ["Send the recorded probe."],
            "location": {
                "kind": "DAST", "url": "http://localhost:3000/?q=probe", "method": "GET",
                "parameter": "q", "input_location": "query", "file_path": None,
                "line": None, "pattern_id": None,
            },
            "evidence": {
                "request": {"method": "GET", "payload": "<script>probe()</script>"},
                "response": {"status": 200, "excerpt": "[REDACTED]"},
                "source": None,
                "observations": ["Probe reflected"],
                "verification": {"method": "reflection", "executed": False, "attempts": 2},
            },
            "created_at": "2026-09-24T10:00:01.000Z",
        }]
        self.findings_reads = 0

    def get_scan(self, scan_id):
        return self.scan if scan_id == self.scan["id"] else None

    def list_findings(self, scan_id):
        assert scan_id == self.scan["id"]
        self.findings_reads += 1
        return self.findings


def test_export_preserves_contract_and_is_an_independent_json_snapshot():
    repository = MemoryReads()
    original_scan, original_findings = deepcopy(repository.scan), deepcopy(repository.findings)
    before = datetime.now(timezone.utc)
    result = export_scan(repository, "scan-1")
    after = datetime.now(timezone.utc)

    assert set(result) == {"schema_version", "exported_at", "scan", "filters", "findings"}
    assert result["schema_version"] == 1
    assert result["filters"] == {"severity": None, "owasp_category": None, "confidence": None, "check_id": None}
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", result["exported_at"])
    timestamp = datetime.fromisoformat(result["exported_at"].replace("Z", "+00:00"))
    assert before.replace(microsecond=before.microsecond // 1000 * 1000) <= timestamp <= after
    assert json.loads(json.dumps(result, ensure_ascii=False)) == result
    assert result["scan"] == original_scan
    assert result["findings"] == original_findings
    assert repository.findings_reads == 1

    result["scan"]["errors"].append("Caller mutation")
    result["findings"][0]["evidence"]["observations"].append("Caller mutation")
    assert repository.scan == original_scan
    assert repository.findings == original_findings


def test_unknown_scan_raises_instead_of_exporting_an_empty_scan():
    repository = MemoryReads()
    with pytest.raises(ValueError, match="Scan not found"):
        export_scan(repository, "missing")
    assert repository.findings_reads == 0


def test_storage_errors_are_not_silently_exported_as_empty_results():
    class BrokenReads(MemoryReads):
        def list_findings(self, scan_id):
            raise RuntimeError("Storage unavailable")

    with pytest.raises(RuntimeError, match="Storage unavailable"):
        export_scan(BrokenReads(), "scan-1")


def test_non_json_values_are_rejected():
    repository = MemoryReads()
    repository.findings[0]["evidence"]["verification"]["elapsed"] = float("nan")
    with pytest.raises(ValueError):
        export_scan(repository, "scan-1")


def _mixed_reads():
    repository = MemoryReads()
    base = repository.findings[0]
    repository.findings = [
        {**deepcopy(base), "id": "f-high-a03", "severity": "high"},
        {**deepcopy(base), "id": "f-medium-a01", "severity": "medium",
         "owasp": {"edition": "2021", "category": "A01:2021", "name": "Broken Access Control"}},
        {**deepcopy(base), "id": "f-low-a03", "severity": "low"},
    ]
    return repository


def test_filters_select_or_within_and_across_dimensions_and_record_scope():
    repository = _mixed_reads()

    result = export_scan(repository, "scan-1", severity=["low", "high", "high"], owasp_category=["A03:2021"])
    assert [f["id"] for f in result["findings"]] == ["f-high-a03", "f-low-a03"]
    # Canonical: severity order, deduplicated, so equal selections export identically.
    assert result["filters"] == {"severity": ["high", "low"], "owasp_category": ["A03:2021"], "confidence": None, "check_id": None}

    result = export_scan(repository, "scan-1", owasp_category=["A01:2021"])
    assert [f["id"] for f in result["findings"]] == ["f-medium-a01"]
    assert result["filters"] == {"severity": None, "owasp_category": ["A01:2021"], "confidence": None, "check_id": None}

    result = export_scan(repository, "scan-1", severity=["critical"])
    assert result["findings"] == []
    assert result["scan"]["status"] == "partial"


def test_empty_filter_values_mean_unfiltered():
    result = export_scan(_mixed_reads(), "scan-1", severity=["", " "], owasp_category=[])
    assert result["filters"] == {"severity": None, "owasp_category": None, "confidence": None, "check_id": None}
    assert len(result["findings"]) == 3


@pytest.mark.parametrize("kwargs", [{"severity": ["severe"]}, {"severity": ["High"]},
                                    {"owasp_category": ["A03"]}, {"owasp_category": ["Injection"]}])
def test_invalid_filters_raise_before_reading(kwargs):
    repository = _mixed_reads()
    with pytest.raises(InvalidFilterError):
        export_scan(repository, "scan-1", **kwargs)
    assert repository.findings_reads == 0


def test_dumps_export_is_indented_utf8_json_with_trailing_newline():
    result = export_scan(MemoryReads(), "scan-1")
    text = dumps_export(result)
    assert text.endswith("}\n")
    assert "café" in text and "\\u00e9" not in text
    assert '\n  "schema_version": 1,' in text
    assert json.loads(text) == result


def test_real_repository_export_matches_contract_and_keeps_redaction(tmp_path):
    """Schema consistency against CX's persisted store, not only a stub."""
    from appsec.models import finding, location
    from appsec.repository import Repository

    with Repository(tmp_path / "store.db") as repo:
        scan_id = repo.start_scan("http://localhost:3000/?token=hunter2", "DAST")
        repo.add_finding(scan_id, finding(
            "dast.xss.reflected", "Reflected input indicator",
            location("DAST", url="http://localhost:3000/search?q=x", method="get", parameter="q",
                     input_location="query"),
            description="Reflection requires manual review.", remediation="Encode output.",
            reproduction_steps=["Send the probe."],
            evidence={"request": {"method": "GET", "payload": "<svg onload=alert(1)>",
                                  "headers": {"Authorization": "Bearer abc.def.ghi"}},
                      "observations": ["Probe reflected"], "verification": {"method": "reflection"}}))
        repo.finish_scan(scan_id, "completed")
        result = export_scan(repo, scan_id)

    assert set(result["scan"]) == {"id", "scope", "scan_type", "started_at", "finished_at", "status",
                                   "errors", "limitations"}
    assert "hunter2" not in json.dumps(result)
    [item] = result["findings"]
    assert set(item) == {"id", "scan_id", "check_id", "title", "severity", "confidence", "owasp", "description",
                         "remediation", "reproduction_steps", "location", "evidence", "created_at"}
    assert set(item["location"]) == {"kind", "url", "method", "parameter", "input_location", "file_path", "line",
                                     "pattern_id"}
    assert item["location"]["method"] == "GET" and item["location"]["line"] is None
    assert set(item["evidence"]) == {"request", "response", "source", "observations", "verification"}
    assert item["evidence"]["request"]["headers"]["Authorization"] == "[REDACTED]"
    assert item["evidence"]["request"]["payload"] == "<svg onload=alert(1)>"
    for stamp in (result["exported_at"], result["scan"]["started_at"], result["scan"]["finished_at"],
                  item["created_at"]):
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", stamp)


@pytest.mark.parametrize("kwargs", [{"severity": ["high", None]}, {"severity": 1},
                                    {"owasp_category": [42]}, {"confidence": [False]},
                                    {"check_id": [object()]}, {"confidence": "maybe"},
                                    {"check_id": "<script>"}, {"check_id": "a" * 129}])
def test_malformed_filter_types_and_identifiers_are_rejected(kwargs):
    with pytest.raises(InvalidFilterError):
        export_scan(_mixed_reads(), "scan-1", **kwargs)


def test_confidence_and_check_filters_compose_with_severity():
    repository = _mixed_reads()
    repository.findings[0]["confidence"] = "confirmed"
    repository.findings[0]["check_id"] = "dast.sqli"
    result = export_scan(repository, "scan-1", severity="high", confidence="confirmed", check_id="dast.sqli")
    assert [f["id"] for f in result["findings"]] == ["f-high-a03"]
    assert result["filters"]["confidence"] == ["confirmed"]
    assert result["filters"]["check_id"] == ["dast.sqli"]
    assert export_scan(repository, "scan-1", confidence="suspected", check_id="dast.sqli")["findings"] == []
