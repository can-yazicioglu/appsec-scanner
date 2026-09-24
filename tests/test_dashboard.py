"""Dashboard filtering, export consistency and scan-state presentation.

All data is labelled FIXTURE data persisted through the real Repository.
"""

import json
import os
import re
import sqlite3

import pytest

from appsec import cli
from appsec.dashboard import create_app
from appsec.exporter import export_scan
from appsec.repository import Repository
from tests.dashboard_data import build_store

FINDING_ROW = re.compile(r'data-finding-id="([^"]+)"')


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "results" / "appsec.db"
    path.parent.mkdir()
    return path, build_store(path)


@pytest.fixture
def client(store):
    return create_app(store[0]).test_client()


def page(client, url, status=200):
    response = client.get(url)
    assert response.status_code == status, response.get_data(as_text=True)[:500]
    return response.get_data(as_text=True)


def listed(client, url):
    return FINDING_ROW.findall(page(client, url))


def names(ids, *keys):
    return {ids[k] for k in keys}


def without_timestamp(export):
    return {k: v for k, v in export.items() if k != "exported_at"}


def test_findings_list_shows_title_severity_confidence_location_and_owasp(client, store):
    _, ids = store
    html = page(client, f"/scans/{ids['dast']}")
    assert len(FINDING_ROW.findall(html)) == 7
    assert "[FIXTURE] SQL injection" in html
    assert 'class="severity severity-high">High<' in html
    assert "Confirmed</span>" in html and "Suspected · needs review</span>" in html
    assert '<code class="url">http://localhost:3000/rest/products/search</code>' in html
    assert "A01:2021" in html and "Broken Access Control" in html


@pytest.mark.parametrize(("query", "expected"), [
    ("", ("xss_confirmed", "xss_suspected", "sqli_confirmed", "sqli_error", "auth", "idor", "js_url")),
    ("?severity=high", ("xss_confirmed", "sqli_confirmed", "sqli_error", "idor")),
    ("?severity=low&severity=medium", ("xss_suspected", "auth", "js_url")),
    ("?owasp=A01:2021", ("idor",)),
    ("?owasp=A07:2021&owasp=A01:2021", ("auth", "idor")),
    ("?owasp=A03:2021&severity=medium", ("xss_suspected", "js_url")),
    ("?severity=critical", ()),
    ("?confidence=confirmed&severity=high", ("xss_confirmed", "sqli_confirmed", "idor")),
    ("?check_id=dast.sqli&confidence=suspected", ("sqli_error",)),
    ("?severity=&owasp=", ("xss_confirmed", "xss_suspected", "sqli_confirmed", "sqli_error", "auth", "idor",
                           "js_url")),
])
def test_filters_return_expected_records_and_match_the_export(client, store, query, expected):
    path, ids = store
    shown = listed(client, f"/scans/{ids['dast']}{query}")
    assert set(shown) == names(ids, *expected)

    response = client.get(f"/scans/{ids['dast']}/export.json{query}")
    assert response.status_code == 200
    exported = response.get_json()
    # Same records, same order, as the page — and as a direct exporter call.
    assert [f["id"] for f in exported["findings"]] == shown
    args = {"severity": re.findall(r"severity=(\w*)", query), "owasp_category": re.findall(r"owasp=([\w:]*)", query),
            "confidence": re.findall(r"confidence=(\w*)", query), "check_id": re.findall(r"check_id=([\w.]*)", query)}
    with Repository(path, read_only=True) as repo:
        assert without_timestamp(exported) == without_timestamp(export_scan(repo, ids["dast"], **args))


def test_empty_filter_result_is_explained_not_blank(client, store):
    html = page(client, f"/scans/{store[1]['dast']}?severity=critical")
    assert "No findings match this selection" in html and "0 of 7 findings shown" in html


def test_dashboard_export_is_byte_compatible_with_cli_export(client, store, tmp_path):
    path, ids = store
    out = tmp_path / "cli-export.json"
    assert cli.main(["--db", str(path), "export", ids["dast"], "--output", str(out)]) == 0
    response = client.get(f"/scans/{ids['dast']}/export.json")

    stamp = re.compile(r'"exported_at": "[^"]+"')
    assert stamp.sub("", response.get_data(as_text=True)) == stamp.sub("", out.read_text(encoding="utf-8"))
    assert json.loads(out.read_text(encoding="utf-8"))["filters"] == response.get_json()["filters"]


def test_filtered_export_records_its_scope(client, store):
    response = client.get(f"/scans/{store[1]['dast']}/export.json?severity=high&owasp=A01:2021")
    assert response.headers["Content-Disposition"].endswith('-filtered.json"')
    assert response.get_json()["filters"] == {"severity": ["high"], "owasp_category": ["A01:2021"],
                                              "confidence": None, "check_id": None}


def test_detail_retains_description_evidence_steps_remediation_and_confidence(client, store):
    html = page(client, f"/findings/{store[1]['sqli_confirmed']}")
    for text in ("Three repeated boolean differentials matched a stable baseline.",
                 "Use parameterized queries for all values.",
                 "<li>Probe q with the recorded boolean expressions.</li>",
                 "<li>Compare baseline, true, false and control response digests.</li>",
                 "Repeated boolean response differential", "boolean-differential",
                 "No data extraction performed.", "apple&#39; AND 1=1-- ", "Confirmed</span>"):
        assert text in html
    assert "This is an indicator, not a confirmed vulnerability." not in html


def test_suspected_high_severity_is_not_presented_as_verified(client, store):
    html = page(client, f"/findings/{store[1]['sqli_error']}")
    assert "Manual review required." in html
    assert "This is an indicator, not a confirmed vulnerability." in html
    assert "Database error string (indicator only)" in html
    assert "✓" not in html and "Confirmed</span>" not in html


def test_browser_check_label_does_not_claim_execution(client, store):
    html = page(client, f"/findings/{store[1]['xss_suspected']}")
    assert "Browser execution check for the probe&#39;s alert dialog" in html
    assert re.search(r"observed probe dialog</th>\s*<td><code>false</code>", html)
    assert "Manual review required." in html


def test_idor_detail_shows_expected_and_observed_access_with_redacted_credentials(client, store):
    html = page(client, f"/findings/{store[1]['idor']}")
    assert "Two-account protected-content comparison" in html and "Expected vs observed access" in html
    rows = [re.sub(r"<[^>]+>|\s+", " ", row).split() for row in re.findall(r"<tr>(.*?)</tr>", html, re.S)
            if "Expected<" in row or "Observed, round" in row]
    assert [" ".join(r) for r in rows] == [
        "Expected Allowed Denied",
        "Observed, round 1 HTTP 200 · baseline assertions met HTTP 200 · identity matched · protected content returned",
        "Observed, round 2 HTTP 200 · baseline assertions met "
        "HTTP 403 · identity not matched · protected content not returned",
    ]
    assert '<mark class="redacted">[REDACTED]</mark>' in html
    assert '<span class="kind">GET</span> <code class="url">http://localhost:3000/rest/basket/2</code>' in html


def test_sast_findings_show_file_line_rule_and_manual_review(client, store):
    _, ids = store
    listing = page(client, f"/scans/{ids['sast']}")
    assert '<code class="path">app/tasks.py:42</code>' in listing
    assert '<code class="path">frontend/src/search.js:7</code>' in listing
    assert listing.count("Suspected · needs review") >= 2

    html = page(client, f"/findings/{ids['sast_py']}")
    assert "Lightweight pattern checks do not establish data flow or exploitability." in html
    assert '<code class="path">app/tasks.py:42</code>' in html
    assert "<code>py.subprocess.shell-true</code>" in html
    assert "Endpoint" not in html
    assert 'api_key = &#34;<mark class="redacted">[REDACTED]</mark>&#34;' in html


def test_failed_partial_and_running_scans_are_not_presented_as_clean(client, store):
    _, ids = store
    overview = page(client, "/")
    for label in ("Failed", "Partial", "Not finished", "None recorded · incomplete scan"):
        assert label in overview

    failed = page(client, f"/scans/{ids['failed']}")
    assert "Scan failed — results are incomplete." in failed
    assert "results are incomplete" in failed and "Target unreachable" in failed

    partial = page(client, f"/scans/{ids['partial']}")
    assert "Partial scan." in partial and "Browser verification unavailable" in partial
    assert "Scan not finished." in page(client, f"/scans/{ids['running']}")

    clean = page(client, f"/scans/{ids['sast']}?severity=critical")
    assert "Scan failed" not in clean and "Partial scan" not in clean


def test_scan_list_filters_by_status_and_type(client, store):
    _, ids = store
    html = page(client, "/?status=failed")
    assert ids["failed"][:8] in html and ids["dast"][:8] not in html
    html = page(client, "/?scan_type=SAST")
    assert ids["sast"][:8] in html and ids["failed"][:8] not in html
    assert "No scans match these filters" in page(client, "/?status=failed&scan_type=SAST")


@pytest.mark.parametrize(("url", "status"), [
    ("/scans/{dast}?severity=severe", 400), ("/scans/{dast}?owasp=Injection", 400),
    ("/scans/{dast}/export.json?severity=severe", 400), ("/?status=done", 400), ("/?page=0", 400),
    ("/scans/does-not-exist", 404), ("/scans/does-not-exist/export.json", 404), ("/findings/does-not-exist", 404),
])
def test_invalid_filters_and_unknown_ids_are_errors_not_empty_results(client, store, url, status):
    response = client.get(url.format(**store[1]))
    assert response.status_code == status
    if url.split("?")[0].endswith(".json"):
        assert response.is_json and response.get_json()["error"]
    else:
        assert "No findings" not in response.get_data(as_text=True)


def test_empty_store_shows_guidance(tmp_path):
    path = tmp_path / "empty.db"
    Repository(path).close()
    html = page(create_app(path).test_client(), "/")
    assert "Your next investigation starts in the CLI" in html and "appsec scan --help" in html


def test_missing_store_is_unavailable_and_never_created(tmp_path):
    path = tmp_path / "results" / "missing.db"
    html = page(create_app(path).test_client(), "/", 503)
    assert "Findings store unavailable" in html
    assert not path.exists() and not path.parent.exists()


def test_unversioned_database_is_refused_without_migration(tmp_path):
    path = tmp_path / "other.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE unrelated (x)")
    before = path.read_bytes()
    page(create_app(path).test_client(), "/", 503)
    assert path.read_bytes() == before


def test_persisted_findings_survive_restart_and_new_records_appear(store):
    path, ids = store
    first = listed(create_app(path).test_client(), f"/scans/{ids['dast']}")
    restarted = create_app(path).test_client()
    assert listed(restarted, f"/scans/{ids['dast']}") == first

    with Repository(path) as repo:
        scan = repo.start_scan("FIXTURE later run", "DAST")
    assert scan[:8] in page(restarted, "/")


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores file permissions")
def test_dashboard_works_against_a_write_protected_store(store):
    path, ids = store
    os.chmod(path, 0o444)
    os.chmod(path.parent, 0o555)
    try:
        client = create_app(path).test_client()
        for url in ("/", f"/scans/{ids['dast']}", f"/findings/{ids['idor']}", f"/scans/{ids['sast']}/export.json"):
            page(client, url)
    finally:
        os.chmod(path.parent, 0o755)
        os.chmod(path, 0o644)


def test_real_idor_scan_output_shows_expected_versus_observed_access(lab, tmp_path):
    """Presentation against CX's actual IDOR check persisted from the controlled lab."""
    from appsec.scanner import run_scan
    from tests.test_idor import idor_config

    path = tmp_path / "idor.db"
    with Repository(path) as repo:
        scan_id = run_scan(idor_config(lab[0]), repo)
        [record] = repo.list_findings(scan_id)
    html = page(create_app(path).test_client(), f"/findings/{record['id']}")
    assert "Expected vs observed access" in html and "Two-account protected-content comparison" in html
    assert html.count("HTTP 200 · identity matched · protected content returned") == 2
    assert "fixture-private" not in html
