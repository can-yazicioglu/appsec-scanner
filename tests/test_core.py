import json

import pytest

from appsec.checks.sqli import check_sqli, repeatable_boolean
from appsec.checks.xss import check_xss
from appsec.cli import main
from appsec.discovery import Endpoint, static_discover
from appsec.models import finding, location
from appsec.redaction import Redactor
from appsec.repository import Repository


def sample():
    return finding(
        "test.rule",
        "Fixture finding",
        location("DAST", url="http://localhost/?token=private", method="get"),
        description="Manual review",
        remediation="Fix it",
        reproduction_steps=["Inspect"],
        evidence={"observations": ["password='hidden'"], "verification": {"method": "fixture"}},
    )


def test_repository_redacts_merges_filters_survives_restart(tmp_path):
    path = tmp_path / "results.db"
    with Repository(path, Redactor(["private"])) as repo:
        sid = repo.start_scan("http://localhost/?token=private", "DAST")
        value = sample()
        value["severity"] = " HIGH "
        fid = repo.add_finding(sid, value)
        value["confidence"] = "confirmed"
        assert repo.add_finding(sid, value) == fid
        value["confidence"] = "suspected"
        assert repo.add_finding(sid, value) == fid
        repo.finish_scan(sid, "partial", limitations=["Fixture"])
    with Repository(path) as repo:
        results = repo.list_findings(sid, confidence="confirmed", severity="high")
        assert len(results) == 1
        assert results[0]["location"]["method"] == "GET"
        assert results[0]["location"]["file_path"] is None
        assert "private" not in json.dumps(repo.get_scan(sid))
        assert "hidden" not in json.dumps(results)
        with pytest.raises(ValueError):
            repo.list_findings(sid, confidence="certain")


def test_redaction_preserves_structural_enums_and_masks_session_urls():
    with Repository(":memory:", Redactor(["confirmed", "high", "a"])) as repo:
        sid = repo.start_scan("http://localhost/?sessionid=sensitive-session&auth=sensitive-auth", "DAST")
        value = sample()
        value.update(confidence="confirmed", severity="high")
        fid = repo.add_finding(sid, value)
        assert repo.get_finding(fid)["confidence"] == "confirmed"
        assert repo.get_finding(fid)["severity"] == "high"
        assert "sensitive-" not in repo.get_scan(sid)["scope"]


def test_interrupted_scan_is_not_completed(monkeypatch):
    from appsec.config import ScanConfig
    from appsec.scanner import run_scan

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("appsec.scanner.static_discover", interrupt)
    with Repository(":memory:") as repo:
        sid = run_scan(ScanConfig("http://127.0.0.1", ["127.0.0.1"]), repo)
        assert repo.get_scan(sid)["status"] == "failed"
        assert repo.get_scan(sid)["errors"] == ["Scan interrupted by operator."]


def test_static_links_forms_and_dedup(lab, client):
    endpoints, errors, _ = static_discover(client, lab[0])
    assert not errors
    assert any(e.url.endswith("/escaped") and e.inputs == {"q": "hello"} for e in endpoints)
    assert len({e.key for e in endpoints}) == len(endpoints)


def test_reflection_and_db_errors_stay_suspected(lab, client):
    xss = check_xss(client, Endpoint(lab[0] + "/escaped?q=hello"), "q")
    sql = check_sqli(client, Endpoint(lab[0] + "/error-only?q=hello"), "q")
    assert xss["confidence"] == sql["confidence"] == "suspected"


def test_sql_boolean_real_sqlite_confirmation(lab, client):
    result = check_sqli(client, Endpoint(lab[0] + "/sql?id=1"), "id")
    assert result["confidence"] == "confirmed"
    assert result["evidence"]["verification"]["repetitions"] == 3
    assert "fixture-item" not in json.dumps(result)
    assert check_sqli(client, Endpoint(lab[0] + "/safe?q=hello"), "q") is None
    assert check_sqli(client, Endpoint(lab[0] + "/escaped?q=hello"), "q") is None


def test_variation_never_confirms():
    stable = dict(baseline=[200, "a", 10], true=[200, "a", 10], control=[200, "a", 10], false=[200, "b", 1])
    assert repeatable_boolean([stable] * 3)
    assert not repeatable_boolean([stable, stable, {**stable, "baseline": [200, "changed", 10]}])
    assert not repeatable_boolean([{**stable, "false": [500, "b", 1]}] * 3)


def test_inaccessible_checks_are_errors(lab, client):
    for check in (check_xss, check_sqli):
        with pytest.raises(ValueError, match="baseline inaccessible"):
            check(client, Endpoint(lab[0] + "/private-xss?q=hello"), "q")


@pytest.mark.parametrize("encoding", ["form", "json"])
def test_post_reflection_keeps_suspected(lab, client, encoding):
    from appsec.browser import Browser

    endpoint = Endpoint(lab[0] + "/post-reflect", "POST", {"q": "hello"}, encoding)
    result = check_xss(client, endpoint, "q", browser_factory=Browser)
    assert result["confidence"] == "suspected"
    assert "POST reflection" in result["description"]


def test_cli_scan_export_and_failed_status(lab, tmp_path, capsys):
    db, output = tmp_path / "store.db", tmp_path / "out.json"
    assert (
        main(
            [
                "--db",
                str(db),
                "scan",
                lab[0],
                "--allow-host",
                "127.0.0.1",
                "--manual",
                "--endpoint",
                lab[0] + "/sql?id=1",
                "--check",
                "sqli",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    payload = json.loads(output.read_text())
    sid = payload["scan"]["id"]
    assert payload["findings"][0]["confidence"] == "confirmed"
    assert main(["--db", str(db), "export", sid, "--output", str(output)]) == 0
    assert (
        main(
            [
                "--db",
                str(db),
                "scan",
                lab[0],
                "--allow-host",
                "127.0.0.1",
                "--manual",
                "--endpoint",
                lab[0] + "/sql?id=1",
                "--max-requests",
                "1",
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert json.loads(output.read_text())["scan"]["status"] in ("failed", "partial")
