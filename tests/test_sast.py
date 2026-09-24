import json

import pytest

from appsec.cli import main
from appsec.exporter import export_scan
from appsec.models import normalize_finding
from appsec.repository import Repository
from appsec.sast import javascript_patterns, run_source_scan


def test_python_js_rules_suspected_and_source_relative(tmp_path):
    with Repository(tmp_path / "store.db") as repo:
        sid = run_source_scan("tests/fixtures/source", repo)
        results = repo.list_findings(sid)
        assert repo.get_scan(sid)["status"] == "completed"
        assert len(results) == 6
        assert {r["location"]["pattern_id"] for r in results} == {
            "eval",
            "sql-construction",
            "hardcoded-secret",
        }
        assert all(r["confidence"] == "suspected" for r in results)
        assert {r["location"]["file_path"] for r in results} == {"insecure.py", "insecure.js"}
        text = json.dumps(export_scan(repo, sid))
        assert "fixture-only-not-a-real" not in text
        assert all(
            r["location"]["url"] is None and r["evidence"]["verification"]["executed"] is False
            for r in results
        )
        wrong = {**results[0], "confidence": "confirmed"}
        with pytest.raises(ValueError, match="SAST findings must remain suspected"):
            normalize_finding(wrong)
    assert b"fixture-only-not-a-real" not in (tmp_path / "store.db").read_bytes()


def test_never_executes_and_skips_symlink_escape(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    side_effect = tmp_path / "executed"
    (source / "side_effect.py").write_text(
        f"from pathlib import Path\nPath({str(side_effect)!r}).touch()\neval('1')\n"
    )
    outside = tmp_path / "outside.py"
    outside.write_text("eval(input())")
    (source / "escape.py").symlink_to(outside)
    with Repository(":memory:") as repo:
        sid = run_source_scan(source, repo)
        assert repo.get_scan(sid)["status"] == "partial"
        assert len(repo.list_findings(sid)) == 1
    assert not side_effect.exists()


def test_parse_errors_and_bounds_are_not_clean(tmp_path):
    (tmp_path / "broken.py").write_text('password = "sensitive-syntax-error')
    with Repository(":memory:") as repo:
        sid = run_source_scan(tmp_path, repo)
        assert repo.get_scan(sid)["status"] == "failed"
        assert "sensitive-syntax-error" not in json.dumps(export_scan(repo, sid))
        sid = run_source_scan(tmp_path, repo, max_file_bytes=2)
        assert repo.get_scan(sid)["status"] == "partial"


def test_multiline_and_same_line_secrets_are_fully_masked(tmp_path):
    (tmp_path / "secrets.py").write_text(
        'API_KEY = """first-private-segment\nsecond-private-segment"""\neval(user); password="third-private-segment"\n'
    )
    (tmp_path / "secrets.js").write_text(
        'const apiKey = `fourth-private-segment\nfifth-private-segment`;\neval(user); const password="sixth-private-segment";'
    )
    with Repository(":memory:") as repo:
        sid = run_source_scan(tmp_path, repo)
        assert repo.get_scan(sid)["status"] == "completed"
        assert len(repo.list_findings(sid)) == 6
        assert "private-segment" not in json.dumps(export_scan(repo, sid))


def test_js_comments_and_literal_eval_are_not_calls():
    assert not javascript_patterns('// eval(input)\nconst note = "eval(input)";\n/* eval(input) */')
    rules = javascript_patterns("const query = `SELECT * FROM items WHERE id=${user}`;")
    assert (1, "sql-construction") in rules


def test_source_cli_export_and_dashboard(tmp_path):
    from appsec.dashboard import create_app

    database, output = tmp_path / "source.db", tmp_path / "source.json"
    assert main(["--db", str(database), "source-scan", "tests/fixtures/source", "--output", str(output)]) == 0
    payload = json.loads(output.read_text())
    client = create_app(database).test_client()
    result = client.get(f"/scans/{payload['scan']['id']}/export.json").get_json()
    assert result["findings"] == payload["findings"]
    page = client.get(f"/findings/{payload['findings'][0]['id']}")
    assert page.status_code == 200
    assert b"Manual review" in page.data or b"manual review" in page.data
