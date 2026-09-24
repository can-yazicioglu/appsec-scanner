"""Dashboard presentation of the real SAST scanner's persisted output (v0.4)."""

import json
import re

from appsec import cli
from appsec.dashboard import create_app

SOURCE = "tests/fixtures/source"
FIXTURE_SECRETS = ("fixture-only-not-a-real-credential", "fixture-only-not-a-real-token")


def test_real_source_scan_renders_file_locations_manual_review_and_redaction(tmp_path):
    db, out = tmp_path / "sast.db", tmp_path / "cli.json"
    assert cli.main(["--db", str(db), "source-scan", SOURCE, "--output", str(out)]) == 0
    exported = json.loads(out.read_text(encoding="utf-8"))
    client = create_app(db).test_client()
    scan_id = exported["scan"]["id"]
    languages = {f["evidence"]["verification"].get("language") for f in exported["findings"]}
    assert {"python", "javascript"} <= languages

    listing = client.get(f"/scans/{scan_id}").get_data(as_text=True)
    for finding in exported["findings"]:
        location = finding["location"]
        assert f'<code class="path">{location["file_path"]}:{location["line"]}</code>' in listing
        html = client.get(f"/findings/{finding['id']}").get_data(as_text=True)
        assert "Manual review required." in html and "do not establish data flow" in html
        assert "Static source pattern (not executed, no data-flow analysis)" in html
        assert location["pattern_id"] in html and "Endpoint" not in html
        assert "Confirmed</span>" not in html
    assert listing.count("confidence-suspected") == len(exported["findings"])

    hardcoded = next(f for f in exported["findings"] if f["location"]["pattern_id"] == "hardcoded-secret")
    assert '<mark class="redacted">[REDACTED]</mark>' in client.get(f"/findings/{hardcoded['id']}").get_data(as_text=True)

    download = client.get(f"/scans/{scan_id}/export.json").get_data(as_text=True)
    stamp = re.compile(r'"exported_at": "[^"]+"')
    assert stamp.sub("", download) == stamp.sub("", out.read_text(encoding="utf-8"))
    pages = [listing, download] + [client.get(f"/findings/{f['id']}").get_data(as_text=True)
                                   for f in exported["findings"]]
    assert not any(secret in page for page in pages for secret in FIXTURE_SECRETS)
