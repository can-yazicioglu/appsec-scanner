import pytest

from appsec.browser import Browser
from appsec.checks.xss import check_xss
from appsec.discovery import Endpoint

pytestmark = pytest.mark.browser


def test_execution_requires_matching_probe(lab, client):
    result = check_xss(client, Endpoint(lab[0] + "/xss?q=hello"), "q", browser_factory=Browser)
    assert result["confidence"] == "confirmed"
    assert result["evidence"]["verification"]["observed_probe_dialog"] is True
    escaped = check_xss(client, Endpoint(lab[0] + "/unrelated?q=hello"), "q", browser_factory=Browser)
    assert escaped["confidence"] == "suspected"


def test_spa_discovers_api_and_blocks_subrequests(lab, client):
    base, app = lab
    with Browser(client, wait_ms=100) as browser:
        endpoints, errors, _ = browser.discover(base + "/spa")
        assert any(e.url.endswith("/api/search") and e.inputs == {"q": "hello"} for e in endpoints)
        assert not errors
    with Browser(client, wait_ms=100) as browser:
        browser.discover(base + "/external")
        assert browser.errors
    assert "/outside" not in app.config["HITS"]


def test_browser_redirect_scope(lab, client):
    base, app = lab
    with Browser(client, wait_ms=100) as browser:
        browser.discover(base + "/redirect?to=" + base.replace("127.0.0.1", "localhost") + "/outside")
        assert browser.errors
    assert "/outside" not in app.config["HITS"]
