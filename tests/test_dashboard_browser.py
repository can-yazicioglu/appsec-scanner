"""Real-browser checks that stored payloads stay inert and key signals stay visible.

All data is labelled FIXTURE data persisted through the real Repository.
"""

import threading

import pytest
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from appsec.dashboard import create_app
from tests.dashboard_data import build_store

pytestmark = pytest.mark.browser


@pytest.fixture
def dashboard(tmp_path):
    ids = build_store(tmp_path / "appsec.db")
    server = make_server("127.0.0.1", 0, create_app(tmp_path / "appsec.db"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", ids
    server.shutdown()
    thread.join()


@pytest.mark.parametrize("width", [1280, 390])
def test_malicious_evidence_never_executes_or_triggers_requests(dashboard, width):
    base, ids = dashboard
    paths = ["/", f"/scans/{ids['dast']}", f"/scans/{ids['sast']}"]
    paths += [f"/findings/{ids[k]}" for k in ("xss_confirmed", "xss_suspected", "idor", "js_url", "sast_py", "sast_js")]
    problems, requests = [], []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": width, "height": 900})
        page.on("dialog", lambda dialog: (problems.append(dialog.message), dialog.dismiss()))
        page.on("pageerror", lambda error: problems.append(str(error)))
        page.on("request", lambda request: requests.append(request.url))
        for path in paths:
            page.goto(base + path)
            page.wait_for_timeout(200)
            assert not page.evaluate("document.documentElement.scrollWidth > window.innerWidth + 1"), path
        browser.close()
    assert problems == []
    assert all(url.startswith(base + "/") for url in requests), sorted(set(requests))


def test_narrow_screens_keep_confidence_and_scan_status_beside_titles(dashboard):
    base, ids = dashboard
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 390, "height": 900})
        page.goto(f"{base}/scans/{ids['dast']}")
        row = page.locator(f'tr[data-finding-id="{ids["sqli_error"]}"]')
        for selector in (".severity", ".confidence-suspected"):
            box = row.locator(selector).bounding_box()
            assert box and box["x"] >= 0 and box["x"] + box["width"] <= 390, selector

        page.goto(base + "/")
        for status in ("failed", "partial", "running"):
            box = page.locator(f".status-{status}").first.bounding_box()
            assert box and box["x"] + box["width"] <= 390, status
        browser.close()
