"""Evidence is untrusted: it must render as inert text and never drive requests.

All data is labelled FIXTURE data persisted through the real Repository.
"""

import json
from html.parser import HTMLParser
from pathlib import Path

import pytest
from flask import Flask

from appsec.dashboard import create_app
from appsec.dashboard.__main__ import main as run_dashboard
from tests.dashboard_data import IMG, JS_URL, PAYLOADS, SCRIPT, SECRET, SVG, build_store

TEMPLATES = Path(__file__).resolve().parents[1] / "appsec" / "dashboard" / "templates"


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def elements(html):
    parser = Elements()
    parser.feed(html)
    return parser.tags


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "appsec.db"
    return path, build_store(path)


@pytest.fixture
def client(store):
    return create_app(store[0]).test_client()


def all_pages(ids):
    urls = ["/", f"/scans/{ids['dast']}", f"/scans/{ids['partial']}", f"/scans/{ids['sast']}"]
    urls += [f"/findings/{ids[k]}" for k in ("xss_confirmed", "xss_suspected", "idor", "js_url", "sast_py", "sast_js")]
    return urls


def test_malicious_evidence_renders_as_escaped_text(client, store):
    _, ids = store
    for url in all_pages(ids):
        html = client.get(url).get_data(as_text=True)
        for payload in PAYLOADS:
            assert payload not in html, (url, payload)
        tags = elements(html)
        # The only script is the dashboard's own static file; no injected elements or handlers.
        assert [a.get("src") for t, a in tags if t == "script"] == ["/static/dashboard.js"], url
        assert not [t for t, _ in tags if t in ("svg", "img", "iframe", "object", "embed")], url
        assert not [(t, k) for t, a in tags for k in a if k.startswith("on")], url

    detail = client.get(f"/findings/{ids['xss_confirmed']}").get_data(as_text=True)
    assert "&lt;img src=x onerror=alert(1)&gt;" in detail  # title
    assert "&lt;script&gt;alert(document.cookie)&lt;/script&gt;" in detail  # description, observations
    assert "&#34;&gt;&lt;svg onload=alert(&#34;fixture&#34;)&gt;" in detail  # payload and steps
    listing = client.get(f"/scans/{ids['dast']}").get_data(as_text=True)
    assert "parameter <code>c&#34;&gt;&lt;svg onload=alert(&#34;fixture&#34;)&gt;</code>" in listing


def test_scanned_urls_never_become_links_or_embedded_resources(client, store):
    _, ids = store
    for url in all_pages(ids):
        html = client.get(url).get_data(as_text=True)
        for tag, attrs in elements(html):
            for name in ("href", "src", "action", "srcset", "poster", "data"):
                value = attrs.get(name)
                if value is not None:
                    assert (value.startswith("/") and not value.startswith("//")) or (name == "href" and value == "#main"), (url, tag, name, value)
                    assert "localhost:3000" not in value and "javascript:" not in value.lower()
    detail = client.get(f"/findings/{ids['js_url']}").get_data(as_text=True)
    assert f'<code class="url">{JS_URL}localhost:3000/</code>' in detail


def test_redacted_values_stay_redacted_in_pages_and_export(client, store):
    _, ids = store
    for url in all_pages(ids) + [f"/scans/{ids['dast']}/export.json", f"/scans/{ids['sast']}/export.json"]:
        assert SECRET not in client.get(url).get_data(as_text=True), url
    detail = client.get(f"/findings/{ids['xss_confirmed']}").get_data(as_text=True)
    assert '<mark class="redacted">[REDACTED]</mark>' in detail
    overview = client.get("/").get_data(as_text=True)
    assert '<mark class="redacted">%5BREDACTED%5D</mark>' in overview


def test_json_export_keeps_payloads_as_data_with_safe_headers(client, store):
    _, ids = store
    response = client.get(f"/scans/{ids['dast']}/export.json")
    assert response.mimetype == "application/json"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Content-Disposition"].startswith("attachment;")
    exported = {f["id"]: f for f in json.loads(response.get_data(as_text=True))["findings"]}
    evidence = exported[ids["xss_confirmed"]]["evidence"]
    # Data, not markup: JSON consumers receive the exact stored payload, unescaped.
    assert evidence["request"]["payload"] == SVG
    assert evidence["response"]["excerpt"] == f"<p>{SVG}</p>"
    assert exported[ids["xss_confirmed"]]["title"].endswith(IMG)


def test_security_headers_on_pages_errors_and_exports(client, store, tmp_path):
    _, ids = store
    responses = [client.get(u) for u in ("/", f"/findings/{ids['idor']}", f"/scans/{ids['dast']}/export.json",
                                        "/findings/missing", "/scans/x/export.json", "/?page=abc")]
    responses += [client.post("/"), create_app(tmp_path / "missing.db").test_client().get("/")]
    for response in responses:
        csp = response.headers["Content-Security-Policy"]
        assert "default-src 'none'" in csp and "script-src 'self'" in csp and "unsafe" not in csp
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "no-referrer"


def test_templates_never_disable_escaping():
    for template in TEMPLATES.glob("*.html"):
        text = template.read_text(encoding="utf-8")
        for unsafe in ("|safe", "| safe", "autoescape false", "Markup(", "|urlize"):
            assert unsafe not in text, (template.name, unsafe)


def test_dashboard_exposes_only_read_routes(client, store):
    app = create_app(store[0])
    for rule in app.url_map.iter_rules():
        assert rule.methods <= {"GET", "HEAD", "OPTIONS"}, rule
        assert not any(word in rule.rule for word in ("start", "run", "trigger", "new", "delete", "schedule")), rule
    ids = store[1]
    for url in ("/", f"/scans/{ids['dast']}", f"/scans/{ids['dast']}/export.json", f"/findings/{ids['idor']}"):
        for method in ("post", "put", "patch", "delete"):
            assert getattr(client, method)(url).status_code == 405, (method, url)
    html = client.get(f"/scans/{ids['dast']}").get_data(as_text=True)
    forms = [a for t, a in elements(html) if t == "form"]
    assert forms and all(a.get("method") == "get" for a in forms)


def test_documented_run_configuration_keeps_debug_off(store, monkeypatch):
    calls = []
    monkeypatch.setattr(Flask, "run", lambda self, **kwargs: calls.append((self, kwargs)))
    monkeypatch.setenv("FLASK_DEBUG", "1")
    run_dashboard(["--db", str(store[0])])
    [(app, kwargs)] = calls
    assert kwargs["debug"] is False and kwargs["use_reloader"] is False
    assert kwargs["host"] == "127.0.0.1"
    assert app.debug is False


def test_evidence_containing_the_redaction_marker_escapes_surroundings(client, store):
    detail = client.get(f"/findings/{store[1]['sast_py']}").get_data(as_text=True)
    assert "# &lt;script&gt;alert(document.cookie)&lt;/script&gt;" in detail
    assert SCRIPT not in detail
