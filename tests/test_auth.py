import json

import pytest

from appsec.auth import authenticate
from appsec.browser import Browser
from appsec.checks.xss import check_xss
from appsec.discovery import Endpoint
from appsec.http import SafeSession
from appsec.redaction import Redactor
from appsec.scope import Scope, ScopeError


def auth_config(base, user="alice", encoding="json"):
    return {
        "login": {
            "url": base + "/login",
            "encoding": encoding,
            "fields": {"username": user, "password": "fixture-password"},
            "token_path": "authentication.token",
            "local_storage_key": "token",
        },
        "verify": {"url": base + "/me", "json": {"user": user}, "identity_path": "user"},
    }


def test_login_cookie_token_and_env(lab, client, monkeypatch):
    base, _ = lab
    config = auth_config(base)
    config["login"]["fields"]["password"] = "${FIXTURE_PASSWORD}"
    monkeypatch.setenv("FIXTURE_PASSWORD", "fixture-password")
    assert authenticate(client, base, config) == "alice"
    assert client.request("GET", base + "/me").json()["user"] == "alice"
    persisted = client.redactor.clean({"note": "fixture-password fixture-token-alice fixture-session-alice"})
    assert "fixture-" not in json.dumps(persisted)


def test_form_csrf_and_failed_login(lab, client):
    base, _ = lab
    config = auth_config(base, encoding="form")
    config["login"]["csrf"] = {
        "url": base + "/login",
        "field": "csrf_token",
        "selector": "input[name=csrf_token]",
    }
    assert authenticate(client, base, config) == "alice"
    config["verify"]["json"]["user"] = "bob"
    with pytest.raises(ValueError):
        authenticate(client, base, config)


def test_supplied_cookie_and_bearer(lab):
    base, _ = lab
    for config in ({"cookies": {"session": "fixture-session-bob"}}, {"bearer_token": "fixture-token-bob"}):
        client = SafeSession(Scope(["127.0.0.1"]), redactor=Redactor())
        try:
            authenticate(client, base, config)
            assert client.request("GET", base + "/me").json()["user"] == "bob"
        finally:
            client.close()


def test_auth_secrets_redacted_before_scope_is_persisted(lab):
    from appsec.config import ScanConfig
    from appsec.repository import Repository
    from appsec.scanner import run_scan

    config = ScanConfig(
        lab[0] + "/?q=fixture-password",
        ["127.0.0.1"],
        mode="manual",
        endpoints=[{"url": lab[0] + "/safe?q=hello"}],
        checks=["xss"],
        auth=auth_config(lab[0]),
    )
    with Repository(":memory:") as repo:
        sid = run_scan(config, repo)
        assert "fixture-password" not in json.dumps(repo.get_scan(sid))


def test_auth_unapproved_url_fails_before_request(lab, client):
    base, app = lab
    config = auth_config(base)
    config["login"]["url"] = "http://unapproved.invalid/login"
    with pytest.raises(ScopeError):
        authenticate(client, base, config)
    assert app.config["HITS"] == []


def test_credentials_do_not_cross_approved_origins(lab):
    from tests.fixtures.lab import live_lab

    with live_lab() as (other, _):
        client = SafeSession(Scope(["127.0.0.1"]))
        try:
            authenticate(client, lab[0], auth_config(lab[0]))
            assert client.request("GET", other + "/me").status_code == 401
        finally:
            client.close()


@pytest.mark.browser
def test_authenticated_browser_executes_probe(lab, client):
    base, _ = lab
    authenticate(client, base, auth_config(base))
    result = check_xss(client, Endpoint(base + "/private-xss?q=hello"), "q", browser_factory=Browser)
    assert result["confidence"] == "confirmed"
