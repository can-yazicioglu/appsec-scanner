import pytest

from appsec.config import ScanConfig
from appsec.http import Budget, RequestFailure
from appsec.scope import Scope, ScopeError


@pytest.mark.parametrize("url", ["http://localhost.evil/", "http://evil.localhost/", "http://localhost@evil/",
                                      "http://evil@localhost/", "file:///etc/passwd", "http://localhost\\@evil/",
                                      "http://localhost:99999/", "http://localhost\n.evil/"])
def test_rejects_ambiguous_or_unapproved(url):
    with pytest.raises(ScopeError):
        Scope(["localhost"]).require(url)


def test_normalization_and_manual_enforcement():
    assert Scope(["LOCALHOST."]).require("http://LOCALHOST.:80/path") == "http://localhost/path"
    assert Scope(["::1"]).allows("http://[::1]:3000/")
    with pytest.raises(ScopeError):
        ScanConfig("http://localhost", ["localhost"], endpoints=[{"url": "http://evil/"}]).validate()


def test_redirect_does_not_contact_unapproved_host(lab, client):
    base, app = lab
    with pytest.raises(ScopeError):
        client.request("GET", base + "/redirect", params={"to": base.replace("127.0.0.1", "localhost") + "/outside"})
    assert "/outside" not in app.config["HITS"]


def test_budget():
    budget = Budget(1, 10)
    budget.take()
    with pytest.raises(RequestFailure):
        budget.take()
