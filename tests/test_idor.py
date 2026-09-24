import json

import pytest

from appsec.config import ScanConfig
from appsec.repository import Repository
from appsec.scanner import run_scan
from appsec.scope import ScopeError
from tests.test_auth import auth_config


def idor_config(base, mode="vulnerable", expected="deny"):
    return ScanConfig(
        base,
        ["127.0.0.1"],
        mode="manual",
        checks=["idor"],
        idor={
            "accounts": {
                "owner_account": auth_config(base, "alice"),
                "other_account": auth_config(base, "bob"),
            },
            "resources": [
                {
                    "url": base + f"/resource/{mode}/1",
                    "owner": "owner_account",
                    "other": "other_account",
                    "expected_other": expected,
                    "identity_match": {"id": 1, "owner": "alice"},
                    "protected_match": {"protected": "fixture-private-alice"},
                }
            ],
        },
    )


def test_confirms_protected_content_with_isolated_accounts(lab):
    with Repository(":memory:") as repo:
        sid = run_scan(idor_config(lab[0]), repo)
        assert repo.get_scan(sid)["status"] == "completed"
        result = repo.list_findings(sid)[0]
        assert result["confidence"] == "confirmed"
        assert len(result["evidence"]["verification"]["rounds"]) == 2
        assert "fixture-private" not in json.dumps(result)
        assert "fixture-token" not in json.dumps(result)
        assert lab[1].config["RESOURCE_USERS"] == ["alice", "bob", "alice", "bob"]


@pytest.mark.parametrize("mode,status", [("secure", "completed"), ("login-page", "partial")])
def test_denial_or_200_login_page_does_not_confirm(lab, mode, status):
    with Repository(":memory:") as repo:
        sid = run_scan(idor_config(lab[0], mode), repo)
        assert not repo.list_findings(sid)
        assert repo.get_scan(sid)["status"] == status


def test_owner_baseline_required_and_shared_policy_respected(lab):
    config = idor_config(lab[0])
    config.idor["resources"][0]["identity_match"]["id"] = 999
    with Repository(":memory:") as repo:
        sid = run_scan(config, repo)
        assert repo.get_scan(sid)["status"] == "failed"
        assert not repo.list_findings(sid)
        sid = run_scan(idor_config(lab[0], expected="allow"), repo)
        assert repo.get_scan(sid)["status"] == "completed"
        assert not repo.list_findings(sid)


def test_same_account_is_rejected(lab):
    config = idor_config(lab[0])
    config.idor["accounts"]["other_account"] = auth_config(lab[0], "alice")
    with Repository(":memory:") as repo:
        sid = run_scan(config, repo)
        assert repo.get_scan(sid)["status"] == "failed"
        assert not repo.list_findings(sid)


def test_unapproved_idor_resource_blocked_before_login(lab):
    config = idor_config(lab[0])
    config.idor["resources"][0]["url"] = "http://unapproved.invalid/item/1"
    with Repository(":memory:") as repo, pytest.raises(ScopeError):
        run_scan(config, repo)
    assert not lab[1].config["HITS"]
