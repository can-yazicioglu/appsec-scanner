"""Explicit two-account, read-only authorization checks. No ID enumeration."""

from contextlib import ExitStack, closing

from ..auth import authenticate, json_path, resolve_env, validate_auth
from ..http import SafeSession, origin
from ..models import finding, location


def validate_idor(scope, target, config):
    if not isinstance(config, dict) or set(config) != {"accounts", "resources"}:
        raise ValueError("IDOR requires accounts and explicit resources")
    accounts, resources = config["accounts"], config["resources"]
    if not isinstance(accounts, dict) or len(accounts) != 2:
        raise ValueError("IDOR requires exactly two isolated accounts")
    for auth in accounts.values():
        validate_auth(scope, target, auth)
        verify = auth.get("verify", {})
        if not verify.get("identity_path") or verify["identity_path"] not in verify.get("json", {}):
            raise ValueError("Each IDOR account needs an asserted JSON identity and identity_path")
    if not isinstance(resources, list) or not 1 <= len(resources) <= 30:
        raise ValueError("IDOR requires 1 to 30 explicit resources")
    for resource in resources:
        url = scope.require(resource["url"])
        if origin(url) != origin(target) or resource.get("method", "GET") != "GET":
            raise ValueError("IDOR supports read-only GET resources on the target origin")
        if resource.get("owner") not in accounts or resource.get("other") not in accounts:
            raise ValueError("Unknown resource account")
        if resource["owner"] == resource["other"] or resource.get("expected_other") not in ("deny", "allow"):
            raise ValueError("IDOR needs distinct accounts and explicit other-account outcome")
        for key in ("identity_match", "protected_match"):
            if not isinstance(resource.get(key), dict) or not resource[key]:
                raise ValueError("Resources require identity_match and protected_match JSON assertions")
        if set(resource["identity_match"]) & set(resource["protected_match"]):
            raise ValueError("Protected assertions must be separate from resource identity assertions")


def matches(response, expected):
    try:
        data = response.json()
        return all(json_path(data, path) == value for path, value in expected.items())
    except (ValueError, KeyError, IndexError, TypeError):
        return False


def check_idor(scan_config, parent):
    config = resolve_env(scan_config.idor)
    validate_idor(parent.scope, scan_config.target, config)
    findings, errors, limitations, completed = [], [], [], 0
    # Protected values are comparison-only. Never persist their contents.
    for resource in config["resources"]:
        for value in resource["protected_match"].values():
            if isinstance(value, str):
                parent.redactor.register(value)
    with ExitStack() as stack:
        clients, identities = {}, {}
        for name, auth in config["accounts"].items():
            session = stack.enter_context(
                closing(
                    SafeSession(
                        parent.scope,
                        timeout=parent.timeout,
                        budget=parent.budget,
                        redactor=parent.redactor,
                        max_bytes=parent.max_bytes,
                    )
                )
            )
            identities[name] = authenticate(session, scan_config.target, auth)
            clients[name] = session
        if len({str(value) for value in identities.values()}) != 2:
            raise ValueError("IDOR account verification resolved to the same identity")
        for resource in config["resources"]:
            try:
                observations = []
                for _ in range(2):
                    owner = clients[resource["owner"]].request("GET", resource["url"])
                    if owner.status_code != resource.get("owner_status", 200) or not matches(
                        owner, {**resource["identity_match"], **resource["protected_match"]}
                    ):
                        raise ValueError(
                            "Owner baseline did not satisfy explicit resource/protected-content expectations"
                        )
                    other = clients[resource["other"]].request("GET", resource["url"])
                    observations.append(
                        {
                            "owner_status": owner.status_code,
                            "owner_matches": True,
                            "other_status": other.status_code,
                            "other_identity_matches": matches(other, resource["identity_match"]),
                            "other_protected_matches": matches(other, resource["protected_match"]),
                        }
                    )
                access = [o["other_identity_matches"] and o["other_protected_matches"] for o in observations]
                if resource["expected_other"] == "deny" and any(access):
                    confirmed = all(access)
                    findings.append(
                        finding(
                            "dast.idor.read",
                            "Cross-account protected resource access",
                            location("DAST", url=resource["url"], method="GET"),
                            severity="high",
                            confidence="confirmed" if confirmed else "suspected",
                            category="A01:2021",
                            name="Broken Access Control",
                            description="The separately verified non-owner retrieved explicitly protected resource content."
                            if confirmed
                            else "Protected content appeared in one of two attempts; manual review required.",
                            remediation="Enforce server-side object ownership/authorization for every resource read. Derive identity from the authenticated session, deny by default, and test both permitted and prohibited roles.",
                            reproduction_steps=[
                                "Authenticate as the configured resource owner and verify identity and protected-field assertions.",
                                "In a separate authenticated non-owner session, request the same explicit GET resource twice.",
                                "Compare the configured protected fields; do not infer access from status alone.",
                            ],
                            evidence={
                                "request": {"url": parent.redactor.url(resource["url"]), "method": "GET"},
                                "response": {"status": observations[-1]["other_status"]},
                                "observations": [
                                    "Expected owner: allowed; expected non-owner: denied.",
                                    "Two independently verified account identities; separate cookie jars and headers.",
                                    "Protected values are withheld; assertion outcomes are recorded.",
                                ],
                                "verification": {
                                    "method": "two-account-content-comparison",
                                    "expected_other": "deny",
                                    "identity_fields": list(resource["identity_match"]),
                                    "protected_fields": list(resource["protected_match"]),
                                    "rounds": observations,
                                },
                            },
                        )
                    )
                elif resource["expected_other"] == "deny" and any(
                    o["other_status"] not in (401, 403, 404) for o in observations
                ):
                    limitations.append(
                        "Non-owner response had an unexpected status but protected content was not proven; manual review required."
                    )
                elif resource["expected_other"] == "allow" and not all(access):
                    limitations.append(
                        "Expected shared access was not verified; review the resource policy/configuration."
                    )
                completed += 1
            except Exception as exc:
                errors.append(
                    f"IDOR resource check incomplete: {type(exc).__name__}: {parent.redactor.text(str(exc))}"
                )
    return findings, errors, limitations, completed
