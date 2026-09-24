"""Explicit, origin-bound cookie/token/form/JSON login configuration."""

import os
import re
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from .http import origin


def resolve_env(value):
    if isinstance(value, dict):
        return {k: resolve_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_env(v) for v in value]
    if isinstance(value, str):
        match = re.fullmatch(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", value)
        if match:
            if match[1] not in os.environ:
                raise ValueError("Required authentication environment variable is not set")
            return os.environ[match[1]]
    return value


def json_path(value, path):
    for part in path.split("."):
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def register_auth_secrets(redactor, config):
    config = resolve_env(config)
    for group in (
        config.get("headers", {}),
        config.get("cookies", {}),
        config.get("local_storage", {}),
        (config.get("login") or {}).get("fields", {}),
    ):
        for value in group.values():
            redactor.register(value)
    redactor.register(config.get("bearer_token"))


def validate_auth(scope, target, config):
    for section in (config.get("login"), config.get("verify"), (config.get("login") or {}).get("csrf")):
        if section:
            url = scope.require(section["url"])
            if origin(url) != origin(target):
                raise ValueError("Authentication URLs must share the target origin")
    if config.get("login") and not config.get("verify"):
        raise ValueError("Automated login requires an explicit verification endpoint")


def authenticate(client, target, config):
    config = resolve_env(config)
    target = client.scope.require(target)
    validate_auth(client.scope, target, config)
    client.origin = origin(target)
    for value in config.get("headers", {}).values():
        client.redactor.register(value)
    headers = config.get("headers", {})
    if any(k.lower() not in ("authorization", "x-api-key", "x-auth-token") for k in headers):
        raise ValueError("Authentication supports only Authorization, X-API-Key, X-Auth-Token headers")
    client.auth_headers.update(headers)
    if config.get("bearer_token"):
        client.redactor.register(config["bearer_token"])
        client.auth_headers["Authorization"] = "Bearer " + config["bearer_token"]
    for key, value in config.get("cookies", {}).items():
        client.redactor.register(value)
        client.session.cookies.set(key, value, domain=urlsplit(target).hostname, path="/")
    for key, value in config.get("local_storage", {}).items():
        client.redactor.register(value)
        client.browser_storage[key] = value
    login = config.get("login")
    if login:
        fields = dict(login["fields"])
        for value in fields.values():
            client.redactor.register(value)
        if login.get("csrf"):
            csrf = login["csrf"]
            page = client.request("GET", csrf["url"])
            node = BeautifulSoup(page.text, "html.parser").select_one(csrf["selector"])
            if page.status_code != 200 or node is None or not node.get("value"):
                raise ValueError("Login CSRF field unavailable")
            fields[csrf["field"]] = node["value"]
            client.redactor.register(node["value"])
        encoding = login.get("encoding", "form")
        if encoding not in ("form", "json"):
            raise ValueError("Login encoding must be form or json")
        response = client.request("POST", login["url"], **{"data" if encoding == "form" else "json": fields})
        if not 200 <= response.status_code < 300:
            raise ValueError("Automated login failed")
        if login.get("token_path"):
            token = json_path(response.json(), login["token_path"])
            if not isinstance(token, str) or not token:
                raise ValueError("Login token missing")
            client.redactor.register(token)
            client.auth_headers["Authorization"] = "Bearer " + token
            if login.get("token_cookie"):
                client.session.cookies.set(
                    login["token_cookie"], token, domain=urlsplit(target).hostname, path="/"
                )
            if login.get("local_storage_key"):
                client.browser_storage[login["local_storage_key"]] = token
    verify = config.get("verify")
    identity = None
    if verify:
        response = client.request("GET", verify["url"])
        if response.status_code != verify.get("status", 200):
            raise ValueError("Authentication verification failed (status)")
        if not verify.get("json") and not verify.get("contains"):
            raise ValueError("Authentication verification needs a JSON field or content assertion")
        for path, expected in verify.get("json", {}).items():
            if json_path(response.json(), path) != expected:
                raise ValueError("Authentication verification failed (identity/content)")
        if verify.get("contains") and verify["contains"] not in response.text:
            raise ValueError("Authentication verification failed (content)")
        if verify.get("identity_path"):
            identity = json_path(response.json(), verify["identity_path"])
            if identity is None or isinstance(identity, (dict, list)):
                raise ValueError("Account identity must be a scalar")
    return identity
