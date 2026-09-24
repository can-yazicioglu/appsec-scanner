from functools import partial

from .browser import Browser
from .checks.sqli import check_sqli
from .checks.xss import check_xss
from .discovery import Endpoint, static_discover
from .http import Budget, SafeSession


def run_scan(config, repository):
    scope = config.validate()  # Fail closed before starting or issuing requests.
    scan_id = repository.start_scan(config.target, "DAST")
    client = SafeSession(scope, timeout=config.timeout, budget=Budget(config.max_requests, config.max_seconds),
                         redactor=repository.redactor)
    errors, limitations, successful = [], [], 0
    endpoints = {}
    try:
        if config.auth:
            from .auth import authenticate
            authenticate(client, config.target, config.auth)
        for item in config.endpoints:
            endpoint = Endpoint(**item)
            endpoints.setdefault(endpoint.key, endpoint)
        limits = dict(max_pages=config.max_pages, max_depth=config.max_depth, max_endpoints=config.max_endpoints)
        if config.mode == "static":
            discovered, failures, notes = static_discover(client, config.target, **limits)
        elif config.mode == "spa":
            with Browser(client, wait_ms=config.browser_wait_ms) as browser:
                discovered, failures, notes = browser.discover(config.target, **limits)
        else:
            discovered, failures, notes = [], [], []
        errors.extend(failures)
        limitations.extend(notes)
        for endpoint in discovered:
            if len(endpoints) < config.max_endpoints:
                endpoints.setdefault(endpoint.key, endpoint)
        for endpoint in endpoints.values():
            if endpoint.method == "POST" and not config.allow_post:
                limitations.append("POST endpoints discovered but not probed; set allow_post explicitly to enable.")
                continue
            parameters = endpoint.parameters
            if len(parameters) > config.max_parameters:
                limitations.append("Parameter limit reached for an endpoint.")
            for parameter in parameters[:config.max_parameters]:
                for check in config.checks:
                    if check == "idor":
                        continue
                    try:
                        if check == "xss":
                            factory = partial(Browser, wait_ms=config.browser_wait_ms) if config.verify_xss else None
                            result = check_xss(client, endpoint, parameter, browser_factory=factory)
                        else:
                            result = check_sqli(client, endpoint, parameter)
                        if result:
                            repository.add_finding(scan_id, result)
                            verification = result["evidence"]["verification"]
                            if verification.get("unavailable") or verification.get("incomplete"):
                                errors.append(f"{check}: verification was incomplete; inspect finding evidence.")
                        successful += 1
                    except Exception as exc:
                        errors.append(f"{check} at {repository.redactor.url(endpoint.url)}: {type(exc).__name__}: {repository.redactor.text(str(exc))}")
        if "idor" in config.checks:
            from .checks.idor import check_idor
            results, failures, notes, count = check_idor(config, client)
            for result in results:
                repository.add_finding(scan_id, result)
            errors.extend(failures)
            limitations.extend(notes)
            successful += count
        if not successful and not errors:
            limitations.append("No eligible inputs were tested; this is not evidence that the target is secure.")
    except Exception as exc:
        errors.append(f"Scan failed: {type(exc).__name__}: {repository.redactor.text(str(exc))}")
    finally:
        client.close()
        status = ("partial" if successful else "failed") if errors else ("partial" if limitations else "completed")
        repository.finish_scan(scan_id, status, errors=list(dict.fromkeys(errors)),
                               limitations=list(dict.fromkeys(limitations)))
    return scan_id
