import secrets

from ..models import finding, location


def check_xss(client, endpoint, parameter, *, browser_factory=None):
    nonce = "appsec_" + secrets.token_hex(16)
    payload = f'\"><svg onload=alert("{nonce}")>'
    response = endpoint.send(client, parameter, payload)
    if nonce not in response.text:
        return None
    confirmed = False
    verification = {"method": "reflection", "probe_id": nonce, "observed_probe_dialog": False}
    reason = "Reflection alone does not prove execution; manual review required."
    if browser_factory and endpoint.method == "GET":
        try:
            with browser_factory(client) as browser:
                confirmed, verification = browser.verify_xss(endpoint.probe_url(parameter, payload), nonce)
            reason = "Browser observed this probe's unique alert." if confirmed else "Browser did not observe probe execution."
        except Exception as exc:
            reason = f"Browser verification unavailable ({type(exc).__name__}); manual review required."
            verification["unavailable"] = type(exc).__name__
    elif endpoint.method != "GET":
        reason = "POST reflection found; browser execution verification supports GET query inputs only. Manual review required."
    raw = payload in response.text
    return finding(
        "dast.xss.reflected", "Reflected cross-site scripting" if confirmed else "Reflected input indicator",
        location("DAST", url=endpoint.url, method=endpoint.method, parameter=parameter,
                 input_location=endpoint.input_location), severity="high" if confirmed else "medium",
        confidence="confirmed" if confirmed else "suspected",
        description=reason, remediation="Apply context-aware output encoding and safe DOM APIs; avoid HTML insertion of untrusted input. Add a restrictive CSP as defense in depth.",
        reproduction_steps=[f"Supply the recorded payload in {parameter} using {endpoint.method} {endpoint.url}.",
                            "In an isolated browser, inspect whether the matching probe alert executes."],
        evidence={"request": {"method": endpoint.method, "url": client.redactor.url(endpoint.url),
                              "parameter": parameter, "payload": payload},
                  "response": {"status": response.status_code, "excerpt": payload if raw else nonce,
                               "media_type": response.headers.get("Content-Type")},
                  "observations": ["Unique probe marker was reflected.", f"Unescaped payload present: {raw}", reason],
                  "verification": verification})
