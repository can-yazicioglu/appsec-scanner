"""Labelled FIXTURE records for dashboard tests — not scan results.

Every scope starts with "FIXTURE" and every title with "[FIXTURE]". Records are
persisted through the public Repository write API so dashboard tests exercise
the scanner's real normalization, redaction and SQLite schema.
"""

from appsec.models import finding, location
from appsec.redaction import Redactor
from appsec.repository import Repository

SECRET = "fixture-secret-7d1f0c"
SCRIPT = "<script>alert(document.cookie)</script>"
SVG = '"><svg onload=alert("fixture")>'
IMG = "<img src=x onerror=alert(1)>"
JS_URL = "javascript:alert(document.domain)//"
PAYLOADS = (SCRIPT, SVG, IMG)


def _dast(path, parameter="q", input_location="query", method="GET"):
    return location("DAST", url="http://localhost:3000" + path, method=method, parameter=parameter,
                    input_location=input_location)


def build_store(path):
    """Persist one scan of each status plus a SAST scan; return their IDs."""
    ids = {}
    with Repository(path, Redactor([SECRET])) as repo:
        ids["dast"] = dast = repo.start_scan(f"FIXTURE http://localhost:3000/?key={SECRET}", "DAST")
        ids["xss_confirmed"] = repo.add_finding(dast, finding(
            "dast.xss.reflected", f"[FIXTURE] Reflected cross-site scripting {IMG}", _dast("/search"),
            severity="high", confidence="confirmed",
            description=f"Browser observed this probe's unique alert. Payload: {SCRIPT}",
            remediation="Apply context-aware output encoding.",
            reproduction_steps=[f"Send {SVG} in q.", "Observe the probe alert in an isolated browser."],
            evidence={"request": {"method": "GET", "url": "http://localhost:3000/search", "parameter": "q",
                                  "payload": SVG, "headers": {"Authorization": f"Bearer {SECRET}"}},
                      "response": {"status": 200, "excerpt": f"<p>{SVG}</p>", "media_type": "text/html"},
                      "observations": ["Unique probe marker was reflected.", f"Context: {SCRIPT}"],
                      "verification": {"method": "browser-dialog", "probe_id": "appsec_fixture",
                                       "observed_probe_dialog": True, "errors": []}}))
        ids["xss_suspected"] = repo.add_finding(dast, finding(
            "dast.xss.reflected", "[FIXTURE] Reflected input indicator", _dast("/feedback", parameter=f"c{SVG}"),
            severity="medium", description=f"Reflection alone does not prove execution. {IMG}",
            remediation="Encode output.", reproduction_steps=["Send the recorded probe."],
            evidence={"request": {"method": "GET", "payload": SVG}, "response": {"status": 200, "excerpt": IMG},
                      "observations": ["Browser did not observe probe execution."],
                      "verification": {"method": "browser-dialog", "observed_probe_dialog": False}}))
        ids["sqli_confirmed"] = repo.add_finding(dast, finding(
            "dast.sqli", "[FIXTURE] SQL injection", _dast("/rest/products/search"),
            severity="high", confidence="confirmed",
            description="Three repeated boolean differentials matched a stable baseline.",
            remediation="Use parameterized queries for all values.",
            reproduction_steps=["Probe q with the recorded boolean expressions.",
                                "Compare baseline, true, false and control response digests."],
            evidence={"request": {"method": "GET", "parameter": "q", "payload": "apple' AND 1=1-- "},
                      "response": {"status": 200, "excerpt": None},
                      "observations": ["No data extraction performed."],
                      "verification": {"method": "boolean-differential", "repetitions": 3,
                                       "rounds": [{"true_payload": "apple' AND 1=1-- ", "samples": [[200, "ab", 12]]}]}}))
        ids["sqli_error"] = repo.add_finding(dast, finding(
            "dast.sqli", "[FIXTURE] Database error indicator", _dast("/rest/user/login", "email", "json", "POST"),
            severity="high", description="Error text alone does not confirm SQL injection.",
            remediation="Return generic errors.", reproduction_steps=["Send a single quote in email."],
            evidence={"request": {"method": "POST", "payload": "'"}, "response": {"status": 500, "excerpt": "SQLITE_ERROR"},
                      "observations": [], "verification": {"method": "error-indicator", "repetitions": 0}}))
        ids["auth"] = repo.add_finding(dast, finding(
            "dast.auth.session", "[FIXTURE] Session token accepted after logout", _dast("/rest/user/whoami", None, None),
            severity="low", confidence="confirmed", category="A07:2021",
            name="Identification and Authentication Failures",
            description="The token remained valid after logout.", remediation="Invalidate sessions server-side.",
            reproduction_steps=["Log out.", "Replay the recorded request."],
            evidence={"observations": ["Replay returned 200."], "verification": {"method": "session-replay"}}))
        ids["idor"] = repo.add_finding(dast, finding(
            # Evidence shape mirrors appsec/checks/idor.py output persisted from the controlled lab.
            "dast.idor.read", "[FIXTURE] Basket readable by another account", _dast("/rest/basket/2", None, None),
            severity="high", confidence="confirmed", category="A01:2021", name="Broken Access Control",
            description="The separately verified non-owner retrieved protected content.",
            remediation="Enforce object ownership checks.",
            reproduction_steps=["Authenticate as the owner account.", "Request the same basket as the other account."],
            evidence={"request": {"method": "GET", "url": "http://localhost:3000/rest/basket/2",
                                  "headers": {"Cookie": f"token={SECRET}"}},
                      "response": {"status": 200},
                      "observations": ["Expected owner: allowed; expected non-owner: denied."],
                      "verification": {"method": "two-account-content-comparison", "expected_other": "deny",
                                       "identity_fields": ["id", "owner"], "protected_fields": ["items"],
                                       "rounds": [{"owner_status": 200, "owner_matches": True, "other_status": 200,
                                                   "other_identity_matches": True, "other_protected_matches": True},
                                                  {"owner_status": 200, "owner_matches": True, "other_status": 403,
                                                   "other_identity_matches": False,
                                                   "other_protected_matches": False}]}}))
        ids["js_url"] = repo.add_finding(dast, finding(
            "dast.xss.reflected", "[FIXTURE] Scheme-confusion location", location(
                "DAST", url=JS_URL + "localhost:3000/", method="GET", parameter="next", input_location="query"),
            description="Location value that must never become a link.", remediation="Encode output.",
            reproduction_steps=["Inspect only."],
            evidence={"observations": [], "verification": {"method": "reflection"}}))
        repo.finish_scan(dast, "completed")

        ids["partial"] = repo.start_scan("FIXTURE http://localhost:3000/", "DAST")
        repo.finish_scan(ids["partial"], "partial", errors=[f"Request budget exhausted {SCRIPT}"],
                         limitations=["Browser verification unavailable"])
        ids["failed"] = repo.start_scan("FIXTURE http://localhost:3000/", "DAST")
        repo.finish_scan(ids["failed"], "failed", errors=["Target unreachable"])
        ids["running"] = repo.start_scan("FIXTURE http://localhost:3000/", "DAST")

        ids["sast"] = sast = repo.start_scan("FIXTURE source tree", "SAST")
        ids["sast_py"] = repo.add_finding(sast, finding(
            "sast.python.subprocess-shell", "[FIXTURE] Shell command built from input", location(
                "SAST", file_path="app/tasks.py", line=42, pattern_id="py.subprocess.shell-true"),
            description="subprocess.run is called with shell=True.", remediation="Pass an argument list.",
            reproduction_steps=["Open app/tasks.py at line 42.", "Trace cmd to its sources."],
            evidence={"source": f'subprocess.run(cmd, shell=True)  # {SCRIPT}\napi_key = "{SECRET}"',
                      "observations": ["Pattern matched."], "verification": {"method": "pattern-match"}}))
        ids["sast_js"] = repo.add_finding(sast, finding(
            "sast.javascript.eval", "[FIXTURE] eval of request data", location(
                "SAST", file_path="frontend/src/search.js", line=7, pattern_id="js.eval"),
            description="eval receives request-derived data.", remediation="Remove eval.",
            reproduction_steps=["Open frontend/src/search.js at line 7."],
            evidence={"source": f"eval(req.query.q) // {IMG}", "observations": [],
                      "verification": {"method": "pattern-match"}}))
        repo.finish_scan(sast, "completed")
    return ids
