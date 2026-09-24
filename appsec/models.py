import hashlib
import json
import uuid
from datetime import datetime, timezone

SEVERITIES = ("critical", "high", "medium", "low", "informational")
CONFIDENCES = ("confirmed", "suspected")
STATUSES = ("running", "completed", "partial", "failed")
LOCATION_KEYS = ("kind", "url", "method", "parameter", "input_location", "file_path", "line", "pattern_id")


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def location(kind, **kwargs):
    return {key: kind if key == "kind" else kwargs.get(key) for key in LOCATION_KEYS}


def finding(check_id, title, location, *, severity="medium", confidence="suspected",
            description, remediation, reproduction_steps, evidence, category="A03:2021", name="Injection"):
    return dict(check_id=check_id, title=title, severity=severity, confidence=confidence,
                owasp={"edition": "2021", "category": category, "name": name},
                description=description, remediation=remediation, reproduction_steps=reproduction_steps,
                location=location, evidence={"request": None, "response": None, "source": None,
                                             "observations": [], "verification": {}, **evidence})


def normalize_finding(value):
    data = json.loads(json.dumps(value, allow_nan=False))
    for key in ("check_id", "title", "description", "remediation"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise ValueError(f"Finding requires nonempty {key}")
    for key, choices in (("severity", SEVERITIES), ("confidence", CONFIDENCES)):
        data[key] = str(data.get(key, "")).lower().strip()
        if data[key] not in choices:
            raise ValueError(f"Invalid {key}")
    loc = data.get("location", {})
    if loc.get("kind") not in ("DAST", "SAST"):
        raise ValueError("Invalid location kind")
    loc = location(**loc)
    if loc["kind"] == "DAST":
        if not loc["url"] or not loc["method"]:
            raise ValueError("DAST requires URL and method")
        loc["method"] = loc["method"].upper()
    else:
        if not loc["file_path"] or not isinstance(loc["line"], int) or loc["line"] < 1 or not loc["pattern_id"]:
            raise ValueError("SAST requires relative path, positive line and pattern ID")
        if loc["file_path"].startswith("/") or ".." in loc["file_path"].split("/"):
            raise ValueError("SAST path must be source-relative")
        if data["confidence"] != "suspected":
            raise ValueError("SAST findings must remain suspected")
    data["location"] = loc
    if data.get("owasp", {}).get("edition") != "2021" or data["owasp"].get("category") not in (
        "A01:2021", "A03:2021", "A07:2021"
    ):
        raise ValueError("Unsupported OWASP mapping")
    if not isinstance(data.get("reproduction_steps"), list) or not all(
        isinstance(s, str) for s in data["reproduction_steps"]
    ):
        raise ValueError("Reproduction steps must be strings")
    evidence = data.get("evidence", {})
    if not isinstance(evidence.get("observations"), list) or not isinstance(evidence.get("verification"), dict):
        raise ValueError("Evidence requires observations and verification")
    data["evidence"] = {"request": None, "response": None, "source": None, **evidence}
    data["id"] = data.get("id") or str(uuid.uuid4())
    data["created_at"] = data.get("created_at") or utcnow()
    return data


def fingerprint(data):
    return hashlib.sha256(json.dumps([data["check_id"], data["location"]], sort_keys=True).encode()).hexdigest()
