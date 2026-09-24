"""Conservative boolean confirmation. No timing claims or data extraction."""

import hashlib
import html
import re
from urllib.parse import quote, quote_plus

from ..models import finding, location

ERROR = re.compile(
    r"SQLITE_ERROR|sqlite3?\.OperationalError|SQL syntax.*?MySQL|Unclosed quotation mark|unterminated quoted string|PostgreSQL.*?ERROR|You have an error in your SQL syntax",
    re.I,
)


def signature(response, payload, baseline_value):
    # Restore only exact probe reflections to the original input. Do not replace
    # short baseline values throughout unrelated page content or erase variation.
    body = response.text
    replacements = {
        encode(str(payload)): encode(str(baseline_value)) for encode in (str, html.escape, quote, quote_plus)
    }
    for value in sorted(replacements, key=len, reverse=True):
        if value and str(payload) != str(baseline_value):
            body = body.replace(value, replacements[value])
    return [response.status_code, hashlib.sha256(body.encode()).hexdigest(), len(body)]


def repeatable_boolean(samples):
    if len(samples) != 3:
        return False
    for kind in ("baseline", "control", "true", "false"):
        if len({tuple(s[kind]) for s in samples}) != 1 or not 200 <= samples[0][kind][0] < 300:
            return False
    first = samples[0]
    return first["baseline"] == first["true"] == first["control"] and first["false"] != first["true"]


def check_sqli(client, endpoint, parameter):
    value = str(endpoint.inputs[parameter])
    base = endpoint.send(client)
    if not 200 <= base.status_code < 300:
        raise ValueError(f"SQLi baseline inaccessible (HTTP {base.status_code})")
    error_payload = value + "'"
    response = endpoint.send(client, parameter, error_payload)
    match = ERROR.search(response.text)
    error = match.group(0)[:160] if match and not ERROR.search(base.text) else None
    # Always consider boolean differential, including applications suppressing errors.
    families = [(value + "' AND 1=1-- ", value + "' AND 1=2-- ", value + "' AND 2=2-- ")]
    if value.isdigit():
        families.insert(0, (value + " AND 1=1", value + " AND 1=2", value + " AND 2=2"))
    confirmed, observations, chosen, failure = False, [], None, None
    for true_payload, false_payload, control_payload in families:
        samples = []
        try:
            for repetition in range(3):
                probes = [
                    ("baseline", value),
                    ("true", true_payload),
                    ("false", false_payload),
                    ("control", control_payload),
                ]
                if repetition % 2:
                    probes.reverse()
                sample = {}
                for label, payload in probes:
                    result = endpoint.send(client, parameter, payload)
                    sample[label] = signature(result, payload, value)
                    if ERROR.search(result.text):
                        sample[label][0] = 500  # SQL errors are never differential proof.
                samples.append(sample)
                if repetition == 0 and not (
                    sample["baseline"] == sample["true"] == sample["control"]
                    and sample["false"] != sample["true"]
                ):
                    break
            observations.append(
                {
                    "true_payload": true_payload,
                    "false_payload": false_payload,
                    "control_payload": control_payload,
                    "samples": samples,
                }
            )
            if repeatable_boolean(samples):
                confirmed, chosen = True, observations[-1]
                break
        except Exception as exc:
            failure = type(exc).__name__
            if not error:
                raise
            break
    if not confirmed and not error:
        return None
    return finding(
        "dast.sqli",
        "SQL injection" if confirmed else "Database error indicator",
        location(
            "DAST",
            url=endpoint.url,
            method=endpoint.method,
            parameter=parameter,
            input_location=endpoint.input_location,
        ),
        severity="high",
        confidence="confirmed" if confirmed else "suspected",
        description="Three repeated boolean differentials matched stable baseline and independent true control."
        if confirmed
        else "Database error induced by a quote; manual review required. Error text alone does not confirm SQL injection.",
        remediation="Use parameterized queries for all values; allowlist identifiers. Return generic errors and apply least database privilege.",
        reproduction_steps=[
            f"Probe {parameter} at {endpoint.method} {endpoint.url} with the recorded bounded boolean expressions.",
            "Repeat baseline, true, false and independent true-control requests; compare response digests and status.",
        ],
        evidence={
            "request": {
                "method": endpoint.method,
                "url": client.redactor.url(endpoint.url),
                "parameter": parameter,
                "payload": chosen["true_payload"] if chosen else error_payload,
            },
            "response": {"status": response.status_code, "excerpt": error},
            "observations": ["No data extraction performed.", "Full response bodies are not persisted."],
            "verification": {
                "method": "boolean-differential" if confirmed else "error-indicator",
                "rounds": observations,
                "repetitions": 3 if confirmed else 0,
                "incomplete": failure,
                "signature_format": ["status", "sha256", "normalized_length"],
            },
        },
    )
