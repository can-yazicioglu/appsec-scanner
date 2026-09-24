"""Authoritative schema and stable, JSON-native read interface."""
import json
import sqlite3
import uuid
from pathlib import Path

from .models import CONFIDENCES, SEVERITIES, STATUSES, fingerprint, normalize_finding, utcnow
from .redaction import Redactor

SCHEMA = """
CREATE TABLE scans (
 id TEXT PRIMARY KEY, scope TEXT NOT NULL,
 scan_type TEXT NOT NULL CHECK(scan_type IN ('DAST','SAST')),
 started_at TEXT NOT NULL, finished_at TEXT,
 status TEXT NOT NULL CHECK(status IN ('running','completed','partial','failed')),
 errors TEXT NOT NULL, limitations TEXT NOT NULL
);
CREATE TABLE findings (
 id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(id), fingerprint TEXT NOT NULL,
 check_id TEXT NOT NULL, title TEXT NOT NULL,
 severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','informational')),
 confidence TEXT NOT NULL CHECK(confidence IN ('confirmed','suspected')),
 owasp TEXT NOT NULL, description TEXT NOT NULL, remediation TEXT NOT NULL,
 reproduction_steps TEXT NOT NULL, location TEXT NOT NULL, evidence TEXT NOT NULL,
 created_at TEXT NOT NULL, UNIQUE(scan_id,fingerprint)
);
CREATE INDEX findings_scan ON findings(scan_id);
PRAGMA user_version=1;
"""
JSON_FIELDS = {"errors", "limitations", "owasp", "reproduction_steps", "location", "evidence"}


class Repository:
    def __init__(self, path, redactor=None):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.redactor = redactor or Redactor()
        self.db = sqlite3.connect(str(path), timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version > 1:
            self.close()
            raise ValueError("Database schema is newer than this application")
        if version == 0:
            self.db.executescript("BEGIN;" + SCHEMA + "COMMIT;")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        self.db.close()

    @staticmethod
    def _decode(row):
        if row is None:
            return None
        return {k: json.loads(v) if k in JSON_FIELDS else v for k, v in dict(row).items() if k != "fingerprint"}

    def start_scan(self, scope, scan_type):
        if scan_type not in ("DAST", "SAST"):
            raise ValueError("Invalid scan type")
        scope = self.redactor.url(scope) if scan_type == "DAST" else self.redactor.text(scope)
        sid = str(uuid.uuid4())
        with self.db:
            self.db.execute("INSERT INTO scans VALUES (?,?,?,?,NULL,'running','[]','[]')",
                            (sid, scope, scan_type, utcnow()))
        return sid

    def finish_scan(self, scan_id, status, *, errors=None, limitations=None):
        if status not in STATUSES[1:]:
            raise ValueError("Invalid terminal scan status")
        with self.db:
            cursor = self.db.execute("UPDATE scans SET status=?, finished_at=?, errors=?, limitations=? WHERE id=?",
                                    (status, utcnow(), json.dumps(self.redactor.clean(errors or [])),
                                     json.dumps(self.redactor.clean(limitations or [])), scan_id))
            if not cursor.rowcount:
                raise ValueError("Unknown scan")

    def add_finding(self, scan_id, finding):
        data = normalize_finding(finding)
        identity = fingerprint(data)
        if data["location"]["url"]:
            data["location"]["url"] = self.redactor.url(data["location"]["url"])
        data = self.redactor.clean(data)
        data["scan_id"] = scan_id
        data["fingerprint"] = identity
        old = self.db.execute("SELECT * FROM findings WHERE scan_id=? AND fingerprint=?",
                              (scan_id, identity)).fetchone()
        if old:
            if old["confidence"] == "confirmed" and data["confidence"] == "suspected":
                return old["id"]
            data["id"], data["created_at"] = old["id"], old["created_at"]
        columns = ["id", "scan_id", "fingerprint", "check_id", "title", "severity", "confidence", "owasp",
                   "description", "remediation", "reproduction_steps", "location", "evidence", "created_at"]
        values = [json.dumps(data[k], ensure_ascii=False) if k in JSON_FIELDS else data[k] for k in columns]
        with self.db:
            self.db.execute(f"INSERT OR REPLACE INTO findings ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})", values)
        return data["id"]

    def get_scan(self, scan_id):
        return self._decode(self.db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone())

    def list_scans(self, *, status=None, scan_type=None, limit=100, offset=0):
        if status is not None and status not in STATUSES:
            raise ValueError("Invalid status")
        if scan_type is not None and scan_type not in ("DAST", "SAST"):
            raise ValueError("Invalid scan type")
        if not 1 <= limit <= 1000 or offset < 0:
            raise ValueError("Invalid pagination")
        clauses, args = [], []
        for key, value in (("status", status), ("scan_type", scan_type)):
            if value is not None:
                clauses.append(key + "=?")
                args.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        return [self._decode(r) for r in self.db.execute(
            "SELECT * FROM scans" + where + " ORDER BY started_at DESC,id DESC LIMIT ? OFFSET ?",
            [*args, limit, offset])]

    def get_finding(self, finding_id):
        return self._decode(self.db.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone())

    def list_findings(self, scan_id, *, severity=None, confidence=None, check_id=None):
        if severity is not None and severity not in SEVERITIES:
            raise ValueError("Invalid severity")
        if confidence is not None and confidence not in CONFIDENCES:
            raise ValueError("Invalid confidence")
        clauses, args = ["scan_id=?"], [scan_id]
        for key, value in (("severity", severity), ("confidence", confidence), ("check_id", check_id)):
            if value is not None:
                clauses.append(key + "=?")
                args.append(value)
        order = "CASE severity " + " ".join(f"WHEN '{s}' THEN {i}" for i, s in enumerate(SEVERITIES)) + " END"
        return [self._decode(r) for r in self.db.execute(
            "SELECT * FROM findings WHERE " + " AND ".join(clauses) + f" ORDER BY {order},created_at,id", args)]
