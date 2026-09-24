"""Read-only Flask dashboard over the scanner's persisted findings.

The dashboard never starts scans, never writes to the store and never creates
or migrates the database. Each request opens the existing SQLite file through
the public ``Repository`` reads and closes it afterwards, so findings persisted
by the CLI appear across restarts without any dashboard-side state.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from urllib.parse import quote

from flask import Flask, current_app, g, jsonify, render_template, request
from markupsafe import Markup, escape

from ..exporter import InvalidFilterError, ScanNotFoundError
from ..redaction import MASK
from ..repository import Repository

CONTENT_SECURITY_POLICY = "; ".join((
    "default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self'",
    "form-action 'self'", "base-uri 'none'", "frame-ancestors 'none'",
))
SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}

# Labels describe the method attempted, never its outcome: confidence and the
# recorded facts say whether it succeeded (browser-dialog may observe nothing).
VERIFICATION_LABELS = {
    "browser-dialog": "Browser execution check for the probe's alert dialog",
    "reflection": "Payload reflection (indicator only)",
    "boolean-differential": "Repeated boolean response differential",
    "error-indicator": "Database error string (indicator only)",
    "two-account-content-comparison": "Two-account protected-content comparison",
}
# Redacted URLs carry the mask percent-encoded.
REDACTION = re.compile(re.escape(MASK) + "|" + re.escape(quote(MASK, safe="")))


class StoreUnavailable(Exception):
    """The scanner database is missing, unreadable or at another schema version."""


def create_app(database_path) -> Flask:
    app = Flask(__name__)
    app.config.update(DEBUG=False, DATABASE_PATH=Path(database_path))

    from .views import bp
    app.register_blueprint(bp)

    app.teardown_appcontext(_close_repository)
    app.after_request(_apply_security_headers)
    for error in (InvalidFilterError, ScanNotFoundError, StoreUnavailable, sqlite3.Error, 404, 405):
        app.register_error_handler(error, _handle_error)

    app.jinja_env.filters.update(
        as_text=as_text, redactions=highlight_redactions, timestamp=format_timestamp, short_id=short_id,
    )
    app.jinja_env.globals.update(verification_label=VERIFICATION_LABELS.get)
    app.context_processor(lambda: {"database_path": app.config["DATABASE_PATH"]})
    return app


def get_repository() -> Repository:
    """Open the existing store for this request; never create or migrate it."""
    if "repository" not in g:
        path = current_app.config["DATABASE_PATH"]
        try:
            g.repository = Repository(path, read_only=True)
        except (ValueError, sqlite3.Error, OSError) as exc:
            raise StoreUnavailable(
                f"The database at {path} could not be opened ({type(exc).__name__}). "
                "Run the scanner CLI first to create or migrate the store; the dashboard only reads existing results."
            ) from exc
    return g.repository


def _close_repository(_exc=None):
    repository = g.pop("repository", None)
    if repository is not None:
        repository.close()


def _apply_security_headers(response):
    response.headers.update(SECURITY_HEADERS)
    return response


ERROR_PAGES = {
    InvalidFilterError: (400, "Invalid filter"),
    ScanNotFoundError: (404, "Scan not found"),
    StoreUnavailable: (503, "Findings store unavailable"),
    sqlite3.Error: (503, "Findings store unavailable"),
}


def _handle_error(error):
    status, title = next((page for kind, page in ERROR_PAGES.items() if isinstance(error, kind)), (None, None))
    if status is None:
        status, title = error.code, error.name
        message = {404: "Nothing is stored under this address.",
                   405: "The dashboard is read-only and accepts only GET requests."}.get(status, error.description)
    elif isinstance(error, sqlite3.Error):
        current_app.logger.warning("Store read failed: %s", type(error).__name__)
        message = f"The scanner database could not be read ({type(error).__name__}). Findings are not shown as empty."
    else:
        message = str(error)
    if request.path.endswith(".json"):
        return jsonify(error=title, message=message), status
    return render_template("error.html", status=status, title=title, message=message), status


def as_text(value) -> str:
    """Evidence values as inert display text; structures become indented JSON."""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, indent=2)


def highlight_redactions(value) -> Markup:
    """Escape evidence text, then mark the store's redaction placeholder."""
    escaped = str(escape(as_text(value)))
    # Both mask forms lack HTML-significant characters, so they survive escaping verbatim.
    return Markup(REDACTION.sub(lambda m: f'<mark class="redacted">{m.group(0)}</mark>', escaped))


def format_timestamp(value) -> str:
    if not value:
        return "—"
    return value.replace("T", " ").removesuffix("Z").split(".")[0] + " UTC"


def short_id(value) -> str:
    return str(value)[:8]
