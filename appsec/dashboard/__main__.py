"""Serve the read-only dashboard: ``python -m appsec.dashboard --db results/appsec.db``."""

import argparse
import ipaddress
import sys

from . import create_app


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m appsec.dashboard",
        description="Read-only findings dashboard. It never starts scans or writes to the database.")
    parser.add_argument("--db", default="results/appsec.db", help="SQLite store written by the scanner CLI")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: loopback only)")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args(argv)

    try:
        loopback = ipaddress.ip_address(args.host).is_loopback
    except ValueError:
        loopback = args.host == "localhost"
    if not loopback:
        print(f"warning: binding to {args.host} exposes stored findings and evidence beyond this machine.",
              file=sys.stderr)
    # Debug mode stays off: the Werkzeug debugger allows code execution.
    create_app(args.db).run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
