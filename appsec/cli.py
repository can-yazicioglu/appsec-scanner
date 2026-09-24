import argparse
import json
import sys
from pathlib import Path

from .config import ScanConfig, load_json
from .exporter import export_scan
from .repository import Repository
from .scanner import run_scan


def write_json(value, path=None):
    text = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(text, encoding="utf-8")
    else:
        print(text, end="")


def parser():
    root = argparse.ArgumentParser(description="Local AppSec scanner — approved targets only")
    root.add_argument("--db", default="results/appsec.db", help="SQLite results path")
    commands = root.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Run a bounded DAST scan")
    scan.add_argument("target", nargs="?")
    scan.add_argument("--config")
    scan.add_argument("--allow-host", action="append")
    modes = scan.add_mutually_exclusive_group()
    modes.add_argument("--static", dest="mode", action="store_const", const="static")
    modes.add_argument("--spa", dest="mode", action="store_const", const="spa")
    modes.add_argument("--manual", dest="mode", action="store_const", const="manual")
    scan.add_argument("--endpoint", action="append", help="Additional GET endpoint including query inputs")
    scan.add_argument("--check", dest="checks", action="append", choices=["xss", "sqli", "idor"])
    scan.add_argument("--verify-xss", action="store_true", default=None)
    scan.add_argument("--allow-post", action="store_true", default=None)
    scan.add_argument("--auth", help="JSON authentication file (keep in ignored local/)")
    for name in ("max-pages", "max-depth", "max-endpoints", "max-parameters", "max-requests", "browser-wait-ms"):
        scan.add_argument("--" + name, type=int)
    for name in ("max-seconds", "timeout"):
        scan.add_argument("--" + name, type=float)
    scan.add_argument("--output", help="Also export this scan as JSON")
    export = commands.add_parser("export", help="Export a persisted scan")
    export.add_argument("scan_id")
    export.add_argument("--output")
    commands.add_parser("scans", help="List recent scans")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        with Repository(args.db) as repository:
            if args.command == "scan":
                values = load_json(args.config) if args.config else {}
                for key in ScanConfig.__dataclass_fields__:
                    val = getattr(args, key, None)
                    if val is not None and key != "auth":
                        values[key] = val
                if args.allow_host:
                    values["allowed_hosts"] = args.allow_host
                if args.auth:
                    values["auth"] = load_json(args.auth)
                if args.endpoint:
                    values["endpoints"] = [*values.get("endpoints", []), *({"url": u} for u in args.endpoint)]
                scan_id = run_scan(ScanConfig(**values), repository)
                if args.output:
                    write_json(export_scan(repository, scan_id), args.output)
                scan = repository.get_scan(scan_id)
                print(json.dumps({"scan_id": scan_id, "status": scan["status"],
                                  "findings": len(repository.list_findings(scan_id))}))
                return 0 if scan["status"] == "completed" else 2
            if args.command == "export":
                write_json(export_scan(repository, args.scan_id), args.output)
            elif args.command == "scans":
                write_json(repository.list_scans())
        return 0
    except (ValueError, TypeError, OSError, KeyError) as exc:
        # Config can contain secrets; don't print its values or parser diagnostics.
        print(f"appsec: configuration/storage error ({type(exc).__name__}); check paths, required fields and scope.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
