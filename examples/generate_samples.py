"""Generate real scan output against the explicitly labeled controlled fixture."""

import logging
from pathlib import Path

from appsec.cli import write_json
from appsec.config import ScanConfig
from appsec.exporter import export_scan
from appsec.repository import Repository
from appsec.sast import run_source_scan
from appsec.scanner import run_scan
from tests.fixtures.lab import live_lab
from tests.test_idor import idor_config


def main():
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    with live_lab() as (base, _), Repository("results/fixture-demo.db") as repository:
        config = ScanConfig(
            base,
            ["127.0.0.1"],
            mode="manual",
            verify_xss=True,
            endpoints=[
                {"url": base + "/xss?q=hello"},
                {"url": base + "/escaped?q=hello"},
                {"url": base + "/sql?id=1"},
                {"url": base + "/error-only?q=hello"},
            ],
        )
        sid = run_scan(config, repository)
        value = export_scan(repository, sid)
        write_json(value, Path("examples/sample-fixture-dast.json"))
        print(f"Controlled fixture DAST: {value['scan']['status']}; {len(value['findings'])} findings; {sid}")
        sid = run_scan(idor_config(base), repository)
        value = export_scan(repository, sid)
        write_json(value, Path("examples/sample-fixture-idor.json"))
        print(f"Controlled fixture IDOR: {value['scan']['status']}; {len(value['findings'])} finding; {sid}")
        sid = run_source_scan("tests/fixtures/source", repository)
        value = export_scan(repository, sid)
        write_json(value, Path("examples/sample-fixture-sast.json"))
        print(f"Controlled fixture SAST: {value['scan']['status']}; {len(value['findings'])} findings; {sid}")


if __name__ == "__main__":
    main()
