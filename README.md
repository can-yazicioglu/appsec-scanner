# AppSec Scanner

A local portfolio project that distinguishes confirmed vulnerabilities from
indicators requiring manual review. Python, requests, BeautifulSoup, optional
Playwright, SQLite and a read-only Flask dashboard. Built incrementally through
v0.1–v0.4; see `docs/verification.md` for evidence as milestones are completed.

## Quick start

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev,browser]'
python -m playwright install --with-deps chromium
docker compose up -d juice-shop
appsec scan --config examples/juice-shop.json --output results/juice-shop.json
appsec scans
appsec export SCAN_ID --output results/export.json
```

Only scan systems you own or have approval to test. Every run requires an
explicit exact hostname allowlist. Subdomains are not implicitly approved.
`--static` discovers HTML links/forms; `--spa` renders pages and observes API
traffic; `--manual --endpoint 'http://127.0.0.1:3000/path?q=test'` targets explicit
GET inputs. POST form/JSON endpoints require config plus `--allow-post`.
POST requests can change application state. These modes share scope enforcement.

Exit codes: 0 completed, 1 invalid configuration/storage operation, 2 partial or
failed scan. A completed scan describes only the selected bounded checks; it
does not certify an application secure. Inspect errors and limitations.

Defaults: 20 pages, depth 3, 40 endpoints, 8 parameters per endpoint, 400 total
requests, 180-second scan budget, 5-second per-request timeout, 1 MB response
limit, 5 redirects, 500 ms SPA settle time. Budgets include verification and
authentication. No brute-force resource enumeration or data extraction.

## Evidence and mappings

Severity estimates impact; confidence records proof. Reflection and database
errors alone are **suspected**. XSS becomes confirmed only after Playwright
observes an alert containing the probe's unpredictable identifier. GET query
execution is supported; POST reflection remains suspected. SQLi requires three
stable baseline/true/false/independent-control rounds, including reversed order;
dynamic responses conservatively remain unconfirmed. No timing-based claims.

Mappings explicitly use **OWASP Top 10:2021**, not a mixture of editions:
[A03 Injection](https://top10.owasp.org/2021/A03_2021-Injection/) for XSS, SQLi,
SQL construction and eval; [A01 Broken Access Control](https://top10.owasp.org/2021/A01_2021-Broken_Access_Control/)
for IDOR; [A07 Identification and Authentication Failures](https://top10.owasp.org/2021/A07_2021-Identification_and_Authentication_Failures/)
for suspected hardcoded credentials. Pattern findings are contextual mappings,
not claims that a complete OWASP category was assessed.

The [data contract](docs/data-contract.md) defines persistence and export.
Secrets are redacted before persistence, and response evidence is minimized.
Keep real credentials in environment variables or ignored `local/` files.

## Development

```sh
pytest -q
ruff check appsec tests
docker compose --profile tools run --rm scanner
```

Controlled test fixtures are deliberately vulnerable and bind loopback only.
Target findings are never inferred from fixture results. PortSwigger support is
a future direction beyond v0.4.
