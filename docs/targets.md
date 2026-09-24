# Local target setup and inspected coverage

## Juice Shop v19.2.1

`docker compose up -d juice-shop` exposes only `127.0.0.1:3000`.
The version is deliberately pinned, not claimed to be latest. Create a test
account through the application, then use the environment-backed login example.
The SPA root is not a useful static API inventory: use browser discovery and
the explicit `/rest/products/search?q=apple` fallback in the example.

Source inspection of the pinned tag found a nested SQL LIKE expression in
`routes/search.ts`, normal email/password login with a returned JSON token in
`routes/login.ts`, and cookie-based whoami identity lookup in
`routes/currentUser.ts`. The current conservative boolean families need not
balance the search expression, so a quote-triggered suspected indicator is a
plausible outcome. DOM XSS through Angular hash routes is not confirmed by the
GET-query reflected-XSS verifier. This project does not claim coverage of every
Juice Shop challenge or automate challenge completion.

## DVWA 2.5

The optional Compose profile builds DVWA from upstream commit
`a96943dc1f52f390ee5df72144660636c4b7dd06` (tag **2.5**) rather than using a moving
DVWA image. MariaDB uses the 10.11 series; no database port is published.

```sh
docker compose --profile dvwa up -d --build dvwa
```

Open http://127.0.0.1:4280/setup.php and use **Create / Reset Database** for this
new disposable lab, then log in using DVWA's documented lab account. Resetting
initializes the disposable lab database; do not connect it to a valuable DB.
Set DVWA Security to **Low** for the documented examples. Set `DVWA_USERNAME`
and `DVWA_PASSWORD` in your shell to that test account, then:

```sh
appsec scan --config examples/dvwa.json --auth examples/auth-dvwa.json --output results/dvwa.json
```

Compose defaults are explicitly disposable lab database credentials. Override
`DVWA_DB_PASSWORD` and `DVWA_DB_ROOT_PASSWORD` in ignored `.env` if desired.
Changing these after initial database creation does not reset MariaDB users.
DVWA and Juice Shop bind loopback only; do not publish these vulnerable labs.

At this commit, low-level reflected XSS directly outputs `name`; low-level SQLi
uses a quoted `id` and requires `Submit`. Login uses a `user_token` CSRF field.
The supplied examples reflect those source observations, but Docker execution
was unavailable in the build workspace. Browser CSP/transport, app settings and
response variation can still change results. Neither target was actually scanned
here. Controlled fixtures provide the recorded execution evidence.

DVWA is useful for XSS/SQLi; it is not assumed to supply a resource-ownership
API suitable for this JSON-assertion IDOR module. Use the explicitly labeled
two-account fixture or configure your own authorized API with known policy.

## Source references

* [Juice Shop search at v19.2.1](https://github.com/juice-shop/juice-shop/blob/v19.2.1/routes/search.ts)
* [Juice Shop login at v19.2.1](https://github.com/juice-shop/juice-shop/blob/v19.2.1/routes/login.ts)
* [Juice Shop current user at v19.2.1](https://github.com/juice-shop/juice-shop/blob/v19.2.1/routes/currentUser.ts)
* [DVWA pinned Compose](https://github.com/digininja/DVWA/blob/a96943dc1f52f390ee5df72144660636c4b7dd06/compose.yml)
* [DVWA low SQLi](https://github.com/digininja/DVWA/blob/a96943dc1f52f390ee5df72144660636c4b7dd06/vulnerabilities/sqli/source/low.php)
* [DVWA low reflected XSS](https://github.com/digininja/DVWA/blob/a96943dc1f52f390ee5df72144660636c4b7dd06/vulnerabilities/xss_r/source/low.php)
* [DVWA login](https://github.com/digininja/DVWA/blob/a96943dc1f52f390ee5df72144660636c4b7dd06/login.php)
