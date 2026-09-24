# Contributing

Keep pull requests focused and explain the problem, resulting behavior, and validation.

## Setup and checks

Requires Python 3.11+. From a cloned repository:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev,browser]'
python -m playwright install --with-deps chromium
pytest -q
ruff check appsec tests examples
git diff --check
```

Without Chromium, run `pytest -q -m 'not browser'` and note the excluded tests.
CI runs the full suite with Chromium.

## Bug reports and changes

- Include reproducible steps, Python version, and sanitized expected/actual output.
- Add focused regression tests for behavior changes and update affected docs.
- Preserve scope checks, budgets, redaction, and confidence distinctions.
- Use loopback fixtures; test other systems only with authorization.
- Never commit credentials, session tokens, private evidence, or scan databases.

Use GitHub issues for ordinary bugs and proposals. For scanner vulnerabilities,
follow [SECURITY.md](SECURITY.md).
