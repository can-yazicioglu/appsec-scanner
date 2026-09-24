from dataclasses import dataclass
from time import monotonic
from urllib.parse import urljoin, urlsplit

import requests

from .redaction import Redactor
from .scope import ScopeError


class RequestFailure(RuntimeError):
    pass


@dataclass
class Budget:
    max_requests: int = 400
    max_seconds: float = 180
    requests: int = 0

    def __post_init__(self):
        self.started = monotonic()

    def take(self):
        if self.requests >= self.max_requests or monotonic() - self.started >= self.max_seconds:
            raise RequestFailure("Scan request/time budget exhausted")
        self.requests += 1


class SafeSession:
    def __init__(self, scope, *, timeout=5, budget=None, redactor=None, max_bytes=1_000_000):
        self.scope, self.timeout = scope, timeout
        self.budget = budget or Budget()
        self.redactor = redactor or Redactor()
        self.max_bytes = max_bytes
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers["User-Agent"] = "AppSec-Portfolio-Scanner/0.1"
        self.origin = None
        self.auth_headers = {}
        self.browser_storage = {}

    def close(self):
        self.session.close()

    def request(self, method, url, *, params=None, data=None, json=None, headers=None, follow=True):
        url = self.scope.require(url)
        for _ in range(6):
            self.budget.take()
            request_headers = dict(headers or {})
            if self.origin and origin(url) == self.origin:
                request_headers.update(self.auth_headers)
            elif self.origin:
                request_headers["Cookie"] = ""
            try:
                response = self.session.request(
                    method,
                    url,
                    params=params,
                    data=data,
                    json=json,
                    headers=request_headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                    stream=True,
                )
                chunks, size = [], 0
                started = monotonic()
                for chunk in response.iter_content(65536):
                    size += len(chunk)
                    if size > self.max_bytes or monotonic() - started > self.timeout:
                        response.close()
                        raise RequestFailure("Response exceeded body/time limit")
                    chunks.append(chunk)
                response._content = b"".join(chunks)
                response._content_consumed = True
                response.close()
                for cookie in self.session.cookies:
                    self.redactor.register(cookie.value)
            except requests.RequestException as exc:
                # Exception text may contain URL credentials or response content.
                raise RequestFailure(f"HTTP request failed ({type(exc).__name__})") from exc
            if (
                follow
                and response.status_code in (301, 302, 303, 307, 308)
                and response.headers.get("Location")
            ):
                next_url = self.scope.require(urljoin(response.url, response.headers["Location"]))
                if origin(next_url) != origin(response.url):
                    # Avoid forwarding login bodies, CSRF fields or custom headers across origins.
                    raise ScopeError("Cross-origin redirect blocked")
                if response.status_code == 303 or (
                    response.status_code in (301, 302) and method.upper() == "POST"
                ):
                    method, data, json = "GET", None, None
                url, params = next_url, None
                continue
            return response
        raise RequestFailure("Redirect limit exceeded")


def origin(url):
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"
