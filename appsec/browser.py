"""Optional browser adapter. HTTP traffic passes through the same scoped client."""
import json
from collections import deque
from urllib.parse import parse_qsl

from .discovery import Endpoint, parse_page
from .http import origin


class Browser:
    def __init__(self, client, *, wait_ms=500):
        self.client, self.wait_ms = client, wait_ms
        self.errors, self.captured = [], {}
        self.playwright = self.browser = None

    def __enter__(self):
        try:
            from playwright.sync_api import sync_playwright
            self.playwright = sync_playwright().start()
            self.browser = self.playwright.chromium.launch()
            self.context = self.browser.new_context(service_workers="block", accept_downloads=False)
            self.context.set_default_timeout(int(self.client.timeout * 1000))
            self.context.route("**/*", self._route)
            self.context.route_web_socket("**/*", lambda ws: ws.close())
            # Requests are proxied below; do not expose credentials in context-wide headers.
            if self.client.origin and self.client.browser_storage:
                self.context.add_init_script("if(location.origin === " + json.dumps(self.client.origin) + ") {"
                    + "for (const [k,v] of Object.entries(" + json.dumps(self.client.browser_storage)
                    + ")) localStorage.setItem(k,v);}")
            self.page = self.context.new_page()
            return self
        except Exception:
            self.__exit__()
            raise

    def __exit__(self, *_):
        if self.browser:
            self.browser.close()
        if self.playwright:
            self.playwright.stop()

    def _route(self, route):
        request = route.request
        try:
            self.client.scope.require(request.url)
            if request.method not in ("GET", "POST", "HEAD", "OPTIONS"):
                raise ValueError("Browser method outside supported scope")
            # Never route.continue_: redirect chains are resolved by SafeSession, so
            # Playwright redirect interception gaps cannot bypass the host policy.
            headers = {k: v for k, v in request.headers.items() if k.lower() in ("accept", "content-type")}
            response = self.client.request(request.method, request.url, data=request.post_data, headers=headers)
            if request.resource_type in ("document", "xhr", "fetch") and request.method in ("GET", "POST"):
                content_type = request.headers.get("content-type", "")
                if request.method == "GET":
                    endpoint = Endpoint(request.url)
                elif "application/json" in content_type:
                    values = json.loads(request.post_data or "{}")
                    endpoint = Endpoint(request.url, "POST", values, "json") if isinstance(values, dict) else None
                elif "application/x-www-form-urlencoded" in content_type:
                    endpoint = Endpoint(request.url, "POST", dict(parse_qsl(request.post_data or "")), "form")
                else:
                    endpoint = None
                if endpoint and len(self.captured) < 200:
                    self.captured.setdefault(endpoint.key, endpoint)
            # requests decompressed bytes already. Preserve CSP and MIME constraints.
            reply_headers = {k: v for k, v in response.headers.items() if k.lower() not in
                             ("content-encoding", "content-length", "transfer-encoding", "connection")}
            route.fulfill(status=response.status_code, headers=reply_headers, body=response.content)
        except Exception as exc:
            self.errors.append(f"Browser request blocked/failed: {type(exc).__name__}")
            route.abort()

    def discover(self, target, *, max_pages=20, max_depth=3, max_endpoints=40):
        queue, visited, endpoints = deque([(target, 0)]), set(), {}
        while queue and len(visited) < max_pages and len(endpoints) < max_endpoints:
            url, depth = queue.popleft()
            url = self.client.scope.require(url)
            if url in visited:
                continue
            visited.add(url)
            try:
                self.page.goto(url, wait_until="domcontentloaded")
                self.page.wait_for_timeout(self.wait_ms)
                parsed, links = parse_page(self.page.content(), self.page.url, self.client.scope)
                for endpoint in [*parsed, *self.captured.values()]:
                    if len(endpoints) < max_endpoints:
                        endpoints.setdefault(endpoint.key, endpoint)
                if depth < max_depth:
                    queue.extend((link, depth + 1) for link in links if link not in visited)
            except Exception as exc:
                self.errors.append(f"SPA discovery failed: {type(exc).__name__}")
        limits = ["SPA discovery visits links and observes network traffic; it does not click controls or explore all app states."]
        if queue or len(endpoints) >= max_endpoints:
            limits.append("SPA discovery reached configured bounds.")
        return list(endpoints.values()), self.errors[:], limits

    def verify_xss(self, url, nonce):
        self.client.scope.require(url)
        observed = []

        def dialog(event):
            if event.type == "alert" and event.message == nonce and origin(self.page.url) == origin(url):
                observed.append(nonce)
            event.dismiss()

        self.page.on("dialog", dialog)
        try:
            self.page.goto(url, wait_until="domcontentloaded")
            self.page.wait_for_timeout(self.wait_ms)
            return bool(observed), {"method": "browser-dialog", "probe_id": nonce,
                                    "observed_probe_dialog": bool(observed), "errors": self.errors[:]}
        finally:
            self.page.remove_listener("dialog", dialog)
