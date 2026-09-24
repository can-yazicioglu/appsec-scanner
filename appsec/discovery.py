from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from .redaction import SECRET_KEY


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    inputs: dict = field(default_factory=dict)
    input_location: str = "query"

    def __post_init__(self):
        self.method = self.method.upper()
        if self.method not in ("GET", "POST") or self.input_location not in ("query", "form", "json"):
            raise ValueError("Endpoints support GET query or POST form/JSON")
        if (self.method == "GET") != (self.input_location == "query"):
            raise ValueError("GET requires query; POST requires form or json")
        p = urlsplit(self.url)
        if self.method == "GET":
            self.inputs = {**dict(parse_qsl(p.query, keep_blank_values=True)), **self.inputs}
            self.url = urlunsplit((p.scheme, p.netloc, p.path or "/", "", ""))
        else:
            self.url = urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))

    @property
    def key(self):
        return self.method, self.url, self.input_location, tuple(sorted(self.inputs))

    @property
    def parameters(self):
        return [k for k, v in self.inputs.items() if not SECRET_KEY.search(k) and isinstance(v, (str, int, float))]

    def values(self, parameter=None, payload=None):
        return {**self.inputs, **({parameter: payload} if parameter is not None else {})}

    def probe_url(self, parameter=None, payload=None):
        return self.url + ("?" + urlencode(self.values(parameter, payload)) if self.inputs else "")

    def send(self, client, parameter=None, payload=None):
        keyword = {"query": "params", "form": "data", "json": "json"}[self.input_location]
        return client.request(self.method, self.url, **{keyword: self.values(parameter, payload)})


def parse_page(html, url, scope):
    soup = BeautifulSoup(html, "html.parser")
    endpoints, links = [], []
    for anchor in soup.select("a[href]"):
        link = urljoin(url, anchor.get("href", ""))
        if scope.allows(link):
            links.append(scope.require(link))
            endpoints.append(Endpoint(link))
    for form in soup.find_all("form"):
        action = urljoin(url, form.get("action") or url)
        method = form.get("method", "GET").upper()
        if method not in ("GET", "POST") or not scope.allows(action):
            continue
        inputs = {}
        for node in form.select("input[name], textarea[name], select[name]"):
            if node.has_attr("disabled") or node.get("type", "").lower() in ("file", "reset"):
                continue
            if node.get("type", "").lower() in ("checkbox", "radio") and not node.has_attr("checked"):
                continue
            if node.name == "select":
                option = node.select_one("option[selected]") or node.select_one("option")
                inputs[node["name"]] = option.get("value", option.get_text()) if option else ""
            else:
                inputs[node["name"]] = node.get("value", node.get_text() if node.name == "textarea" else "")
        endpoints.append(Endpoint(action, method, inputs, "query" if method == "GET" else "form"))
    return endpoints, links


def static_discover(client, target, *, max_pages=20, max_depth=3, max_endpoints=40):
    queue, visited, found, errors = deque([(target, 0)]), set(), {}, []
    while queue and len(visited) < max_pages and len(found) < max_endpoints:
        url, depth = queue.popleft()
        url = client.scope.require(url).split("#", 1)[0]
        if url in visited:
            continue
        visited.add(url)
        try:
            response = client.request("GET", url)
            if response.status_code >= 400:
                raise RuntimeError(f"Discovery returned HTTP {response.status_code}")
            endpoint = Endpoint(url)
            found.setdefault(endpoint.key, endpoint)
            if "html" not in response.headers.get("Content-Type", ""):
                continue
            endpoints, links = parse_page(response.text, response.url, client.scope)
            for endpoint in endpoints:
                if len(found) < max_endpoints:
                    found.setdefault(endpoint.key, endpoint)
            if depth < max_depth:
                queue.extend((link, depth + 1) for link in links if link not in visited)
        except Exception as exc:
            errors.append(f"Static discovery: {type(exc).__name__}: {client.redactor.text(str(exc))}")
    limitations = []
    if queue or len(found) >= max_endpoints:
        limitations.append("Discovery reached configured page/depth/endpoint bounds; coverage is incomplete.")
    return list(found.values()), errors, limitations
