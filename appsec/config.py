import json
from dataclasses import dataclass, field
from pathlib import Path

from .discovery import Endpoint
from .scope import Scope


@dataclass
class ScanConfig:
    target: str
    allowed_hosts: list[str]
    mode: str = "static"
    max_pages: int = 20
    max_depth: int = 3
    max_endpoints: int = 40
    max_parameters: int = 8
    max_requests: int = 400
    max_seconds: float = 180
    timeout: float = 5
    browser_wait_ms: int = 500
    verify_xss: bool = False
    allow_post: bool = False
    checks: list[str] = field(default_factory=lambda: ["xss", "sqli"])
    endpoints: list[dict] = field(default_factory=list)
    auth: dict | None = None
    idor: dict | None = None

    def validate(self):
        scope = Scope(self.allowed_hosts)
        self.target = scope.require(self.target)
        if self.mode not in ("static", "spa", "manual"):
            raise ValueError("Mode must be static, spa or manual")
        for name, lower, upper in (("max_pages", 1, 200), ("max_depth", 0, 10), ("max_endpoints", 1, 200),
                                   ("max_parameters", 1, 30), ("max_requests", 1, 5000),
                                   ("max_seconds", 1, 3600), ("timeout", 0.1, 60), ("browser_wait_ms", 0, 10000)):
            if not lower <= getattr(self, name) <= upper:
                raise ValueError(f"{name} must be between {lower} and {upper}")
        if not self.checks or any(c not in ("xss", "sqli", "idor") for c in self.checks):
            raise ValueError("Checks must select xss, sqli or idor")
        if len(self.endpoints) > self.max_endpoints:
            raise ValueError("Manual endpoints exceed max_endpoints")
        for endpoint in self.endpoints:
            scope.require(endpoint["url"])
            Endpoint(**endpoint)
        if self.mode == "manual" and not self.endpoints and "idor" not in self.checks:
            raise ValueError("Manual mode requires explicit endpoints")
        return scope


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))
