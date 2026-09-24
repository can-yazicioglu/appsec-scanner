"""Exact canonical hostname allowlisting, shared by every network path."""
import ipaddress
from urllib.parse import urlsplit, urlunsplit


class ScopeError(ValueError):
    pass


def hostname(value):
    value = value.lower().rstrip(".")
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        result = value.encode("idna").decode("ascii")
        if not result or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in result):
            raise ScopeError("Invalid hostname")
        return result


class Scope:
    def __init__(self, allowed_hosts):
        if not allowed_hosts:
            raise ScopeError("At least one explicit approved host is required")
        self.hosts = set()
        for value in allowed_hosts:
            if any(c in value for c in "/@?#\\") or value.startswith("*"):
                raise ScopeError("Allowlist entries must be exact hostnames, without schemes or paths")
            self.hosts.add(hostname(value.strip("[]")))

    def require(self, url):
        try:
            if any(ord(c) < 33 for c in url) or "\\" in url:
                raise ScopeError("Ambiguous URL rejected")
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
                raise ScopeError("Only HTTP(S) URLs without userinfo are allowed")
            host = hostname(parts.hostname)
            port = parts.port  # Validates malformed/out-of-range ports.
            if host not in self.hosts:
                raise ScopeError("Request host is outside the approved allowlist")
            host = f"[{host}]" if ":" in host else host
            netloc = host + (f":{port}" if port and port != (443 if parts.scheme == "https" else 80) else "")
            return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, parts.fragment))
        except (ValueError, UnicodeError) as exc:
            raise ScopeError("Invalid or unapproved target URL") from exc

    def allows(self, url):
        try:
            self.require(url)
            return True
        except ScopeError:
            return False
