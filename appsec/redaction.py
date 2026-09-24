"""Small, deliberately conservative evidence redactor; not a general DLP engine."""

import re
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlsplit, urlunsplit

MASK = "[REDACTED]"
SECRET_KEY = re.compile(r"password|passwd|secret|token|authorization|cookie|api.?key|csrf|credential", re.I)


class Redactor:
    def __init__(self, secrets=()):
        self.secrets = set()
        for secret in secrets:
            self.register(secret)

    def register(self, value):
        if isinstance(value, str) and value:
            self.secrets.update((value, quote(value, safe=""), quote_plus(value)))

    def text(self, value):
        value = str(value)
        for secret in sorted(self.secrets, key=len, reverse=True):
            value = value.replace(secret, MASK)
        value = re.sub(r"(?i)\bBearer\s+[^\s\"'<>]+", "Bearer " + MASK, value)
        value = re.sub(
            r"""(?ix)(["']?(?:password|passwd|secret|[\w-]*token|api[_-]?key|authorization|cookie|set-cookie)["']?\s*[:=]\s*)(["'])(.*?)\2""",
            lambda m: m[1] + m[2] + MASK + m[2],
            value,
        )
        value = re.sub(
            r"(?i)((?:password|passwd|secret|[\w-]*token|api[_-]?key)=)[^&\s<>\"']+",
            lambda m: m[1] + MASK,
            value,
        )
        value = re.sub(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+\b", MASK, value)
        return value

    def url(self, url):
        parts = urlsplit(url)
        netloc = parts.netloc.rsplit("@", 1)[-1]
        query = urlencode(
            [
                (k, MASK if SECRET_KEY.search(k) else self.text(v))
                for k, v in parse_qsl(parts.query, keep_blank_values=True)
            ]
        )
        return self.text(urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment)))

    def clean(self, value):
        if isinstance(value, dict):
            return {k: MASK if SECRET_KEY.search(k) else self.clean(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.clean(v) for v in value]
        if isinstance(value, str):
            return self.text(value)
        return value
