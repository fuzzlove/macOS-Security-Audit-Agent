from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SECRET_ASSIGNMENT = re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key|authorization|cookie)=([^\s&]+)")
AUTH_HEADER = re.compile(r"(?i)(authorization\s*:\s*)([^\r\n]+)")
USER_PATH = re.compile(r"/Users/[^/\s]+")


def redact_text(value: str, *, redact_user_paths: bool = False, limit: int = 4096) -> str:
    text = str(value or "")[: max(0, limit)]
    text = SECRET_ASSIGNMENT.sub(r"\1=[REDACTED]", text)
    text = AUTH_HEADER.sub(r"\1[REDACTED]", text)
    if redact_user_paths:
        text = USER_PATH.sub("/Users/[REDACTED]", text)
    return text


def redact_url(value: str) -> str:
    try:
        parts = urlsplit(str(value))
        query = urlencode([(key, "[REDACTED]") for key, _ in parse_qsl(parts.query, keep_blank_values=True)])
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
    except ValueError:
        return "[INVALID URL REDACTED]"


def redact_environment(values: dict[str, str], denied_fragments: tuple[str, ...]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in values.items():
        upper = str(key).upper()
        result[str(key)] = "[REDACTED]" if any(fragment in upper for fragment in denied_fragments) else redact_text(str(value), limit=512)
    return result
