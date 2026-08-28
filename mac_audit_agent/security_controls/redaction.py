from __future__ import annotations

import re
from typing import Any

from .diff_engine import safe_text

SECRET_ARGUMENTS = re.compile(r"(?i)(password|passwd|token|secret|api[-_]?key|recovery[-_]?key|private[-_]?key)(=|:)([^\s]+)")
BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")


def redact_text(value: object) -> str:
    text = safe_text(value)
    text = SECRET_ARGUMENTS.sub(lambda match: f"{match.group(1)}{match.group(2)}<redacted>", text)
    return BEARER.sub(lambda match: f"{match.group(1)} <redacted>", text)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {safe_text(key, 256): ("<redacted>" if re.search(r"(?i)password|token|secret|recovery.?key|private.?key", str(key)) else redact(item)) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
