from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Mapping
from typing import Any

CONTROL_CATEGORIES = {"Cc", "Cf"}


def safe_text(value: object, limit: int = 2048) -> str:
    text = unicodedata.normalize("NFC", str(value))[:limit]
    return "".join(f"<U+{ord(char):04X}>" if unicodedata.category(char) in CONTROL_CATEGORIES else char for char in text)


def normalize_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {safe_text(key, 256): normalize_value(value[key]) for key in sorted(value, key=lambda item: str(item))}
    if isinstance(value, (list, tuple, set, frozenset)):
        normalized = [normalize_value(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True, default=str))
    if isinstance(value, str):
        return safe_text(value.strip())
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return safe_text(value)


def canonical_json(value: Any) -> bytes:
    return json.dumps(normalize_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def state_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def changed_fields(previous: Mapping[str, Any], current: Mapping[str, Any]) -> tuple[str, ...]:
    before, after = normalize_value(previous), normalize_value(current)
    return tuple(sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key)))
