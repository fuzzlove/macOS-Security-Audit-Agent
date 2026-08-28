from __future__ import annotations

import hashlib
import re
import shlex
from typing import Any


_SENSITIVE_OPTION = re.compile(
    r"(?i)^(--?(?:password|passwd|token|secret|api[-_]?key|authorization|bearer|access[-_]?key|private[-_]?key)(?:=|$))"
)
_INLINE_SECRET = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[-_]?key|authorization|bearer)\s*([=:])\s*([^\s,;]+)"
)
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_AUTHORIZATION_BEARER = re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+[^\s,;]+")


def stable_reference(namespace: str, value: object, salt: str) -> str:
    material = f"{namespace}\0{salt}\0{value}".encode("utf-8", errors="replace")
    return f"{namespace}-{hashlib.sha256(material).hexdigest()[:24]}"


def user_reference(*, uid: int | None, account: str, host_salt: str) -> str:
    value = f"uid:{uid}" if uid is not None and uid >= 0 else f"account:{account or 'unknown'}"
    return stable_reference("user", value, host_salt)


def redact_text(value: object, maximum_length: int = 4096) -> str:
    text = str(value or "")[:maximum_length]
    text = _AUTHORIZATION_BEARER.sub("Authorization: Bearer <REDACTED>", text)
    text = _INLINE_SECRET.sub(lambda match: f"{match.group(1)}{match.group(2)}<REDACTED>", text)
    text = _AWS_KEY.sub("<REDACTED_AWS_KEY>", text)
    text = _PRIVATE_KEY.sub("<REDACTED_PRIVATE_KEY>", text)
    return text


def redact_command_line(value: object, maximum_arguments: int = 64) -> str:
    try:
        arguments = shlex.split(str(value or ""), posix=True)
    except ValueError:
        return redact_text(value)
    output: list[str] = []
    redact_next = False
    for argument in arguments[:maximum_arguments]:
        if redact_next:
            output.append("<REDACTED>")
            redact_next = False
            continue
        match = _SENSITIVE_OPTION.match(argument)
        if match:
            if "=" in argument:
                output.append(argument.split("=", 1)[0] + "=<REDACTED>")
            else:
                output.append(argument)
                redact_next = True
            continue
        output.append(redact_text(argument, 1024))
    return " ".join(output)


def minimize_mapping(value: dict[str, Any], *, maximum_items: int = 64) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, item in list(value.items())[:maximum_items]:
        name = str(key)[:128]
        if re.search(r"(?i)(password|token|secret|authorization|cookie|clipboard|document_content|message)", name):
            output[name] = "<REDACTED>"
        elif name in {"command_line", "argv", "arguments"}:
            output[name] = redact_command_line(item)
        elif isinstance(item, str):
            output[name] = redact_text(item)
        elif item is None or isinstance(item, (bool, int, float)):
            output[name] = item
        elif isinstance(item, (list, tuple)):
            output[name] = [redact_text(entry, 512) for entry in item[:32]]
        elif isinstance(item, dict):
            output[name] = minimize_mapping(item, maximum_items=32)
        else:
            output[name] = redact_text(item)
    return output


__all__ = ["minimize_mapping", "redact_command_line", "redact_text", "stable_reference", "user_reference"]
