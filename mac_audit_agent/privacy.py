from __future__ import annotations

import re
from typing import Any


MAC_ADDRESS_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
IP_ADDRESS_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USERNAME_PATH_RE = re.compile(r"/Users/[^/\s]+")
HOME_PATH_RE = re.compile(r"~/(?:[^\s]+)")
TOKEN_RE = re.compile(r"([?&](?:token|auth|key|secret|sig|signature|password)=)[^&\s]+", flags=re.IGNORECASE)
USERNAME_KV_RE = re.compile(r"\buser(?:name)?\s*[=:]\s*[^\s]+", flags=re.IGNORECASE)
SUDO_USER_RE = re.compile(r"\b(?:su|sudo)\s+-u\s+[A-Za-z0-9._-]+")
HOSTNAME_VALUE_RE = re.compile(r"(?i)\b(hostname|host|device_name|likely_hostname)\s*=\s*([^\s,;]+)")
HOSTNAME_URL_RE = re.compile(r"(?i)\bhttps?://([A-Za-z0-9._-]+)")


def redact_text(
    text: str,
    *,
    redact_usernames: bool = True,
    redact_paths: bool = True,
    redact_ips: bool = True,
    redact_hostnames: bool = True,
    redact_macs: bool = True,
    redact_url_secrets: bool = True,
) -> str:
    redacted = str(text or "")
    if redact_url_secrets:
        redacted = TOKEN_RE.sub(r"\1[REDACTED]", redacted)
    if redact_macs:
        redacted = MAC_ADDRESS_RE.sub("[REDACTED_MAC]", redacted)
    if redact_ips:
        redacted = IP_ADDRESS_RE.sub("[REDACTED_IP]", redacted)
    if redact_paths:
        redacted = USERNAME_PATH_RE.sub("/Users/[REDACTED_USER]", redacted)
        redacted = HOME_PATH_RE.sub("~/[REDACTED_PATH]", redacted)
    if redact_hostnames:
        redacted = HOSTNAME_VALUE_RE.sub(lambda match: f"{match.group(1)}=[REDACTED_HOSTNAME]", redacted)
        redacted = HOSTNAME_URL_RE.sub("https://[REDACTED_HOSTNAME]", redacted)
    if redact_usernames:
        redacted = USERNAME_KV_RE.sub("user=[REDACTED]", redacted)
        redacted = SUDO_USER_RE.sub(lambda match: match.group(0).rsplit(" ", 1)[0] + " [REDACTED_USER]", redacted)
        redacted = re.sub(
            r"\b([A-Za-z][A-Za-z0-9._-]{2,})\b(?=\s+\[REDACTED_IP\]|\s+\[REDACTED_MAC\]|\s+/Users/|\s+~/)",
            "[REDACTED_USER]",
            redacted,
        )
    return redacted


def redact_structure(value: Any, **kwargs: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value, **kwargs)
    if isinstance(value, list):
        return [redact_structure(item, **kwargs) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_structure(item, **kwargs) for item in value)
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        redact_hostnames = kwargs.get("redact_hostnames", True)
        redact_macs = kwargs.get("redact_macs", True)
        redact_ips = kwargs.get("redact_ips", True)
        redact_usernames = kwargs.get("redact_usernames", True)
        redact_paths = kwargs.get("redact_paths", True)
        for key, item in value.items():
            key_name = str(key).lower()
            if key_name in {"hostname", "host", "device_name", "likely_hostname"} and redact_hostnames:
                redacted[key] = "[REDACTED_HOSTNAME]" if item else item
            elif key_name in {"mac_address", "mac", "physical_address"} and redact_macs:
                redacted[key] = "[REDACTED_MAC]" if item else item
            elif key_name in {"ip", "ip_address", "source_ip", "destination_ip"} and redact_ips:
                redacted[key] = "[REDACTED_IP]" if item else item
            elif key_name in {"username", "user", "investigator_name"} and redact_usernames:
                redacted[key] = "[REDACTED_USER]" if item else item
            elif key_name in {"path", "file_path", "directory"} and redact_paths:
                redacted[key] = redact_text(str(item), **kwargs)
            else:
                redacted[key] = redact_structure(item, **kwargs)
        return redacted
    return value
