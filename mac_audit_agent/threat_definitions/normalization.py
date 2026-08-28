"""Strict indicator normalization without inventing broader block scope."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .models import DefinitionType


class NormalizationError(ValueError):
    pass


_HEX_LENGTHS = {DefinitionType.MD5: 32, DefinitionType.SHA1: 40, DefinitionType.SHA256: 64, DefinitionType.CERTIFICATE_HASH: 64}
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_hostname(value: str) -> str:
    raw = value.strip().rstrip(".")
    if not raw or raw.startswith("*."):
        raise NormalizationError("wildcards and empty hostnames are not accepted implicitly")
    try:
        normalized = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise NormalizationError("hostname IDNA conversion failed") from exc
    if len(normalized) > 253 or any(not _LABEL.fullmatch(label) for label in normalized.split(".")):
        raise NormalizationError("invalid hostname syntax")
    return normalized


def normalize_url(value: str) -> str:
    try:
        parsed = urlsplit(value.strip())
    except ValueError as exc:
        raise NormalizationError("invalid URL") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise NormalizationError("URL requires HTTP(S), a host, and no embedded credentials")
    try:
        host = ipaddress.ip_address(parsed.hostname).compressed
    except ValueError:
        host = normalize_hostname(parsed.hostname)
    try:
        port = parsed.port
    except ValueError as exc:
        raise NormalizationError("invalid URL port") from exc
    default_port = (parsed.scheme.lower() == "http" and port == 80) or (parsed.scheme.lower() == "https" and port == 443)
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and not default_port:
        netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    return urlunsplit(SplitResult(parsed.scheme.lower(), netloc, path, parsed.query, ""))


def normalize_value(definition_type: DefinitionType, value: str) -> str:
    maximum_bytes = 64 * 1024 * 1024 if definition_type == DefinitionType.YARA_RULE else 1_048_576
    if not isinstance(value, str) or len(value.encode("utf-8", errors="ignore")) > maximum_bytes:
        raise NormalizationError("definition value is missing or too large")
    if definition_type != DefinitionType.YARA_RULE and any(ord(character) < 0x20 for character in value):
        raise NormalizationError("definition contains control characters")
    if definition_type in _HEX_LENGTHS:
        normalized = value.strip().lower()
        if len(normalized) != _HEX_LENGTHS[definition_type] or not re.fullmatch(r"[0-9a-f]+", normalized):
            raise NormalizationError(f"invalid {definition_type.value} value")
        return normalized
    if definition_type in {DefinitionType.DOMAIN, DefinitionType.HOSTNAME}:
        return normalize_hostname(value)
    if definition_type == DefinitionType.URL:
        return normalize_url(value)
    if definition_type == DefinitionType.IPV4:
        address = ipaddress.ip_address(value.strip())
        if address.version != 4:
            raise NormalizationError("expected IPv4")
        return str(address)
    if definition_type == DefinitionType.IPV6:
        address = ipaddress.ip_address(value.strip())
        if address.version != 6:
            raise NormalizationError("expected IPv6")
        return address.compressed
    if definition_type == DefinitionType.CIDR:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    if definition_type in {DefinitionType.BEHAVIOR_RULE, DefinitionType.DETECTION_RULE}:
        try:
            document = json.loads(value)
        except json.JSONDecodeError as exc:
            raise NormalizationError("behavior and detection rules must be JSON") from exc
        if not isinstance(document, dict):
            raise NormalizationError("behavior and detection rules must be JSON objects")
        return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    normalized = value.strip()
    if not normalized:
        raise NormalizationError("empty definition")
    return normalized


def definition_id(definition_type: DefinitionType, normalized_value: str) -> str:
    digest = hashlib.sha256(f"{definition_type.value}\0{normalized_value}".encode()).hexdigest()
    return f"msaa-{definition_type.value.lower()}-{digest[:24]}"


__all__ = ["NormalizationError", "definition_id", "normalize_hostname", "normalize_url", "normalize_value"]
