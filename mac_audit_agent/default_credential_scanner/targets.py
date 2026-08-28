from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

_SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+;:@%/-]*$")
_SAFE_HOSTNAME = re.compile(r"^[A-Za-z0-9.-]+$")
MAX_TARGETS = 100


@dataclass(frozen=True)
class AuthorizedHttpTarget:
    url: str
    scheme: str
    host: str
    port: int
    base_path: str

    @property
    def nmap_host(self) -> str:
        return self.host

    @property
    def is_ipv6(self) -> bool:
        try:
            return ipaddress.ip_address(self.host.split("%", 1)[0]).version == 6
        except ValueError:
            return False


def parse_authorized_target(value: str) -> AuthorizedHttpTarget:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("Target is empty.")
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parsed = urlsplit(raw)
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise ValueError(f"Invalid target URL: {value}") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Target must be an HTTP(S) URL with a host: {value}")
    if parsed.username or parsed.password:
        raise ValueError("Targets must not contain embedded credentials.")
    if parsed.query or parsed.fragment:
        raise ValueError("Targets must not contain query strings or fragments.")
    if not 1 <= port <= 65535:
        raise ValueError(f"Target port is outside 1-65535: {value}")
    host = parsed.hostname.rstrip(".")
    if len(host) > 253 or any(character.isspace() for character in host):
        raise ValueError(f"Target host is invalid: {value}")
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        labels = host.split(".")
        if (
            not _SAFE_HOSTNAME.fullmatch(host)
            or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels)
        ):
            raise ValueError(f"Target hostname is outside the safe DNS syntax: {value}")
    path = parsed.path or "/"
    if len(path) > 512 or not _SAFE_PATH.fullmatch(path) or "," in path or "=" in path:
        raise ValueError("Target path contains unsupported characters for the NSE argument boundary.")
    shown_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    netloc = shown_host if port == default_port else f"{shown_host}:{port}"
    normalized_url = urlunsplit((scheme, netloc, path, "", ""))
    return AuthorizedHttpTarget(normalized_url, scheme, host, port, path)


def parse_authorized_targets(text: str, *, maximum: int = MAX_TARGETS) -> tuple[AuthorizedHttpTarget, ...]:
    rows: list[AuthorizedHttpTarget] = []
    seen: set[str] = set()
    for line_number, raw in enumerate(str(text or "").splitlines(), 1):
        candidate = raw.strip()
        if not candidate or candidate.startswith("#"):
            continue
        try:
            target = parse_authorized_target(candidate)
        except ValueError as exc:
            raise ValueError(f"Line {line_number}: {exc}") from exc
        if target.url not in seen:
            rows.append(target)
            seen.add(target.url)
        if len(rows) > max(1, min(int(maximum), MAX_TARGETS)):
            raise ValueError(f"Target list exceeds the maximum of {maximum} HTTP(S) servers.")
    if not rows:
        raise ValueError("Enter at least one authorized HTTP(S) server.")
    return tuple(rows)


__all__ = ["MAX_TARGETS", "AuthorizedHttpTarget", "parse_authorized_target", "parse_authorized_targets"]
