from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class Resolution:
    hostname: str
    addresses: tuple[str, ...]
    duration_ms: float
    error: str = ""


def destination_is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


def resolve_public(hostname: str, port: int, transport: str, *, every_address: bool = True) -> Resolution:
    if not hostname or len(hostname) > 253 or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for char in hostname):
        raise ValueError("invalid provider hostname")
    started = time.monotonic()
    socktype = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
    try:
        records = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socktype)
    except socket.gaierror as exc:
        return Resolution(hostname, (), round((time.monotonic() - started) * 1000, 3), type(exc).__name__)
    addresses = tuple(sorted({str(row[4][0]).split("%", 1)[0] for row in records}, key=lambda value: (ipaddress.ip_address(value).version, value)))
    if any(not destination_is_public(address) for address in addresses):
        raise PermissionError("provider DNS returned a non-public or prohibited destination")
    if not every_address:
        chosen = []
        for version in (4, 6):
            chosen.extend(address for address in addresses if ipaddress.ip_address(address).version == version)[:1]
        addresses = tuple(chosen)
    return Resolution(hostname, addresses, round((time.monotonic() - started) * 1000, 3))
