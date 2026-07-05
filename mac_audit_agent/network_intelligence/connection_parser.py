from __future__ import annotations

import re

from mac_audit_agent.models import safe_int, utc_now_iso
from mac_audit_agent.network_intelligence.models import ListeningPort, NetworkConnection

LSOF_SPLIT = re.compile(r"\s+")


def split_endpoint(endpoint: str) -> tuple[str, str]:
    endpoint = endpoint.strip()
    if endpoint in {"*", "*:*"}:
        return "*", ""
    if endpoint.startswith("[") and "]:" in endpoint:
        host, port = endpoint.rsplit(":", 1)
        return host.strip("[]"), port
    if ":" in endpoint:
        host, port = endpoint.rsplit(":", 1)
        return host, port
    return endpoint, ""


def parse_lsof_name(name: str) -> tuple[str, str, str, str, str]:
    state = ""
    state_match = re.search(r"\(([^)]+)\)$", name)
    if state_match:
        state = state_match.group(1)
        name = name[: state_match.start()].strip()
    if "->" in name:
        local, remote = [part.strip() for part in name.split("->", 1)]
    else:
        local, remote = name.strip(), ""
    local_address, local_port = split_endpoint(local)
    remote_address, remote_port = split_endpoint(remote)
    return local_address, local_port, remote_address, remote_port, state


def parse_lsof_connections(text: str, *, timestamp: str | None = None) -> list[NetworkConnection]:
    timestamp = timestamp or utc_now_iso()
    connections: list[NetworkConnection] = []
    for line in text.splitlines()[1:]:
        parts = LSOF_SPLIT.split(line.strip(), maxsplit=8)
        if len(parts) < 9:
            continue
        command, pid_raw, user, _fd, _type, _device, _size, node, name = parts
        local_address, local_port, remote_address, remote_port, state = parse_lsof_name(name)
        if not remote_address or state == "LISTEN":
            continue
        connections.append(
            NetworkConnection(
                timestamp=timestamp,
                protocol=node,
                local_address=local_address,
                local_port=local_port,
                remote_address=remote_address,
                remote_port=remote_port,
                state=state,
                pid=safe_int(pid_raw),
                process_name=command,
                user=user,
                evidence=line.strip(),
            )
        )
    return connections


def parse_lsof_listeners(text: str, *, timestamp: str | None = None) -> list[ListeningPort]:
    timestamp = timestamp or utc_now_iso()
    listeners: list[ListeningPort] = []
    for line in text.splitlines()[1:]:
        parts = LSOF_SPLIT.split(line.strip(), maxsplit=8)
        if len(parts) < 9:
            continue
        command, pid_raw, user, _fd, _type, _device, _size, node, name = parts
        endpoint = name.split(" ", 1)[0]
        local_address, port = split_endpoint(endpoint)
        listeners.append(
            ListeningPort(
                timestamp=timestamp,
                protocol=node,
                local_address=local_address,
                port=port,
                pid=safe_int(pid_raw),
                process_name=command,
                user=user,
                service_guess=service_guess(port),
                evidence=line.strip(),
            )
        )
    return listeners


def service_guess(port: str) -> str:
    return {
        "22": "SSH / Remote Login",
        "445": "SMB",
        "548": "AFP",
        "5900": "Screen Sharing / VNC",
        "5000": "AirPlay / development service",
        "7000": "AirPlay",
        "8080": "Proxy / development service",
    }.get(str(port), "Unknown")
