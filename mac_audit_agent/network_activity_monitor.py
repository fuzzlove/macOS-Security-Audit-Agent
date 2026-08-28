from __future__ import annotations

import ipaddress
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.network_intelligence.collector import NetworkIntelligenceCollector
from mac_audit_agent.network_intelligence.models import ListeningPort, NetworkConnection


@dataclass(frozen=True)
class ProcessNetworkGroup:
    pid: int | None
    process_name: str
    process_path: str
    user: str
    connections: tuple[NetworkConnection, ...] = ()
    listeners: tuple[ListeningPort, ...] = ()
    risk_level: str = "info"
    risk_reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid, "process_name": self.process_name,
            "process_path": self.process_path, "user": self.user,
            "connections": [item.to_dict() for item in self.connections],
            "listeners": [item.to_dict() for item in self.listeners],
            "risk_level": self.risk_level, "risk_reasons": list(self.risk_reasons),
        }


@dataclass(frozen=True)
class NetworkActivitySnapshot:
    timestamp: str
    groups: tuple[ProcessNetworkGroup, ...]
    connection_count: int
    listener_count: int
    remote_endpoint_count: int
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["groups"] = [group.to_dict() for group in self.groups]
        return payload


class NetworkActivityMonitor:
    """Original process-centric monitor built on MSAA's normalized collectors."""

    def __init__(self, runner=None) -> None:
        self.runner = runner or _run

    def collect(self) -> NetworkActivitySnapshot:
        snapshot = NetworkIntelligenceCollector(self.runner).collect()
        process_paths = self._process_paths({
            item.pid for item in (*snapshot.connections, *snapshot.listeners) if item.pid
        })
        buckets: dict[tuple[int | None, str, str], dict[str, Any]] = {}
        for connection in snapshot.connections:
            connection.process_path = process_paths.get(connection.pid or 0, "")
            key = (connection.pid, connection.process_name, connection.user)
            buckets.setdefault(key, {"connections": [], "listeners": []})["connections"].append(connection)
        for listener in snapshot.listeners:
            listener.process_path = process_paths.get(listener.pid or 0, "")
            key = (listener.pid, listener.process_name, listener.user)
            buckets.setdefault(key, {"connections": [], "listeners": []})["listeners"].append(listener)
        groups: list[ProcessNetworkGroup] = []
        for (pid, name, user), values in buckets.items():
            reasons, severity = _risk(values["connections"], values["listeners"], process_paths.get(pid or 0, ""))
            groups.append(ProcessNetworkGroup(
                pid, name, process_paths.get(pid or 0, ""), user,
                tuple(values["connections"]), tuple(values["listeners"]), severity, tuple(reasons),
            ))
        groups.sort(key=lambda item: (_severity_rank(item.risk_level), item.process_name.lower(), item.pid or 0))
        endpoints = {(item.remote_address, item.remote_port, item.protocol) for item in snapshot.connections}
        return NetworkActivitySnapshot(
            utc_now_iso(), tuple(groups), len(snapshot.connections), len(snapshot.listeners),
            len(endpoints), dict(snapshot.diagnostics),
        )

    def _process_paths(self, pids: set[int]) -> dict[int, str]:
        output: dict[int, str] = {}
        for pid in sorted(pids)[:2048]:
            result = self.runner(["/bin/ps", "-p", str(pid), "-o", "comm="])
            if result.returncode == 0:
                output[pid] = (result.stdout or "").strip()
        return output


def _risk(connections: list[NetworkConnection], listeners: list[ListeningPort], path: str) -> tuple[list[str], str]:
    reasons: list[str] = []
    severity = "info"
    if path.startswith(("/tmp/", "/private/tmp/", "/var/tmp/", str(Path.home() / "Downloads"))):
        reasons.append("Process is executing from a temporary or user-download location.")
        severity = "high"
    if not path:
        reasons.append("Executable path could not be resolved with current permissions.")
        severity = "medium"
    public_remotes = 0
    for connection in connections:
        try:
            address = ipaddress.ip_address(connection.remote_address.split("%", 1)[0])
        except ValueError:
            continue
        if not (address.is_private or address.is_loopback or address.is_link_local or address.is_multicast):
            public_remotes += 1
    if public_remotes >= 10:
        reasons.append(f"Process has {public_remotes} concurrent public remote endpoints.")
        severity = "high" if public_remotes >= 25 else max_severity(severity, "medium")
    if listeners and any(item.local_address in {"*", "0.0.0.0", "::"} for item in listeners):
        reasons.append("Process exposes one or more listeners on all interfaces.")
        severity = max_severity(severity, "medium")
    return reasons, severity


def max_severity(left: str, right: str) -> str:
    return left if _severity_rank(left) <= _severity_rank(right) else right


def _severity_rank(value: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(value, 5)


def _run(command: list[str]):
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=12)
    except Exception as exc:
        return subprocess.CompletedProcess(command, 1, "", str(exc))


__all__ = ["NetworkActivityMonitor", "NetworkActivitySnapshot", "ProcessNetworkGroup"]
