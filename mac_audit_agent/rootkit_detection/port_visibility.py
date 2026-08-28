from __future__ import annotations

import re
import shutil
import socket
import subprocess

from mac_audit_agent.rootkit_detection.models import PortVisibilityFinding


def _run(command: list[str], timeout: int = 8) -> tuple[str, str]:
    try:
        completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
        return (completed.stdout or "").strip(), (completed.stderr or "").strip()
    except FileNotFoundError:
        return "", "unavailable: command not found"
    except subprocess.TimeoutExpired:
        return "", "unavailable: command timed out"
    except Exception as exc:
        return "", f"unavailable: {type(exc).__name__}: {exc}"


def parse_lsof_listeners(text: str) -> list[PortVisibilityFinding]:
    findings: list[PortVisibilityFinding] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        command, pid, user = parts[0], parts[1], parts[2]
        tail = " ".join(parts[8:])
        match = re.search(r"(TCP|UDP)\s+(.+):(\d+)(?:\s+\(LISTEN\))?", tail, re.IGNORECASE)
        if not match:
            match = re.search(r"(.+):(\d+)\s+\(LISTEN\)", tail)
            if not match:
                continue
            protocol = "tcp"
            bind_address, port = match.groups()
        else:
            protocol, bind_address, port = match.groups()
        findings.append(
            PortVisibilityFinding(
                port=int(port),
                protocol=protocol.lower(),
                bind_address=bind_address,
                process_owner=f"{command}:{user}",
                pid=pid,
                lsof_seen=True,
                socket_state="listen",
                visibility_status="consistent",
                severity="info",
                confidence="medium",
                evidence=[line.strip()],
            )
        )
    return findings


def parse_netstat_listeners(text: str) -> list[PortVisibilityFinding]:
    findings: list[PortVisibilityFinding] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or not parts[0].lower().startswith(("tcp", "udp")):
            continue
        proto = parts[0].lower().split("4", 1)[0].split("6", 1)[0]
        state = parts[-1].lower()
        if proto.startswith("tcp") and state != "listen":
            continue
        address = parts[3]
        match = re.search(r"(.+)[.:](\d+)$", address)
        if not match:
            continue
        bind, port = match.groups()
        findings.append(
            PortVisibilityFinding(
                port=int(port),
                protocol="tcp" if proto.startswith("tcp") else "udp",
                bind_address=bind,
                netstat_seen=True,
                socket_state=state,
                visibility_status="missing_owner",
                severity="medium",
                confidence="low",
                evidence=[line.strip()],
            )
        )
    return findings


def parse_nc_output(text: str) -> bool | None:
    lowered = text.lower()
    if "succeeded" in lowered or "open" in lowered or "connected" in lowered:
        return True
    if "refused" in lowered or "timed out" in lowered or "failed" in lowered:
        return False
    return None


def _probe_local_tcp(port: int, timeout: float = 0.25) -> bool:
    for host in ("127.0.0.1", "::1"):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((host, int(port))) == 0:
                    return True
        except OSError:
            continue
    return False


def review_port_visibility(*, allow_netcat_localhost: bool = False, allow_nmap_localhost: bool = False) -> tuple[list[PortVisibilityFinding], list[str], list[str]]:
    commands: list[str] = []
    limitations: list[str] = []
    lsof_items: list[PortVisibilityFinding] = []
    netstat_items: list[PortVisibilityFinding] = []
    if shutil.which("lsof"):
        commands.append("lsof -nP -iTCP -sTCP:LISTEN")
        output, error = _run(["/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
        lsof_items = parse_lsof_listeners(output)
        if error and not output:
            limitations.append(f"lsof listener inventory unavailable: {error}")
    else:
        limitations.append("lsof unavailable.")
    if shutil.which("netstat"):
        commands.append("netstat -anv")
        output, error = _run(["/usr/sbin/netstat", "-anv"])
        netstat_items = parse_netstat_listeners(output)
        if error and not output:
            limitations.append(f"netstat listener inventory unavailable: {error}")
    else:
        limitations.append("netstat unavailable.")

    by_key: dict[tuple[str, int], PortVisibilityFinding] = {}
    for item in lsof_items:
        by_key[(item.protocol, item.port)] = item
    for item in netstat_items:
        key = (item.protocol, item.port)
        existing = by_key.get(key)
        if existing:
            existing.netstat_seen = True
            existing.evidence.extend(e for e in item.evidence if e not in existing.evidence)
        else:
            item.visibility_status = "missing_owner"
            item.severity = "medium"
            item.confidence = "low"
            by_key[key] = item

    findings = list(by_key.values())
    for item in findings:
        if item.protocol == "tcp" and (allow_netcat_localhost or allow_nmap_localhost):
            item.nc_seen = _probe_local_tcp(item.port)
            item.evidence.append(f"local TCP connect probe nc_equivalent={item.nc_seen}")
        if item.netstat_seen and not item.lsof_seen:
            item.visibility_status = "hidden_candidate" if item.nc_seen else "missing_owner"
            item.severity = "high" if item.nc_seen else "medium"
            item.confidence = "medium" if item.nc_seen else "low"
            item.evidence.append("Listener visible to netstat but no owner was visible through lsof.")
        elif item.lsof_seen and item.netstat_seen:
            item.visibility_status = "consistent"
        elif item.lsof_seen:
            item.visibility_status = "consistent"
    if allow_nmap_localhost and not shutil.which("nmap"):
        limitations.append("nmap localhost check requested but nmap is unavailable.")
    elif allow_nmap_localhost:
        limitations.append("nmap integration is intentionally limited to localhost; socket probe used for this run.")
    return findings, commands, limitations
