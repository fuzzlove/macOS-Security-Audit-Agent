from __future__ import annotations

import re

from mac_audit_agent.network_intelligence.models import NetworkPosture


def parse_route_default(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    return values


def parse_scutil_dns(text: str) -> list[str]:
    servers: list[str] = []
    for match in re.finditer(r"nameserver\[\d+\]\s*:\s*([^\s]+)", text):
        server = match.group(1).strip()
        if server and server not in servers:
            servers.append(server)
    return servers


class DNSGatewayCollector:
    def __init__(self, runner) -> None:
        self.runner = runner

    def collect(self) -> tuple[NetworkPosture, list[str]]:
        errors: list[str] = []
        route_result = self.runner(["/sbin/route", "-n", "get", "default"])
        dns_result = self.runner(["/usr/sbin/scutil", "--dns"])
        route = parse_route_default(route_result.stdout if route_result.returncode == 0 else "")
        if route_result.returncode != 0:
            errors.append(f"default route collection failed: {(route_result.stderr or route_result.stdout).strip()}")
        if dns_result.returncode != 0:
            errors.append(f"DNS collection failed: {(dns_result.stderr or dns_result.stdout).strip()}")
        return (
            NetworkPosture(
                active_interface=route.get("interface", ""),
                gateway=route.get("gateway", ""),
                dns_servers=parse_scutil_dns(dns_result.stdout if dns_result.returncode == 0 else ""),
            ),
            errors,
        )
