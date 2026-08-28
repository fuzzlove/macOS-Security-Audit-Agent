from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import asdict, dataclass
from typing import Any, Iterable


POLICY_SCHEMA_VERSION = "1.0"


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    output: list[str] = []
    for value in values:
        candidate = str(value).strip()
        if candidate and candidate not in output:
            output.append(candidate)
    return tuple(output)


def normalize_approved_dns(values: Iterable[str]) -> tuple[str, ...]:
    output: list[str] = []
    for value in values:
        try:
            candidate = str(ipaddress.ip_address(str(value).strip().split("%", 1)[0]))
        except ValueError:
            continue
        if candidate not in output:
            output.append(candidate)
    return tuple(output)


@dataclass(frozen=True)
class ConnectionAllowRule:
    source: str
    target: str
    port: str = "*"
    protocol: str = "*"
    process: str = "*"

    def matches(self, connection: Any) -> bool:
        address = str(getattr(connection, "remote_address", "") or "").split("%", 1)[0]
        port = str(getattr(connection, "remote_port", "") or "")
        protocol = str(getattr(connection, "protocol", "") or "").lower()
        process = str(getattr(connection, "process_name", "") or "").lower()
        try:
            address_value = ipaddress.ip_address(address)
            target_match = address_value in ipaddress.ip_network(self.target, strict=False)
        except ValueError:
            target_match = address.lower() == self.target.lower()
        return bool(
            target_match
            and (self.port == "*" or self.port == port)
            and (self.protocol == "*" or self.protocol == protocol)
            and (self.process == "*" or self.process.lower() == process)
        )

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def parse_connection_allowlist(value: str | Iterable[str]) -> tuple[ConnectionAllowRule, ...]:
    """Parse one bounded, explainable endpoint rule per line.

    Forms: ``address``, ``CIDR``, ``address:port``, or
    ``process|protocol|address-or-CIDR|port``. A leading ``#`` is a comment.
    """
    rows = value.splitlines() if isinstance(value, str) else list(value)
    rules: list[ConnectionAllowRule] = []
    for raw in rows:
        source = str(raw).strip()
        if not source or source.startswith("#"):
            continue
        process = protocol = port = "*"
        target = source
        if "|" in source:
            parts = [part.strip() for part in source.split("|")]
            if len(parts) != 4 or not all(parts):
                raise ValueError(f"Invalid connection allowlist rule: {source}")
            process, protocol, target, port = parts
            protocol = protocol.lower()
            if protocol not in {"*", "tcp", "udp", "tcp4", "tcp6", "udp4", "udp6"}:
                raise ValueError(f"Unsupported protocol in connection allowlist rule: {source}")
        elif target.startswith("[") and "]:" in target:
            target, port = target[1:].rsplit("]:", 1)
        elif target.count(":") == 1 and "/" not in target:
            possible_target, possible_port = target.rsplit(":", 1)
            if possible_port.isdigit() or possible_port == "*":
                target, port = possible_target, possible_port
        if port != "*" and (not port.isdigit() or not 1 <= int(port) <= 65535):
            raise ValueError(f"Invalid port in connection allowlist rule: {source}")
        try:
            normalized_target = str(ipaddress.ip_network(target.split("%", 1)[0], strict=False))
        except ValueError:
            raise ValueError(f"Connection allowlist target must be an IP address or CIDR: {source}") from None
        rule = ConnectionAllowRule(source, normalized_target, port, protocol, process)
        if rule not in rules:
            rules.append(rule)
    return tuple(rules)


@dataclass(frozen=True)
class ZeroTrustAttestationPolicy:
    approved_dns: tuple[str, ...] = ()
    connection_allowlist: tuple[ConnectionAllowRule, ...] = ()
    schema_version: str = POLICY_SCHEMA_VERSION

    @classmethod
    def from_text(cls, approved_dns: str, connection_allowlist: str) -> "ZeroTrustAttestationPolicy":
        return cls(
            normalize_approved_dns(approved_dns.replace("\n", ",").split(",")),
            parse_connection_allowlist(connection_allowlist),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "approved_dns": list(self.approved_dns),
            "connection_allowlist": [item.to_dict() for item in self.connection_allowlist],
            "qualification": "Configured organizational policy; matching proves policy conformance at collection time, not endpoint safety or compliance certification.",
        }

    @property
    def fingerprint(self) -> str:
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def assess_dns_policy(observed: Iterable[str], policy: ZeroTrustAttestationPolicy) -> tuple[bool | None, dict[str, Any]]:
    current = normalize_approved_dns(observed)
    approved = policy.approved_dns
    missing = tuple(value for value in approved if value not in current)
    unapproved = tuple(value for value in current if value not in approved)
    if not current:
        value: bool | None = None
        status = "UNKNOWN"
        reason = "No current DNS resolver evidence was available."
    elif not approved:
        value = None
        status = "POLICY_NOT_CONFIGURED"
        reason = "Current DNS was collected, but no approved resolver policy is configured."
    else:
        value = not missing and not unapproved
        status = "APPROVED" if value else "NEEDS_VALIDATION"
        reason = "Current DNS exactly matches the approved resolver policy." if value else "One or more current or required resolvers do not match policy."
    return value, {
        "status": status,
        "current_dns": list(current),
        "approved_dns": list(approved),
        "unapproved_dns": list(unapproved),
        "missing_approved_dns": list(missing),
        "reason": reason,
        "policy_fingerprint": policy.fingerprint,
    }


def assess_connection_policy(snapshot: Any, policy: ZeroTrustAttestationPolicy) -> tuple[int | None, dict[str, Any]]:
    groups = list(getattr(snapshot, "groups", []) or [])
    connections = [connection for group in groups for connection in (getattr(group, "connections", ()) or ())]
    if not groups:
        connections = list(getattr(snapshot, "connections", []) or [])
    diagnostics = getattr(snapshot, "diagnostics", {}) or {}
    errors = [str(item) for item in diagnostics.get("errors", [])] if isinstance(diagnostics, dict) else []
    collection_failed = any("connection collection failed" in item.lower() for item in errors)
    rules = policy.connection_allowlist
    rows: list[dict[str, Any]] = []
    unvalidated = 0
    not_applicable = 0
    for connection in connections:
        address = str(getattr(connection, "remote_address", "") or "").split("%", 1)[0]
        try:
            parsed = ipaddress.ip_address(address)
            local_only = parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified
        except ValueError:
            local_only = False
        matched = next((rule for rule in rules if rule.matches(connection)), None)
        state = "NOT_APPLICABLE_LOCAL" if local_only else "APPROVED" if matched else "NEEDS_VALIDATION"
        not_applicable += int(local_only)
        unvalidated += int(state == "NEEDS_VALIDATION")
        rows.append({
            "process": str(getattr(connection, "process_name", "") or "unknown"),
            "pid": getattr(connection, "pid", None),
            "protocol": str(getattr(connection, "protocol", "") or "unknown"),
            "remote_address": address,
            "remote_port": str(getattr(connection, "remote_port", "") or ""),
            "validation_state": state,
            "matched_rule": matched.source if matched else "",
        })
    if collection_failed:
        value: int | None = None
        status = "UNKNOWN"
        reason = "Active connection collection failed; absence of connections was not inferred."
    elif not rules:
        value = None
        status = "POLICY_NOT_CONFIGURED"
        reason = "Connections were collected, but no endpoint allowlist policy is configured."
    else:
        value = unvalidated
        status = "APPROVED" if unvalidated == 0 else "NEEDS_VALIDATION"
        reason = "All applicable active connections matched policy." if unvalidated == 0 else f"{unvalidated} active connection(s) require validation."
    return value, {
        "status": status,
        "active_connection_count": len(connections),
        "approved_connection_count": sum(row["validation_state"] == "APPROVED" for row in rows),
        "unvalidated_connection_count": unvalidated,
        "not_applicable_local_count": not_applicable,
        "connections": rows[:2000],
        "truncated": len(rows) > 2000,
        "collector_errors": errors,
        "reason": reason,
        "policy_fingerprint": policy.fingerprint,
    }


__all__ = [
    "ConnectionAllowRule", "ZeroTrustAttestationPolicy", "assess_connection_policy",
    "assess_dns_policy", "normalize_approved_dns", "parse_connection_allowlist",
]
