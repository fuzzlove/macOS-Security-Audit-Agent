"""Typed active-definition lookup with explicit allowlist conflict semantics."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

from .models import (
    DefinitionAction,
    DefinitionLifecycle,
    DefinitionType,
    ThreatDefinition,
)
from .normalization import NormalizationError, normalize_value


@dataclass(frozen=True)
class DefinitionMatch:
    matched: bool
    definition_ids: tuple[str, ...] = ()
    action: DefinitionAction = DefinitionAction.OBSERVE
    policy_conflict: bool = False
    explanation: str = "No active definition matched."


class DefinitionMatcher:
    def __init__(self, definitions: Iterable[ThreatDefinition]) -> None:
        inactive = {DefinitionLifecycle.EXPIRED, DefinitionLifecycle.REVOKED, DefinitionLifecycle.FALSE_POSITIVE, DefinitionLifecycle.DISABLED, DefinitionLifecycle.SUPERSEDED}
        active = [item for item in definitions if item.lifecycle not in inactive]
        self._exact: dict[tuple[DefinitionType, str], list[ThreatDefinition]] = {}
        self._allow = {item.value for item in active if item.definition_type == DefinitionType.ALLOWLIST}
        self._cidr: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ThreatDefinition]] = []
        for item in active:
            if item.definition_type == DefinitionType.CIDR:
                self._cidr.append((ipaddress.ip_network(item.value), item))
            else:
                self._exact.setdefault((item.definition_type, item.value), []).append(item)

    def match(self, definition_type: DefinitionType, value: str) -> DefinitionMatch:
        try:
            canonical = normalize_value(definition_type, value)
        except NormalizationError:
            return DefinitionMatch(False, explanation="Indicator was malformed and was not matched.")
        matches = list(self._exact.get((definition_type, canonical), ()))
        if definition_type in {DefinitionType.IPV4, DefinitionType.IPV6}:
            address = ipaddress.ip_address(canonical)
            matches.extend(item for network, item in self._cidr if address in network)
        if not matches:
            return DefinitionMatch(False)
        allowlisted = canonical in self._allow
        actions = [item.action for item in matches]
        priority = (DefinitionAction.BLOCK, DefinitionAction.QUARANTINE_CANDIDATE, DefinitionAction.ALERT, DefinitionAction.CORRELATE, DefinitionAction.LOG, DefinitionAction.OBSERVE, DefinitionAction.DISABLED)
        requested = next((action for action in priority if action in actions), DefinitionAction.OBSERVE)
        action = DefinitionAction.ALERT if allowlisted and requested in {DefinitionAction.BLOCK, DefinitionAction.QUARANTINE_CANDIDATE} else requested
        explanation = "IOC matched, but allowlist precedence prevented automatic blocking; detection remains visible." if allowlisted else "Active typed threat definition matched with preserved provenance."
        return DefinitionMatch(True, tuple(sorted(item.definition_id for item in matches)), action, allowlisted, explanation)


__all__ = ["DefinitionMatch", "DefinitionMatcher"]
