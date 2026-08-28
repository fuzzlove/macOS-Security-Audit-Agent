from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from mac_audit_agent.alerts.resilient_models import SecurityEvent


@dataclass(frozen=True)
class DetectorContract:
    rule_id: str
    rule_version: str = "1"
    identity_fields: tuple[str, ...] = ("process_signing_identifier", "process_hash", "process_path", "user_uid", "remote_address", "remote_port", "object_path", "action")
    material_fields: tuple[str, ...] = ("severity", "confidence", "outcome", "process_hash", "user_uid", "remote_address", "object_path")
    protected: bool = False


class DetectorRegistry:
    def __init__(self) -> None:
        self._contracts: dict[str, DetectorContract] = {}

    def register(self, contract: DetectorContract) -> None:
        if not contract.rule_id.strip():
            raise ValueError("detector rule_id is required")
        self._contracts[contract.rule_id] = contract

    def contract_for(self, event: SecurityEvent) -> DetectorContract:
        return self._contracts.get(event.rule_id, DetectorContract(rule_id=event.rule_id, rule_version=event.rule_version))


def _get(event: SecurityEvent, name: str) -> Any:
    return event.attributes.get(name) if name.startswith("attributes.") else getattr(event, name, None)


def _digest(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def calculate_fingerprints(event: SecurityEvent, contract: DetectorContract) -> tuple[str, str]:
    identity = {name: _get(event, name) for name in contract.identity_fields if _get(event, name) not in (None, "", [], {})}
    material = {name: _get(event, name) for name in contract.material_fields if _get(event, name) not in (None, "", [], {})}
    fingerprint = _digest({"rule_id": event.rule_id, "rule_version": contract.rule_version, "host_id": event.host_id, "identity": identity})
    return fingerprint, _digest({"fingerprint": fingerprint, "material": material})
