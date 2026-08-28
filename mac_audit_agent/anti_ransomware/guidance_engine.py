from __future__ import annotations

import getpass
import json
import socket
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from mac_audit_agent.models import utc_now_iso

from .knowledge import KnowledgeBundle, load_knowledge_bundle


@dataclass(frozen=True)
class RansomwareGuidance:
    detection_type: str
    severity: str
    confidence: str
    why_it_matters: str
    mitre_techniques: tuple[dict[str, Any], ...]
    government_guidance: tuple[dict[str, Any], ...]
    recommended_actions: tuple[str, ...]
    compliance_mapping: Mapping[str, Any]
    offline: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class GuidanceEngine:
    def __init__(self, bundle: KnowledgeBundle | None = None) -> None:
        self.bundle = bundle or load_knowledge_bundle()
        self.references = {str(item["reference_id"]): item for item in self.bundle.references}

    def resolve(self, event: Any) -> RansomwareGuidance:
        payload = event if isinstance(event, Mapping) else vars(event)
        detection = str(payload.get("detection_type") or payload.get("event_type") or payload.get("behavior") or "default")
        playbook = self._playbook(detection)
        reference_ids = tuple(playbook.get("reference_ids", ()))
        references = tuple(self.references[item] for item in reference_ids if item in self.references)
        mappings = tuple(self.bundle.mitre_mappings.get(detection, ()))
        confidence = str(payload.get("confidence") or "medium")
        severity = str(payload.get("severity") or playbook.get("severity") or "high").lower()
        return RansomwareGuidance(
            detection, severity, confidence,
            str(playbook.get("why_it_matters") or ""),
            mappings, references,
            tuple(str(item) for item in playbook.get("immediate_actions", ())),
            self.bundle.compliance_mapping,
        )

    def enrich(self, event: Any) -> dict[str, Any]:
        original = dict(event) if isinstance(event, Mapping) else dict(vars(event))
        guidance = self.resolve(original)
        original.update({
            "mitre_techniques": list(guidance.mitre_techniques),
            "government_guidance": list(guidance.government_guidance),
            "recommended_actions": list(guidance.recommended_actions),
            "why_it_matters": guidance.why_it_matters,
            "guidance_offline": True,
        })
        return original

    def _playbook(self, detection: str) -> dict[str, Any]:
        selected = dict(self.bundle.playbooks.get(detection) or self.bundle.playbooks.get("default") or {})
        inherited = str(selected.get("inherits") or "")
        if inherited:
            base = dict(self.bundle.playbooks.get(inherited) or self.bundle.playbooks.get("default") or {})
            base.update({key: value for key, value in selected.items() if key != "inherits"})
            selected = base
        return selected


class GuidanceAuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path or (Path.home() / "Library/Application Support/MSAA/AntiRansomware/audit/guidance.jsonl"))

    def record_view(self, *, finding_id: str, resource_viewed: str, severity: str, response_actions_displayed: list[str]) -> dict[str, Any]:
        event = {
            "event_type": "RANSOMWARE_GUIDANCE_VIEWED",
            "timestamp": utc_now_iso(), "user": getpass.getuser(), "hostname": socket.gethostname(),
            "finding_id": finding_id, "resource_viewed": resource_viewed,
            "severity": severity, "response_actions_displayed": list(response_actions_displayed),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
        return event


__all__ = ["GuidanceAuditLog", "GuidanceEngine", "RansomwareGuidance"]
