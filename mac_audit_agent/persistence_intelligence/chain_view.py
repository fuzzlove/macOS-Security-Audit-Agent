from __future__ import annotations

from mac_audit_agent.persistence_intelligence.models import PersistenceFinding, PersistenceItem


def build_chain_view(items: list[PersistenceItem], findings: list[PersistenceFinding]) -> list[dict]:
    findings_by_item: dict[str, list[dict]] = {}
    for finding in findings:
        findings_by_item.setdefault(finding.item_id, []).append(finding.to_dict())
    chains = []
    for item in items:
        relationships = [
            {"type": "persistence_item", "value": item.label or item.name or item.item_id},
            {"type": "mechanism", "value": item.mechanism},
            {"type": "configuration_source", "value": item.plist_path or item.path},
            {"type": "target_binary", "value": item.executable_path or item.program},
            {"type": "owner", "value": f"{item.owner}:{item.group}".strip(":")},
            {"type": "trust", "value": f"{item.trust_label} ({item.trust_score})"},
            {"type": "risk", "value": f"{item.risk_level} ({item.risk_score})"},
        ]
        for technique in item.mitre_techniques:
            relationships.append({"type": "mitre", "value": technique})
        chains.append({"item_id": item.item_id, "relationships": relationships, "findings": findings_by_item.get(item.item_id, [])})
    return chains
