from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List
from uuid import uuid4

from .models import InvestigationStatus

MACHINE_ALLOWED = {InvestigationStatus.UNREVIEWED, InvestigationStatus.OWNER_PENDING, InvestigationStatus.SUSPICIOUS}
HUMAN_ONLY = {InvestigationStatus.PROBABLE, InvestigationStatus.CONFIRMED, InvestigationStatus.REPORT_SUBMITTED, InvestigationStatus.ACTION_CONFIRMED}
AUTHORITATIVE_EVIDENCE = {"registry_enforcement", "verified_owner_statement", "legal_determination", "validated_incident_response", "authorized_malware_analysis"}


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_type: str
    source: str
    value: str
    reliability: str
    checksum: str
    collected_at: str


@dataclass
class Investigation:
    investigation_id: str
    status: InvestigationStatus = InvestigationStatus.UNREVIEWED
    reviewer: str = ""
    rationale: str = ""
    evidence: List[EvidenceRecord] = field(default_factory=list)
    audit_log: List[dict] = field(default_factory=list)

    def transition(self, target: InvestigationStatus, *, actor: str, rationale: str, human: bool) -> None:
        if not human and target not in MACHINE_ALLOWED:
            raise PermissionError("Machine assessment cannot assign a human-only investigation disposition.")
        if target in HUMAN_ONLY and (not human or not actor.strip() or not rationale.strip()):
            raise ValueError("Human-only dispositions require reviewer identity and rationale.")
        if target == InvestigationStatus.CONFIRMED and not any(item.evidence_type in AUTHORITATIVE_EVIDENCE for item in self.evidence):
            raise ValueError("Confirmed fraud requires authoritative evidence; name similarity is insufficient.")
        timestamp = datetime.now(timezone.utc).isoformat()
        self.audit_log.append({"from": self.status.value, "to": target.value, "actor": actor, "human": human, "rationale": rationale, "timestamp": timestamp})
        self.status, self.reviewer, self.rationale = target, actor, rationale


def new_investigation() -> Investigation:
    return Investigation(str(uuid4()))
