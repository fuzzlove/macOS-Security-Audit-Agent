from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.models import utc_now_iso


def _stable_id(*parts: object) -> str:
    import hashlib

    raw = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


@dataclass
class PersistenceItem:
    item_id: str
    mechanism: str
    label: str = ""
    name: str = ""
    path: str = ""
    plist_path: str = ""
    executable_path: str = ""
    program: str = ""
    program_arguments: list[str] = field(default_factory=list)
    run_at_load: bool = False
    keep_alive: bool = False
    disabled: bool = False
    loaded: bool = False
    owner: str = ""
    group: str = ""
    permissions: str = ""
    writable_by_user: bool = False
    world_writable: bool = False
    target_exists: bool = False
    target_hash_sha256: str = ""
    signed_status: str = "unknown"
    notarization_status: str = "unknown"
    team_id: str = ""
    developer_identity: str = ""
    bundle_id: str = ""
    source_scanner: str = ""
    first_seen: str = ""
    last_seen: str = ""
    baseline_status: str = "unknown"
    risk_score: int = 0
    risk_level: str = "INFO"
    trust_score: int = 50
    trust_label: str = "Unknown"
    confidence: str = "medium"
    mitre_techniques: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    recommended_verification: str = ""
    false_positive_notes: str = ""
    responsible_process: str = ""
    parent_process: str = ""
    responsible_user: str = ""
    analyst_status: str = "open"

    @classmethod
    def create(cls, mechanism: str, path: str, *, label: str = "", source_scanner: str = "", **kwargs: Any) -> "PersistenceItem":
        now = utc_now_iso()
        return cls(
            item_id=_stable_id(mechanism, label, path, kwargs.get("program"), kwargs.get("program_arguments")),
            mechanism=mechanism,
            path=path,
            label=label,
            name=kwargs.pop("name", label or Path(path).name),
            source_scanner=source_scanner,
            first_seen=now,
            last_seen=now,
            **kwargs,
        )

    def fingerprint_payload(self) -> dict[str, Any]:
        return {
            "mechanism": self.mechanism,
            "label": self.label,
            "path": self.path,
            "plist_path": self.plist_path,
            "executable_path": self.executable_path,
            "program": self.program,
            "program_arguments": self.program_arguments,
            "run_at_load": self.run_at_load,
            "keep_alive": self.keep_alive,
            "disabled": self.disabled,
            "loaded": self.loaded,
            "owner": self.owner,
            "group": self.group,
            "permissions": self.permissions,
            "target_hash_sha256": self.target_hash_sha256,
            "signed_status": self.signed_status,
            "bundle_id": self.bundle_id,
        }

    def fingerprint(self) -> str:
        import hashlib

        raw = json.dumps(self.fingerprint_payload(), sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PersistenceFinding:
    finding_id: str
    item_id: str
    severity: str
    confidence: str
    title: str
    description: str
    evidence: list[str]
    why_it_matters: str
    suggested_fix: str
    validation_steps: list[str]
    false_positive_notes: str
    mitre_mapping: list[str]
    nist_mapping: list[str]
    cis_mapping: list[str]
    cvss_score: float
    source_scanner: str
    created_at: str = field(default_factory=utc_now_iso)

    @classmethod
    def from_item(cls, item: PersistenceItem, title: str, description: str, *, severity: str | None = None) -> "PersistenceFinding":
        return cls(
            finding_id=_stable_id("persistence_finding", item.item_id, title, item.risk_score),
            item_id=item.item_id,
            severity=(severity or item.risk_level).upper(),
            confidence=item.confidence,
            title=title,
            description=description,
            evidence=list(item.evidence),
            why_it_matters="Persistence mechanisms can restart unwanted code after reboot or login and can hide attacker access.",
            suggested_fix="Verify the owner, target binary, signing status, and business purpose before changing or removing the item.",
            validation_steps=[
                "Review the plist or configuration source.",
                "Confirm the target executable exists and is expected.",
                "Validate signature, ownership, permissions, and baseline history.",
            ],
            false_positive_notes=item.false_positive_notes or "Legitimate management tools and developer utilities often use persistence mechanisms.",
            mitre_mapping=list(item.mitre_techniques),
            nist_mapping=["NIST CSF 2.0 DE.CM", "NIST CSF 2.0 RS.AN", "NIST 800-53 SI-4", "NIST 800-53 CM-3", "NIST 800-53 CM-6", "NIST 800-61"],
            cis_mapping=["CIS Control 2", "CIS Control 4", "CIS Control 8", "CIS Control 13"],
            cvss_score=round(min(10.0, max(0.0, item.risk_score / 10.0)), 1),
            source_scanner=item.source_scanner,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScannerResult:
    scanner_id: str
    items: list[PersistenceItem] = field(default_factory=list)
    findings: list[PersistenceFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0
    coverage_status: str = "healthy"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["items"] = [item.to_dict() for item in self.items]
        payload["findings"] = [finding.to_dict() for finding in self.findings]
        return payload


@dataclass
class PersistenceScanReport:
    scan_id: str
    started_at: str
    completed_at: str
    items: list[PersistenceItem]
    findings: list[PersistenceFinding]
    scanner_results: list[ScannerResult]
    posture_score: int
    coverage: list[dict[str, Any]]
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "items": [item.to_dict() for item in self.items],
            "findings": [finding.to_dict() for finding in self.findings],
            "scanner_results": [result.to_dict() for result in self.scanner_results],
            "posture_score": self.posture_score,
            "coverage": self.coverage,
            "warnings": self.warnings,
            "errors": self.errors,
        }
