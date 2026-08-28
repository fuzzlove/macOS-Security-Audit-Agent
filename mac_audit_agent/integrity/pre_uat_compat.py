from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

from mac_audit_agent.integrity.wrapper_adapter import IntegrityWrapperAdapter


@dataclass(slots=True)
class PreUATCompatibilityResult:
    compatible: bool
    pre_uat_integrity_status: str
    pre_uat_integrity_trust_state: str
    pre_uat_manifest_path: str
    pre_uat_signature_path: str
    pre_uat_modified_source_files: list[str] = field(default_factory=list)
    pre_uat_generated_modified_files: list[str] = field(default_factory=list)
    pre_uat_blockers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def verify_pre_uat_integrity_compatibility(policy: str = "dev", *, root: Path | None = None) -> PreUATCompatibilityResult:
    status = IntegrityWrapperAdapter(root or Path.cwd()).get_integrity_status_for_pre_uat(policy)
    blockers = []
    if status.status != "verified":
        blockers.append(status.trust_state)
    return PreUATCompatibilityResult(
        compatible=not blockers,
        pre_uat_integrity_status=status.status,
        pre_uat_integrity_trust_state=status.trust_state,
        pre_uat_manifest_path=status.manifest_path,
        pre_uat_signature_path=status.signature_path,
        pre_uat_modified_source_files=status.source_modified_files,
        pre_uat_generated_modified_files=status.generated_modified_files,
        pre_uat_blockers=blockers,
    )


__all__ = ["PreUATCompatibilityResult", "verify_pre_uat_integrity_compatibility"]
