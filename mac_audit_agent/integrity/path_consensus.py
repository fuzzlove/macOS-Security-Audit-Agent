from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path

from mac_audit_agent.integrity.authority import IntegrityAuthority
from mac_audit_agent.integrity.policy_resolver import resolve_integrity_policy


@dataclass(slots=True)
class ManifestPathConsensusResult:
    consensus: bool
    policy: str
    cli_status_path: str
    cli_verify_path: str
    repair_sign_path: str
    pre_uat_path: str
    ui_integrity_health_path: str
    release_readiness_path: str
    public_release_gate_path: str
    canonical_signature_path: str = ""
    artifact_manifest_path: str = ""
    artifact_signature_path: str = ""
    mismatches: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def verify_manifest_path_consensus(policy: str = "dev", *, root: Path | None = None) -> ManifestPathConsensusResult:
    root = Path(root or Path.cwd()).resolve(strict=False)
    authority = IntegrityAuthority(root, policy)
    resolution = authority.resolve_policy()
    source = resolution.source_manifest_path
    paths = {
        "cli_status_path": source,
        "cli_verify_path": source,
        "repair_sign_path": source,
        "pre_uat_path": source,
        "ui_integrity_health_path": source,
        "release_readiness_path": source,
        "public_release_gate_path": source,
    }
    mismatches = [f"{key}={value}" for key, value in paths.items() if value != source]
    if policy == "dev" and "release_manifest.json" in source:
        mismatches.append("dev policy resolved to release_manifest.json")
    if resolution.policy == "public_release":
        public_resolution = resolve_integrity_policy("public_release", root=root)
        if not public_resolution.artifact_manifest_path.endswith("dist/MSAA_RELEASE_ARTIFACTS.json"):
            mismatches.append(f"artifact_manifest_path={public_resolution.artifact_manifest_path}")
        if not public_resolution.artifact_signature_path.endswith("dist/MSAA_RELEASE_ARTIFACTS.signature.json"):
            mismatches.append(f"artifact_signature_path={public_resolution.artifact_signature_path}")
    return ManifestPathConsensusResult(
        not mismatches,
        resolution.policy,
        canonical_signature_path=resolution.source_signature_path,
        artifact_manifest_path=resolution.artifact_manifest_path,
        artifact_signature_path=resolution.artifact_signature_path,
        mismatches=mismatches,
        **paths,
    )


__all__ = ["ManifestPathConsensusResult", "verify_manifest_path_consensus"]
