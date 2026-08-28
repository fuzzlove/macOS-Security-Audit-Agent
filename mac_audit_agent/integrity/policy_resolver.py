from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths, normalize_policy


@dataclass(frozen=True)
class IntegrityPolicyResolution:
    policy: str
    source_manifest_path: str
    source_signature_path: str
    artifact_manifest_path: str
    artifact_signature_path: str
    validate_source_manifest: bool
    validate_artifacts: bool
    require_pytest_evidence: bool
    require_build_evidence: bool
    require_twine_check_evidence: bool
    require_clean_install_evidence: bool
    trust_state_on_failure: str = "policy_resolution_failed"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def resolve_integrity_policy(policy: str | None = "dev", *, root: Path | None = None) -> IntegrityPolicyResolution:
    root = Path(root or Path.cwd()).resolve(strict=False)
    normalized = normalize_policy(policy or "dev")
    paths = integrity_manifest_paths(root)
    validate_artifacts = normalized == "public_release"
    return IntegrityPolicyResolution(
        policy=normalized,
        source_manifest_path=str(paths.manifest_for_policy(normalized)),
        source_signature_path=str(paths.signature_for_policy(normalized)),
        artifact_manifest_path=str(root / "dist" / "MSAA_RELEASE_ARTIFACTS.json"),
        artifact_signature_path=str(root / "dist" / "MSAA_RELEASE_ARTIFACTS.signature.json"),
        validate_source_manifest=True,
        validate_artifacts=validate_artifacts,
        require_pytest_evidence=normalized == "public_release",
        require_build_evidence=normalized == "public_release",
        require_twine_check_evidence=normalized == "public_release",
        require_clean_install_evidence=normalized == "public_release",
    )


__all__ = ["IntegrityPolicyResolution", "resolve_integrity_policy"]
