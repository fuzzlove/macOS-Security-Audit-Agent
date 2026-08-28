from __future__ import annotations

from pathlib import Path

from mac_audit_agent.integrity.path_consistency import validate_manifest_path_consistency
from mac_audit_agent.integrity.policy_resolver import resolve_integrity_policy


def test_dev_policy_never_uses_release_manifest(tmp_path: Path) -> None:
    resolved = resolve_integrity_policy("dev", root=tmp_path)
    consensus = validate_manifest_path_consistency("dev", root=tmp_path)

    assert resolved.source_manifest_path.endswith("mac_audit_agent/integrity/integrity_manifest.json")
    assert "release_manifest.json" not in resolved.source_manifest_path
    assert consensus.consensus is True


def test_public_release_policy_validates_artifacts_separately(tmp_path: Path) -> None:
    resolved = resolve_integrity_policy("public_release", root=tmp_path)
    consensus = validate_manifest_path_consistency("public_release", root=tmp_path)

    assert resolved.validate_source_manifest is True
    assert resolved.validate_artifacts is True
    assert resolved.artifact_manifest_path.endswith("dist/MSAA_RELEASE_ARTIFACTS.json")
    assert resolved.artifact_signature_path.endswith("dist/MSAA_RELEASE_ARTIFACTS.signature.json")
    assert consensus.consensus is True
