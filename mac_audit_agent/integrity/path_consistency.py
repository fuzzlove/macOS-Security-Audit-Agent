from __future__ import annotations

from mac_audit_agent.integrity.path_consensus import ManifestPathConsensusResult, verify_manifest_path_consensus


def validate_manifest_path_consistency(policy: str = "dev", **kwargs) -> ManifestPathConsensusResult:
    return verify_manifest_path_consensus(policy, **kwargs)


__all__ = ["ManifestPathConsensusResult", "validate_manifest_path_consistency", "verify_manifest_path_consensus"]
