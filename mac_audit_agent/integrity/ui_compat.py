from __future__ import annotations

from pathlib import Path

from mac_audit_agent.integrity.wrapper_adapter import IntegrityWrapperAdapter


def get_integrity_health_model(policy: str = "dev", *, root: Path | None = None) -> dict[str, object]:
    status = IntegrityWrapperAdapter(root or Path.cwd()).get_integrity_status_for_ui(policy)
    return {
        "policy": status.policy,
        "manifest_path": status.manifest_path,
        "signature_path": status.signature_path,
        "trust_state": status.trust_state,
        "status": status.status,
        "result_code": status.result_code,
        "failure_code": status.failure_code,
        "release_id": status.release_id,
        "build_id": status.build_id,
        "git_commit": status.git_commit,
        "signing_key_fingerprint": status.signing_key_fingerprint,
        "modified_source_files": status.source_modified_files,
        "generated_modified_files": status.generated_modified_files,
        "title": "Integrity Verified" if status.status == "verified" else "Integrity Verification Failed",
        "message": (
            "MSAA files match the canonical developer-machine signed manifest."
            if status.status == "verified"
            else status.reason
        ),
    }


def verify_integrity_health_model_matches_cli(policy: str = "dev", *, root: Path | None = None) -> dict[str, object]:
    status = IntegrityWrapperAdapter(root or Path.cwd()).get_current_integrity_status(
        policy, consumer="ui_compat_compare"
    )
    model = get_integrity_health_model(policy, root=root)
    mismatches = []
    if model["manifest_path"] != status.manifest_path:
        mismatches.append("manifest_path")
    if model["signature_path"] != status.signature_path:
        mismatches.append("signature_path")
    if model["trust_state"] != status.trust_state:
        mismatches.append("trust_state")
    if model["result_code"] != status.result_code:
        mismatches.append("result_code")
    if model["failure_code"] != status.failure_code:
        mismatches.append("failure_code")
    if model["modified_source_files"] != status.source_modified_files:
        mismatches.append("modified_source_files")
    return {"status": "verified" if not mismatches else "failed", "mismatches": mismatches, "model": model, "cli": status.to_dict()}


__all__ = ["get_integrity_health_model", "verify_integrity_health_model_matches_cli"]
