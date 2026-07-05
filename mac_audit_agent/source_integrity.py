from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from mac_audit_agent.build_identity import detect_build_identity
from mac_audit_agent.integrity.manifest import create_integrity_manifest
from mac_audit_agent.integrity.verifier import verify_integrity_manifest
from mac_audit_agent.version import APP_VERSION, current_git_commit


BASELINE_STATE_KEY = "source_integrity_manifest_v1"
SCHEMA = "mac-audit-agent-source-integrity-v2"
HASH_ALGORITHMS = "sha256"


class IntegrityStateStore(Protocol):
    def get_background_monitor_state(self, key: str, default: str = "") -> str: ...

    def set_background_monitor_state(self, key: str, value: str) -> None: ...


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def build_source_integrity_manifest(root: Path | None = None, *, trust_state: str = "trusted") -> dict:
    manifest = create_integrity_manifest(root or project_root(), source_type="source_tree", trust_state=trust_state)  # type: ignore[arg-type]
    payload = manifest.to_dict()
    payload["schema"] = SCHEMA
    payload["file_count"] = len(payload.get("file_entries", []))
    payload["files"] = {entry["relative_path"]: entry for entry in payload.get("file_entries", [])}
    payload["hash_algorithms"] = HASH_ALGORITHMS
    return payload


def record_source_integrity_baseline(store: IntegrityStateStore, *, root: Path | None = None, trust_state: str = "trusted") -> dict:
    manifest = build_source_integrity_manifest(root, trust_state=trust_state)
    store.set_background_monitor_state(BASELINE_STATE_KEY, json.dumps(manifest, sort_keys=True))
    return manifest


def _load_baseline(store: IntegrityStateStore) -> dict:
    raw = store.get_background_monitor_state(BASELINE_STATE_KEY, "")
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _legacy_verify_from_store(baseline: dict, *, root: Path) -> dict:
    identity = detect_build_identity(root, install_mode="source_tree")
    trust_state = str(baseline.get("trust_state") or "trusted")
    app_version = str(baseline.get("app_version") or "")
    git_commit = str(baseline.get("git_commit") or "")
    base_payload = {
        "trust_state": trust_state,
        "source_type": baseline.get("source_type", "source_tree"),
        "manifest_path": "background_monitor_state:source_integrity_manifest_v1",
        "manifest_app_version": app_version,
        "current_app_version": identity.app_version,
        "manifest_build_id": str(baseline.get("build_id") or ""),
        "current_build_id": identity.build_id,
        "manifest_git_commit": git_commit,
        "current_git_commit": identity.git_commit or current_git_commit(),
        "current_install_mode": identity.install_mode,
        "current_package_version": identity.package_version,
        "mismatch_details": [],
        "exact_mismatch_reason": "",
        "baseline_file_count": len(baseline.get("files", {}) if isinstance(baseline.get("files", {}), dict) else {}),
    }
    if trust_state != "trusted":
        status = "stale" if trust_state == "expired" else trust_state if trust_state in {"draft", "revoked", "unknown"} else "unknown"
        return {
            **base_payload,
            "status": status,
            "overall_status": status,
            "tamper_detected": False,
            "baseline_valid": False,
            "file_count": 0,
            "changed_files": [],
            "missing_files": [],
            "added_files": [],
            "skipped_count": 0,
            "hash_algorithms": HASH_ALGORITHMS,
            "last_checked": "",
            "warnings": ["Only an untrusted or draft source integrity manifest exists; it cannot prove integrity."],
            "errors": [],
            "recommended_actions": ["Create a trusted manifest only after verifying this MSAA installation came from a trusted source."],
        }
    if baseline.get("schema") and baseline.get("schema") != SCHEMA:
        return {
            **base_payload,
            "trust_state": "trusted",
            "status": "stale",
            "overall_status": "stale",
            "tamper_detected": False,
            "baseline_valid": False,
            "file_count": 0,
            "changed_files": [],
            "missing_files": [],
            "added_files": [],
            "skipped_count": 0,
            "hash_algorithms": HASH_ALGORITHMS,
            "last_checked": "",
            "warnings": [f"Source integrity manifest schema {baseline.get('schema')} is stale; expected {SCHEMA}."],
            "mismatch_details": [{"field": "schema", "manifest": str(baseline.get("schema")), "current": SCHEMA, "message": f"Manifest schema {baseline.get('schema')} differs from current schema {SCHEMA}."}],
            "exact_mismatch_reason": f"Manifest schema {baseline.get('schema')} differs from current schema {SCHEMA}.",
            "errors": [],
            "recommended_actions": ["Create a new trusted manifest after confirming this MSAA installation is trusted."],
        }
    if app_version and app_version != identity.app_version:
        reason = f"Manifest version {app_version} differs from current app version {identity.app_version}."
        return {
            **base_payload,
            "trust_state": "trusted",
            "status": "stale",
            "overall_status": "stale",
            "tamper_detected": False,
            "baseline_valid": False,
            "file_count": 0,
            "changed_files": [],
            "missing_files": [],
            "added_files": [],
            "skipped_count": 0,
            "hash_algorithms": HASH_ALGORITHMS,
            "last_checked": "",
            "warnings": [reason, "Trusted manifest was generated for a different MSAA build. This does not by itself prove tampering."],
            "mismatch_details": [{"field": "app_version", "manifest": app_version, "current": identity.app_version, "message": reason}],
            "exact_mismatch_reason": reason,
            "errors": [],
            "recommended_actions": ["Create a new trusted manifest after confirming this is an intentional trusted update."],
        }
    current = build_source_integrity_manifest(root)
    expected_files = baseline.get("files", {}) if isinstance(baseline.get("files", {}), dict) else {}
    current_files = current.get("files", {}) if isinstance(current.get("files", {}), dict) else {}
    changed = sorted(
        rel_path
        for rel_path, expected in expected_files.items()
        if rel_path in current_files and current_files[rel_path].get("sha256") != expected.get("sha256")
    )
    missing = sorted(rel_path for rel_path in expected_files if rel_path not in current_files)
    added = sorted(rel_path for rel_path in current_files if rel_path not in expected_files)
    tamper_detected = bool(changed or missing or added)
    return {
        **base_payload,
        "trust_state": "trusted",
        "status": "modified" if tamper_detected else "verified",
        "overall_status": "modified" if tamper_detected else "verified",
        "tamper_detected": tamper_detected,
        "baseline_valid": True,
        "file_count": len(current_files),
        "baseline_file_count": len(expected_files),
        "changed_files": changed,
        "missing_files": missing,
        "added_files": added,
        "hash_algorithms": HASH_ALGORITHMS,
        "last_checked": current.get("created_at", ""),
        "warnings": [],
        "errors": [],
        "skipped_count": 0,
        "recommended_actions": (
            ["Preserve evidence and reinstall MSAA from a trusted source if this change was not approved."]
            if tamper_detected
            else ["No source integrity drift detected against the trusted manifest."]
        ),
    }


def verify_source_integrity(
    store: IntegrityStateStore,
    *,
    root: Path | None = None,
    initialize: bool = False,
    manifest_path: Path | None = None,
) -> dict:
    base = root or project_root()
    if manifest_path is not None:
        result = verify_integrity_manifest(manifest_path, root=base, expected_source_type="source_tree")
        payload = result.to_dict()
        payload["status"] = payload["overall_status"]
        payload["tamper_detected"] = payload["overall_status"] == "modified"
        payload["changed_files"] = [item["relative_path"] for item in payload["file_results"] if item.get("verification_status") == "mismatch"]
        payload["missing_files"] = [item["relative_path"] for item in payload["file_results"] if item.get("verification_status") == "missing"]
        payload["added_files"] = [item["relative_path"] for item in payload["file_results"] if item.get("verification_status") == "extra"]
        payload.setdefault("trust_state", "unknown")
        return payload

    baseline = _load_baseline(store)
    if baseline:
        if root is None:
            recorded_root = baseline.get("root_path") or baseline.get("root")
            if recorded_root:
                base = Path(str(recorded_root)).expanduser().resolve(strict=False)
        return _legacy_verify_from_store(baseline, root=base)

    default_manifest = base / "msaa_integrity_manifest.json"
    if default_manifest.exists():
        result = verify_integrity_manifest(default_manifest, root=base, expected_source_type="source_tree")
        payload = result.to_dict()
        payload["status"] = payload["overall_status"]
        payload["tamper_detected"] = payload["overall_status"] == "modified"
        payload["changed_files"] = [item["relative_path"] for item in payload["file_results"] if item.get("verification_status") == "mismatch"]
        payload["missing_files"] = [item["relative_path"] for item in payload["file_results"] if item.get("verification_status") == "missing"]
        payload["added_files"] = [item["relative_path"] for item in payload["file_results"] if item.get("verification_status") == "extra"]
        payload.setdefault("trust_state", "unknown")
        return payload

    # Security invariant: verification never records current files as trusted.
    # Use record_source_integrity_baseline() or the manifest CLI after a trusted install/build.
    return {
        "status": "unknown",
        "overall_status": "unknown",
        "trust_state": "unknown",
        "source_type": "source_tree",
        "manifest_path": "",
        "manifest_app_version": "",
        "current_app_version": detect_build_identity(base, install_mode="source_tree").app_version,
        "manifest_build_id": "",
        "current_build_id": detect_build_identity(base, install_mode="source_tree").build_id,
        "manifest_git_commit": "",
        "current_git_commit": current_git_commit(),
        "mismatch_details": [],
        "exact_mismatch_reason": "No trusted source integrity manifest exists.",
        "tamper_detected": False,
        "baseline_valid": False,
        "file_count": 0,
        "changed_files": [],
        "missing_files": [],
        "added_files": [],
        "hash_algorithms": HASH_ALGORITHMS,
        "last_checked": "",
        "errors": ["No trusted source integrity manifest exists."],
        "warnings": ["Current files were not recorded as trusted automatically." if initialize else "Verification requires an existing trusted manifest."],
        "recommended_actions": ["Create a trusted manifest only after installing or building MSAA from a trusted source."],
    }
