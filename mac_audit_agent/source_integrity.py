from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from mac_audit_agent.build_identity import detect_build_identity
from mac_audit_agent.integrity.authority import IntegrityAuthority
from mac_audit_agent.integrity.dev_manifest import verify_manifest as verify_development_manifest
from mac_audit_agent.integrity.manifest import create_integrity_manifest
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths
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
    if trust_state not in {"trusted", "trusted_development_baseline"}:
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

    authority_payload = _authority_source_integrity_payload(base)
    if authority_payload["status"] == "verified" or not initialize:
        return authority_payload

    baseline = _load_baseline(store)
    if baseline:
        if root is None:
            recorded_root = baseline.get("root_path") or baseline.get("root")
            if recorded_root:
                base = Path(str(recorded_root)).expanduser().resolve(strict=False)
        return _legacy_verify_from_store(baseline, root=base)

    if initialize:
        # Security invariant: initialization must not silently trust a source
        # checkout or opportunistically adopt a manifest from disk.
        return _missing_source_integrity_payload(base, initialize=initialize)

    canonical_manifest = integrity_manifest_paths(base).source_development_manifest
    if canonical_manifest.exists():
        summary = verify_development_manifest(base, manifest_path=canonical_manifest, policy="dev")
        return _development_summary_payload(summary, base)

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

    return _missing_source_integrity_payload(base, initialize=initialize)


def _authority_source_integrity_payload(base: Path) -> dict:
    status = IntegrityAuthority(base, "dev").status()
    verified = status.status == "verified" and status.trust_state == "trusted_developer_machine_signed_manifest"
    changed = list(status.source_modified_files or status.modified_files)
    missing = list(status.missing_files)
    added = list(status.extra_files)
    overall_status = "verified" if verified else "modified" if changed or missing or added else "failed"
    return {
        "status": overall_status,
        "overall_status": overall_status,
        "trust_state": status.trust_state,
        "integrity_health_display_title": status.integrity_health_display_title,
        "integrity_health_display_message": status.integrity_health_display_message,
        "source_type": "source_tree",
        "manifest_path": status.manifest_path,
        "signature_path": status.signature_path,
        "manifest_app_version": APP_VERSION,
        "current_app_version": detect_build_identity(base, install_mode="source_tree").app_version,
        "manifest_build_id": "",
        "current_build_id": detect_build_identity(base, install_mode="source_tree").build_id,
        "manifest_git_commit": "",
        "current_git_commit": current_git_commit(),
        "mismatch_details": changed + missing + added,
        "exact_mismatch_reason": status.reason,
        "tamper_detected": not verified and bool(changed or missing or added),
        "baseline_valid": verified,
        "file_count": status.checked_files + len(changed) + len(missing),
        "matched_count": status.checked_files,
        "mismatched_count": len(changed),
        "missing_count": len(missing),
        "extra_count": len(added),
        "changed_files": changed,
        "missing_files": missing,
        "added_files": added,
        "generated_modified_files": list(status.generated_modified_files),
        "hash_algorithms": HASH_ALGORITHMS,
        "last_checked": "",
        "errors": [] if verified else [status.reason],
        "warnings": [] if verified else [status.recommended_action],
        "recommended_actions": [status.recommended_action] if status.recommended_action else [],
        "authority": status.to_dict(),
    }


def _development_summary_payload(summary, base: Path) -> dict:
    metadata = summary.manifest_metadata
    changed = [item.relative_path for item in summary.modified_files]
    missing = [item.relative_path for item in summary.missing_files]
    added = [item.relative_path for item in summary.unexpected_files]
    overall_status = "verified" if summary.ok else "modified"
    return {
        "status": overall_status,
        "overall_status": overall_status,
        "trust_state": "trusted_development_baseline" if summary.ok else "modified_unapproved",
        "integrity_health_display_title": "Trusted Development Baseline" if summary.ok else "Unapproved Source Modification",
        "integrity_health_display_message": "MSAA source files match the signed development integrity manifest." if summary.ok else "Protected source files differ from the selected integrity manifest.",
        "source_type": "source_tree",
        "manifest_path": metadata.get("manifest_path", str(integrity_manifest_paths(base).source_development_manifest)),
        "manifest_app_version": APP_VERSION,
        "current_app_version": detect_build_identity(base, install_mode="source_tree").app_version,
        "manifest_build_id": metadata.get("build_id", ""),
        "current_build_id": detect_build_identity(base, install_mode="source_tree").build_id,
        "manifest_git_commit": metadata.get("git_commit", ""),
        "current_git_commit": current_git_commit(),
        "mismatch_details": changed + missing + added,
        "exact_mismatch_reason": "Canonical development manifest verified." if summary.ok else "Canonical development manifest differs from source tree.",
        "tamper_detected": not summary.ok,
        "baseline_valid": summary.ok,
        "file_count": summary.protected_files_verified + len(changed) + len(missing),
        "matched_count": summary.protected_files_verified,
        "changed_files": changed,
        "missing_files": missing,
        "added_files": added,
        "hash_algorithms": HASH_ALGORITHMS,
        "last_checked": metadata.get("generated_at", ""),
        "errors": summary.schema_errors + summary.signature_errors,
        "warnings": ["Canonical development manifest is unsigned."] if summary.unsigned_manifest_warning else [],
        "recommended_actions": [summary.to_dict().get("recommended_remediation", "")],
    }


def _missing_source_integrity_payload(base: Path, *, initialize: bool = False) -> dict:
    # Security invariant: verification never records current files as trusted.
    # Use record_source_integrity_baseline() or the manifest CLI after a trusted install/build.
    paths = integrity_manifest_paths(base)
    legacy_present = any(path.exists() for path in paths.legacy_manifest_paths)
    trust_state = "manifest_path_divergence" if legacy_present else "missing_manifest"
    reason = (
        "Legacy manifest exists but the canonical development manifest is missing."
        if legacy_present
        else "No trusted source integrity manifest exists."
    )
    return {
        "status": "failed",
        "overall_status": "failed",
        "trust_state": trust_state,
        "integrity_health_display_title": "Manifest Path Mismatch" if legacy_present else "Missing Integrity Manifest",
        "integrity_health_display_message": (
            "Integrity tools are using different manifest paths. Rebuild using the canonical policy manifest."
            if legacy_present
            else "No canonical integrity manifest exists for the selected policy."
        ),
        "source_type": "source_tree",
        "manifest_path": str(paths.source_development_manifest),
        "manifest_app_version": "",
        "current_app_version": detect_build_identity(base, install_mode="source_tree").app_version,
        "manifest_build_id": "",
        "current_build_id": detect_build_identity(base, install_mode="source_tree").build_id,
        "manifest_git_commit": "",
        "current_git_commit": current_git_commit(),
        "mismatch_details": [],
        "exact_mismatch_reason": reason,
        "tamper_detected": False,
        "baseline_valid": False,
        "file_count": 0,
        "changed_files": [],
        "missing_files": [],
        "added_files": [],
        "hash_algorithms": HASH_ALGORITHMS,
        "last_checked": "",
        "errors": [reason],
        "warnings": ["Current files were not recorded as trusted automatically." if initialize else "Verification requires an existing trusted manifest."],
        "recommended_actions": ["Run integrity rehash --policy dev only after confirming this MSAA source tree is trusted."],
    }
