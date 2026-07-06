from __future__ import annotations

from pathlib import Path

from mac_audit_agent.integrity.verifier import verify_integrity_manifest


def verify_user_notifier_integrity(runtime_root_path: Path | None = None, manifest_path: Path | None = None):
    from mac_audit_agent.launch_agent import runtime_root

    root = runtime_root_path or runtime_root("user")
    manifest = manifest_path or Path(root) / "install_manifest.json"
    if not manifest.exists() and manifest_path is None:
        manifest = Path(root) / "integrity_manifest.json"
    return verify_integrity_manifest(manifest, root=root, expected_source_type="user_notifier_runtime")
