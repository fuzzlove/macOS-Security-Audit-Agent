from __future__ import annotations

from pathlib import Path

from mac_audit_agent.integrity.manifest import create_integrity_manifest, write_integrity_manifest
from mac_audit_agent.integrity.verifier import verify_integrity_manifest


def create_runtime_manifest(runtime_root: Path, output_path: Path | None = None, *, source_type: str = "system_runtime"):
    manifest = create_integrity_manifest(runtime_root, source_type=source_type)  # type: ignore[arg-type]
    write_integrity_manifest(manifest, output_path or Path(runtime_root) / "integrity_manifest.json")
    return manifest


def verify_runtime_manifest(runtime_root: Path, manifest_path: Path | None = None):
    return verify_integrity_manifest(manifest_path or Path(runtime_root) / "integrity_manifest.json", root=runtime_root)
