from __future__ import annotations

from pathlib import Path

from mac_audit_agent.integrity.manifest import create_integrity_manifest, write_integrity_manifest
from mac_audit_agent.integrity.verifier import verify_integrity_manifest


def default_source_manifest_path(root: Path) -> Path:
    return Path(root) / "msaa_integrity_manifest.json"


def create_source_manifest(root: Path, output_path: Path | None = None):
    manifest = create_integrity_manifest(root, source_type="source_tree")
    write_integrity_manifest(manifest, output_path or default_source_manifest_path(root))
    return manifest


def verify_source_manifest(root: Path, manifest_path: Path | None = None):
    return verify_integrity_manifest(manifest_path or default_source_manifest_path(root), root=root, expected_source_type="source_tree")
