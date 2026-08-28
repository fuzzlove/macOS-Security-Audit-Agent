from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mac_audit_agent.assets import get_asset_path

RESOURCE_NAMES = ("government_references.json", "mitre_mapping.json", "response_playbooks.json")


@dataclass(frozen=True)
class KnowledgeBundle:
    references: tuple[dict[str, Any], ...]
    mitre_mappings: dict[str, list[dict[str, Any]]]
    playbooks: dict[str, dict[str, Any]]
    compliance_mapping: dict[str, Any]
    versions: dict[str, str]
    integrity: dict[str, str]


def resource_root() -> Path:
    return get_asset_path("ransomware/government_references.json").parent


def load_knowledge_bundle(root: Path | None = None, *, verify_integrity: bool = True) -> KnowledgeBundle:
    root = Path(root or resource_root())
    payloads = {name: _load_json(root / name) for name in RESOURCE_NAMES}
    integrity = verify_resource_integrity(root) if verify_integrity else {}
    references = tuple(payloads["government_references.json"].get("references", ()))
    for reference in references:
        parsed = urlparse(str(reference.get("url") or ""))
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError(f"AR-GOV-URL: official reference must use HTTPS: {reference.get('reference_id', '')}")
    return KnowledgeBundle(
        references,
        dict(payloads["mitre_mapping.json"].get("mappings", {})),
        dict(payloads["response_playbooks.json"].get("playbooks", {})),
        dict(payloads["response_playbooks.json"].get("compliance_mapping", {})),
        {name: str(payload.get("metadata", {}).get("version", "")) for name, payload in payloads.items()},
        integrity,
    )


def verify_resource_integrity(root: Path | None = None) -> dict[str, str]:
    root = Path(root or resource_root())
    manifest_path = root / "integrity_manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError(f"AR-GOV-RESOURCE: missing or unsafe resource {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (
        not isinstance(manifest, dict)
        or manifest.get("algorithm") != "sha256"
        or not isinstance(manifest.get("files"), dict)
    ):
        raise ValueError("AR-GOV-SCHEMA: invalid integrity manifest")
    expected = dict(manifest.get("files", {}))
    output: dict[str, str] = {}
    for name in RESOURCE_NAMES:
        path = root / name
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        output[name] = digest
        if expected.get(name) != digest:
            raise ValueError(f"AR-GOV-INTEGRITY: {name} failed SHA-256 verification")
    return output


def _load_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"AR-GOV-RESOURCE: missing or unsafe resource {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("metadata"), dict):
        raise ValueError(f"AR-GOV-SCHEMA: invalid resource schema {path.name}")
    if not payload["metadata"].get("verified"):
        raise ValueError(f"AR-GOV-UNVERIFIED: resource is not marked verified {path.name}")
    return payload


__all__ = ["KnowledgeBundle", "load_knowledge_bundle", "resource_root", "verify_resource_integrity"]
