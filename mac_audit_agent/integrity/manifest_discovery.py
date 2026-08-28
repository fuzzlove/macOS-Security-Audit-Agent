from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths
from mac_audit_agent.integrity.signing import calculate_file_sha256


@dataclass(slots=True)
class ManifestCandidate:
    path: str
    exists: bool
    canonical: bool
    legacy: bool
    manifest_hash: str = ""
    created_at: str = ""
    build_id: str = ""
    git_commit: str = ""
    file_count: int = 0
    signature_available: bool = False


@dataclass(slots=True)
class ManifestDiscoveryResult:
    canonical_exists: bool
    canonical_path: str
    canonical_signature_exists: bool = False
    canonical_signature_path: str = ""
    discovered: list[ManifestCandidate] = field(default_factory=list)
    discovered_legacy_manifests: list[str] = field(default_factory=list)
    discovered_legacy_signatures: list[str] = field(default_factory=list)
    newest_candidate: str = ""
    legacy_candidates: list[str] = field(default_factory=list)
    conflicting_candidates: list[str] = field(default_factory=list)
    recommended_action: str = "rebuild_manifest"
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _candidate(path: Path, *, canonical: bool, legacy: bool) -> ManifestCandidate:
    payload: dict[str, Any] = {}
    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            payload = {}
    signature_available = (
        path.with_suffix(".sig").exists()
        or path.with_name(path.name.replace(".json", ".signatures.json")).exists()
        or path.with_name(path.name.replace(".json", ".signature.json")).exists()
    )
    return ManifestCandidate(
        path=str(path),
        exists=path.exists(),
        canonical=canonical,
        legacy=legacy,
        manifest_hash=payload.get("manifest_hash") or (calculate_file_sha256(path) if path.exists() else ""),
        created_at=payload.get("generated_at") or payload.get("created_at", ""),
        build_id=payload.get("build_id", ""),
        git_commit=payload.get("git_commit", ""),
        file_count=len(payload.get("files", [])),
        signature_available=signature_available,
    )


def discover_integrity_manifests(project_root: Path | None = None) -> ManifestDiscoveryResult:
    root = Path(project_root or Path.cwd()).resolve(strict=False)
    paths = integrity_manifest_paths(root)
    search_paths = [paths.canonical_manifest, *paths.legacy_manifest_paths, root / "integrity_manifest.json"]
    seen: set[str] = set()
    discovered: list[ManifestCandidate] = []
    for path in search_paths:
        resolved = str(path.expanduser().resolve(strict=False))
        if resolved in seen:
            continue
        seen.add(resolved)
        if path.suffix != ".json" or path.name.endswith(".signatures.json"):
            continue
        candidate = _candidate(path, canonical=path == paths.canonical_manifest, legacy=path != paths.canonical_manifest)
        if candidate.exists or candidate.canonical:
            discovered.append(candidate)
    existing = [item for item in discovered if item.exists]
    legacy_existing = [item for item in existing if item.legacy]
    legacy_signatures = [str(path) for path in paths.legacy_manifest_paths if path.exists() and path.suffix == ".sig"]
    hashes = {item.manifest_hash for item in existing if item.manifest_hash}
    conflicting = [item.path for item in existing] if len(hashes) > 1 else []
    warnings: list[str] = []
    errors: list[str] = []
    if paths.canonical_manifest.exists():
        action = "use_canonical"
        if legacy_existing:
            warnings.append("Legacy integrity manifests were found but canonical manifest takes precedence.")
    elif len(legacy_existing) == 1:
        action = "migrate_legacy"
    elif len(legacy_existing) > 1:
        action = "manual_review_required"
        errors.append("Multiple legacy manifests exist; migration requires explicit review.")
    else:
        action = "rebuild_manifest"
    newest = max(existing, key=lambda item: item.created_at or item.path).path if existing else ""
    return ManifestDiscoveryResult(
        canonical_exists=paths.canonical_manifest.exists(),
        canonical_path=str(paths.canonical_manifest),
        canonical_signature_exists=paths.canonical_signature_bundle.exists(),
        canonical_signature_path=str(paths.canonical_signature_bundle),
        discovered=discovered,
        discovered_legacy_manifests=[item.path for item in legacy_existing],
        discovered_legacy_signatures=legacy_signatures,
        newest_candidate=newest,
        legacy_candidates=[item.path for item in legacy_existing],
        conflicting_candidates=conflicting,
        recommended_action=action,
        warnings=warnings,
        errors=errors,
    )


__all__ = ["ManifestCandidate", "ManifestDiscoveryResult", "discover_integrity_manifests"]
