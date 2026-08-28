from __future__ import annotations

import hashlib
import json
import stat
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.compat.datetime_compat import utc_now
from mac_audit_agent.build_identity import detect_build_identity
from mac_audit_agent.integrity.hasher import DEFAULT_EXCLUDED_PATTERNS, calculate_sha256, collect_integrity_files
from mac_audit_agent.integrity.manifest import canonical_source_type


SIGNATURE_ALGORITHM = "msaa-sha256-manifest-v1"


@dataclass(frozen=True)
class SignedManifestFileEntry:
    path: str
    sha256: str
    required: bool = True
    category: str = "core"
    mode: str = ""
    size_bytes: int = 0
    executable: bool = False
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SignedManifest:
    manifest_id: str
    app_version: str
    build_id: str
    git_commit: str
    created_at: str
    signature: str
    signer_identity: str
    file_entries: list[SignedManifestFileEntry] = field(default_factory=list)
    signature_algorithm: str = SIGNATURE_ALGORITHM
    source_type: str = "source_tree"
    excluded_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDED_PATTERNS))

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "app_version": self.app_version,
            "build_id": self.build_id,
            "git_commit": self.git_commit,
            "created_at": self.created_at,
            "signature": self.signature,
            "signer_identity": self.signer_identity,
            "signature_algorithm": self.signature_algorithm,
            "source_type": self.source_type,
            "excluded_patterns": list(self.excluded_patterns),
            "file_entries": [entry.to_dict() for entry in self.file_entries],
        }

    def canonical_payload(self) -> dict[str, Any]:
        payload = self.to_dict()
        payload["signature"] = ""
        return payload


def _utc_now_iso() -> str:
    return utc_now().isoformat()


def manifest_digest(manifest: SignedManifest) -> str:
    canonical = json.dumps(manifest.canonical_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def sign_manifest(manifest: SignedManifest, *, signer_identity: str = "MSAA local trusted manifest signer") -> SignedManifest:
    manifest.signer_identity = signer_identity
    manifest.signature_algorithm = SIGNATURE_ALGORITHM
    manifest.signature = hashlib.sha256(f"{SIGNATURE_ALGORITHM}:{manifest_digest(manifest)}".encode("utf-8")).hexdigest()
    return manifest


def verify_manifest_signature(manifest: SignedManifest) -> bool:
    if manifest.signature_algorithm != SIGNATURE_ALGORITHM or not manifest.signature:
        return False
    expected = hashlib.sha256(f"{SIGNATURE_ALGORITHM}:{manifest_digest(manifest)}".encode("utf-8")).hexdigest()
    return manifest.signature == expected


def load_signed_manifest(path: Path) -> SignedManifest:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = []
    for item in raw.get("file_entries", []):
        if not isinstance(item, dict):
            continue
        entries.append(
            SignedManifestFileEntry(
                path=str(item.get("path") or item.get("relative_path") or ""),
                sha256=str(item.get("sha256", "")),
                required=bool(item.get("required", True)),
                category=_normalize_category(str(item.get("category") or item.get("source_category") or "core")),
                mode=str(item.get("mode", "")),
                size_bytes=int(item.get("size_bytes") or item.get("size") or 0),
                executable=bool(item.get("executable", False)),
                signature=str(item.get("signature", "")),
            )
        )
    return SignedManifest(
        manifest_id=str(raw.get("manifest_id", "")),
        app_version=str(raw.get("app_version", "")),
        build_id=str(raw.get("build_id", "")),
        git_commit=str(raw.get("git_commit", "")),
        created_at=str(raw.get("created_at", "")),
        signature=str(raw.get("signature", "")),
        signer_identity=str(raw.get("signer_identity", "")),
        file_entries=entries,
        signature_algorithm=str(raw.get("signature_algorithm", "")),
        source_type=canonical_source_type(str(raw.get("source_type", "source_tree"))),
        excluded_patterns=list(raw.get("excluded_patterns", DEFAULT_EXCLUDED_PATTERNS)),
    )


def write_signed_manifest(manifest: SignedManifest, path: Path) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def create_signed_manifest(root: Path, *, source_type: str = "source_tree", signer_identity: str = "MSAA local trusted manifest signer") -> SignedManifest:
    base = Path(root).resolve(strict=False)
    identity = detect_build_identity(base)
    entries: list[SignedManifestFileEntry] = []
    for path in collect_integrity_files(base, canonical_source_type(source_type), DEFAULT_EXCLUDED_PATTERNS):
        rel = path.relative_to(base).as_posix()
        try:
            st = path.lstat()
            mode = stat.S_IMODE(st.st_mode)
            entries.append(
                SignedManifestFileEntry(
                    path=rel,
                    sha256=calculate_sha256(path) if path.is_file() else "",
                    required=True,
                    category=_category_for_path(path),
                    mode=oct(mode),
                    size_bytes=int(st.st_size),
                    executable=bool(mode & 0o111),
                )
            )
        except OSError:
            continue
    manifest = SignedManifest(
        manifest_id=f"msaa-signed-{uuid.uuid4().hex}",
        app_version=identity.app_version,
        build_id=identity.build_id,
        git_commit=identity.git_commit,
        created_at=_utc_now_iso(),
        signature="",
        signer_identity=signer_identity,
        file_entries=entries,
        source_type=canonical_source_type(source_type),
    )
    return sign_manifest(manifest, signer_identity=signer_identity)


def _normalize_category(category: str) -> str:
    normalized = category.lower()
    if normalized in {"source", "python", "logic"}:
        return "core"
    if normalized in {"config_template", "config", "template"}:
        return "template"
    if normalized in {"asset", "runtime", "core"}:
        return normalized
    return "core"


def _category_for_path(path: Path) -> str:
    suffix = path.suffix.lower()
    parts = set(path.parts)
    if path.name in {"monitor.py", "user_notifier.py"}:
        return "runtime"
    if suffix == ".py":
        return "core"
    if suffix in {".plist", ".json", ".toml", ".yaml", ".yml", ".txt"}:
        return "template"
    if suffix in {".png", ".jpg", ".jpeg", ".icns", ".ico", ".css", ".qss"} or "assets" in parts:
        return "asset"
    return "core"
