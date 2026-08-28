from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mac_audit_agent.compat.enum import StrEnum


VALID_INTEGRITY_POLICIES = {"dev", "pre_release", "public_release", "runtime"}


class IntegrityPolicy(StrEnum):
    DEV = "dev"
    PRE_RELEASE = "pre_release"
    PUBLIC_RELEASE = "public_release"
    RUNTIME = "runtime"


@dataclass(frozen=True)
class IntegrityManifestPathSet:
    policy: str
    manifest_path: Path
    signature_path: Path
    signature_bundle_path: Path
    trust_policy_path: Path
    legacy_paths: tuple[Path, ...]
    description: str


@dataclass(frozen=True)
class IntegrityManifestPaths:
    canonical_manifest: Path
    canonical_signature_bundle: Path
    canonical_trust_policy: Path
    canonical_trusted_developer_machines: Path
    legacy_development_manifest: Path
    legacy_development_signature: Path
    legacy_release_manifest: Path
    legacy_release_signature: Path
    runtime_install_manifest: Path
    runtime_install_signature: Path | None
    legacy_manifest_paths: tuple[Path, ...]

    def manifest_for_policy(self, policy: str) -> Path:
        normalize_policy(policy)
        return self.canonical_manifest

    def signature_for_policy(self, policy: str) -> Path:
        normalize_policy(policy)
        return self.canonical_signature_bundle

    @property
    def source_development_manifest(self) -> Path:
        return self.canonical_manifest

    @property
    def source_development_signature(self) -> Path:
        return self.canonical_signature_bundle

    @property
    def release_manifest(self) -> Path:
        return self.canonical_manifest

    @property
    def release_signature(self) -> Path:
        return self.canonical_signature_bundle

    def is_legacy(self, path: Path) -> bool:
        candidate = Path(path).expanduser()
        return any(candidate == legacy or candidate.as_posix() == legacy.as_posix() for legacy in self.legacy_manifest_paths)

    def path_set_for_policy(self, policy: str) -> IntegrityManifestPathSet:
        normalized = normalize_policy(policy)
        descriptions = {
            "dev": "Development/source integrity baseline used for manual testing and Integrity Health.",
            "pre_release": "Signed pre-release source integrity baseline used by Pre-UAT release checks.",
            "public_release": "Signed public release source integrity baseline used by Pre-UAT release checks.",
            "runtime": "Runtime install integrity baseline outside the source tree.",
        }
        return IntegrityManifestPathSet(
            policy=normalized,
            manifest_path=self.manifest_for_policy(normalized),
            signature_path=self.signature_for_policy(normalized),
            signature_bundle_path=self.canonical_signature_bundle,
            trust_policy_path=self.canonical_trust_policy,
            legacy_paths=self.legacy_manifest_paths,
            description=descriptions[normalized],
        )


def normalize_policy(policy: str | None) -> str:
    normalized = str(policy or "dev").strip()
    if normalized == "release":
        normalized = "public_release"
    if normalized not in VALID_INTEGRITY_POLICIES:
        raise ValueError(f"unsupported integrity policy: {policy}")
    return normalized


def integrity_manifest_paths(root: Path | None = None) -> IntegrityManifestPaths:
    base = Path(root or Path.cwd()).expanduser().resolve(strict=False)
    runtime_base = Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "runtime"
    canonical_manifest = base / "mac_audit_agent" / "integrity" / "integrity_manifest.json"
    canonical_signature_bundle = base / "mac_audit_agent" / "integrity" / "integrity_manifest.signature.json"
    canonical_trust_policy = base / "mac_audit_agent" / "integrity" / "trust_policy.json"
    canonical_trusted_developer_machines = base / "mac_audit_agent" / "integrity" / "trusted_developer_machines.json"
    legacy_development_manifest = base / "mac_audit_agent" / "integrity" / "development_manifest.json"
    legacy_development_signature = base / "mac_audit_agent" / "integrity" / "development_manifest.sig"
    legacy_release_manifest = base / "mac_audit_agent" / "integrity" / "release_manifest.json"
    legacy_release_signature = base / "mac_audit_agent" / "integrity" / "release_manifest.sig"
    return IntegrityManifestPaths(
        canonical_manifest=canonical_manifest,
        canonical_signature_bundle=canonical_signature_bundle,
        canonical_trust_policy=canonical_trust_policy,
        canonical_trusted_developer_machines=canonical_trusted_developer_machines,
        legacy_development_manifest=legacy_development_manifest,
        legacy_development_signature=legacy_development_signature,
        legacy_release_manifest=legacy_release_manifest,
        legacy_release_signature=legacy_release_signature,
        runtime_install_manifest=runtime_base / "install_manifest.json",
        runtime_install_signature=runtime_base / "install_manifest.sig",
        legacy_manifest_paths=(
            base / "mac_audit_agent" / "security" / "integrity_manifest.json",
            base / "mac_audit_agent" / "security" / "integrity_manifest.json.sig",
            base / "mac_audit_agent" / "integrity" / "integrity_manifest.signatures.json",
            legacy_release_manifest,
            legacy_release_signature,
            legacy_development_manifest,
            legacy_development_signature,
            runtime_base / "install_manifest.json",
            runtime_base / "install_manifest.sig",
        ),
    )


def resolve_manifest_path(root: Path, policy: str = "dev", manifest: Path | None = None) -> Path:
    root = Path(root).expanduser().resolve(strict=False)
    if manifest is not None:
        path = Path(manifest).expanduser()
        return path if path.is_absolute() else root / path
    return integrity_manifest_paths(root).manifest_for_policy(policy)


def resolve_signature_path(root: Path, policy: str = "dev", signature: Path | None = None, manifest: Path | None = None) -> Path:
    root = Path(root).expanduser().resolve(strict=False)
    if signature is not None:
        path = Path(signature).expanduser()
        return path if path.is_absolute() else root / path
    if manifest is not None:
        manifest_path = Path(manifest).expanduser()
        if not manifest_path.is_absolute():
            manifest_path = root / manifest_path
        paths = integrity_manifest_paths(root)
        if manifest_path.resolve(strict=False) == paths.canonical_manifest.resolve(strict=False):
            return paths.canonical_signature_bundle
        return manifest_path.with_suffix(".sig")
    return integrity_manifest_paths(root).signature_for_policy(policy)


__all__ = [
    "IntegrityManifestPaths",
    "IntegrityManifestPathSet",
    "IntegrityPolicy",
    "VALID_INTEGRITY_POLICIES",
    "integrity_manifest_paths",
    "normalize_policy",
    "resolve_manifest_path",
    "resolve_signature_path",
]
