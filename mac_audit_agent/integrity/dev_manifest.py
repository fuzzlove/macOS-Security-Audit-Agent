from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.compat.datetime_compat import utc_now

from mac_audit_agent.integrity.canonical import (
    canonical_json_bytes,
    manifest_files,
    manifest_metadata,
    signed_payload_from_manifest,
)
from mac_audit_agent.integrity.exclusions import default_excluded_patterns, is_runtime_mutable_path
from mac_audit_agent.integrity.manifest_paths import (
    integrity_manifest_paths,
    normalize_policy,
    resolve_manifest_path as registry_manifest_path,
    resolve_signature_path as registry_signature_path,
)
from mac_audit_agent.integrity.manifest_signing import sign_manifest_with_release_key, verify_release_key_signature_bundle
from mac_audit_agent.integrity.signing import (
    DEFAULT_PUBLIC_KEY_PATH,
    SIGNATURE_ALGORITHM,
    SigningError,
    calculate_file_sha256,
    load_private_key,
    load_public_key,
    public_key_id,
    verify_manifest_signature,
)
from mac_audit_agent.version import APP_VERSION

SCHEMA_VERSION = "1"
GENERATOR_VERSION = f"msaa-integrity-dev-{APP_VERSION}"
HASH_ALGORITHM = "sha256"
CANONICAL_MANIFEST_RELATIVE_PATH = "mac_audit_agent/integrity/integrity_manifest.json"
CANONICAL_SIGNATURE_RELATIVE_PATH = "mac_audit_agent/integrity/integrity_manifest.signature.json"
DEFAULT_AUDIT_LOG = Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "integrity_audit.jsonl"

PROTECTED_ROOTS = (
    "mac_audit_agent",
    "scripts",
    "pyproject.toml",
    "requirements.txt",
    "README.md",
    "SECURITY.md",
)
PROTECTED_SUFFIXES = {
    ".py",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".sh",
    ".plist",
    ".html",
    ".css",
    ".qss",
    ".sql",
    ".png",
    ".jpg",
    ".jpeg",
    ".icns",
    ".ico",
}
EXCLUDED_DIR_PARTS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    "htmlcov",
    ".tox",
    ".nox",
    "node_modules",
    "logs",
    "cache",
    "caches",
    "reports",
    "exports",
    "tmp",
    "temp",
}
EXCLUDED_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".log",
    ".tmp",
    ".cache",
    ".zip",
}
EXCLUDED_RELATIVE_PATHS = {
    CANONICAL_MANIFEST_RELATIVE_PATH,
    CANONICAL_SIGNATURE_RELATIVE_PATH,
    "mac_audit_agent/integrity/trust_policy.json",
    "mac_audit_agent/integrity/trusted_developer_machines.json",
    "mac_audit_agent/integrity/integrity_manifest.signature.json",
    "mac_audit_agent/integrity/integrity_manifest.signatures.json",
    "mac_audit_agent/integrity/developer_identities.json",
    "mac_audit_agent/integrity/approved_source_changes.jsonl",
    "mac_audit_agent/integrity/release_manifest.json",
    "mac_audit_agent/integrity/release_manifest.sig",
    "mac_audit_agent/integrity/development_manifest.json",
    "mac_audit_agent/integrity/development_manifest.sig",
    "mac_audit_agent/security/integrity_manifest.json",
    "mac_audit_agent/security/integrity_manifest.json.sig",
    "mac_audit_agent/security/integrity_manifest_public.pem",
    "dist/MSAA_RELEASE_ARTIFACTS.json",
    "dist/MSAA_RELEASE_ARTIFACTS.signature.json",
}


@dataclass(slots=True)
class IntegrityFinding:
    relative_path: str
    status: str
    severity: str
    expected_hash: str = ""
    observed_hash: str = ""
    recommended_action: str = ""


@dataclass(slots=True)
class IntegrityVerificationSummary:
    ok: bool
    manifest_present: bool
    manifest_signature_valid: bool | None
    signature_required: bool
    unsigned_manifest_warning: bool
    protected_files_verified: int
    modified_files: list[IntegrityFinding] = field(default_factory=list)
    missing_files: list[IntegrityFinding] = field(default_factory=list)
    unexpected_files: list[IntegrityFinding] = field(default_factory=list)
    schema_errors: list[str] = field(default_factory=list)
    signature_errors: list[str] = field(default_factory=list)
    manifest_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "manifest_present": self.manifest_present,
            "manifest_signature_valid": self.manifest_signature_valid,
            "signature_required": self.signature_required,
            "unsigned_manifest_warning": self.unsigned_manifest_warning,
            "protected_files_verified": self.protected_files_verified,
            "modified_count": len(self.modified_files),
            "missing_count": len(self.missing_files),
            "unexpected_count": len(self.unexpected_files),
            "schema_errors": list(self.schema_errors),
            "signature_errors": list(self.signature_errors),
            "modified_files": [asdict(finding) for finding in self.modified_files],
            "missing_files": [asdict(finding) for finding in self.missing_files],
            "unexpected_files": [asdict(finding) for finding in self.unexpected_files],
            "manifest_metadata": dict(self.manifest_metadata),
            "recommended_remediation": recommended_remediation(self),
        }


def utc_now_iso() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def resolve_manifest_path(root: Path, manifest: Path | None = None, *, policy: str = "dev") -> Path:
    return registry_manifest_path(root, policy, manifest)


def resolve_signature_path(root: Path, signature: Path | None = None, manifest: Path | None = None, *, policy: str = "dev") -> Path:
    return registry_signature_path(root, policy, signature, manifest)


def is_developer_or_build_mode(explicit: bool = False) -> bool:
    return explicit or os.environ.get("MSAA_DEVELOPER_MODE") == "1" or os.environ.get("MSAA_BUILD_MODE") == "1"


def git_output(args: list[str], root: Path) -> str:
    try:
        result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=False, timeout=15)
    except Exception:
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def git_dirty_files(root: Path) -> list[str]:
    output = git_output(["status", "--porcelain"], root)
    return [line for line in output.splitlines() if line.strip()]


def protected_scope(rel: str) -> bool:
    first = rel.split("/", 1)[0]
    if rel in PROTECTED_ROOTS or first in PROTECTED_ROOTS:
        return True
    return False


def is_excluded_integrity_path(rel: str) -> bool:
    normalized = rel.replace("\\", "/").lstrip("/")
    if normalized in EXCLUDED_RELATIVE_PATHS:
        return True
    if is_runtime_mutable_path(normalized, default_excluded_patterns()):
        return True
    parts = set(normalized.split("/"))
    if parts & EXCLUDED_DIR_PARTS:
        return True
    path = Path(normalized)
    if path.suffix.lower() in EXCLUDED_SUFFIXES:
        return True
    if path.name.endswith((".egg-info", ".dist-info")):
        return True
    return False


def iter_protected_files(root: Path) -> list[Path]:
    root = Path(root).resolve(strict=False)
    files: list[Path] = []
    for protected_root in PROTECTED_ROOTS:
        candidate = root / protected_root
        if not candidate.exists():
            continue
        candidates = [candidate] if candidate.is_file() else candidate.rglob("*")
        for path in candidates:
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if not protected_scope(rel) or is_excluded_integrity_path(rel):
                continue
            if path.suffix.lower() not in PROTECTED_SUFFIXES:
                continue
            files.append(path)
    return sorted(set(files), key=lambda item: item.relative_to(root).as_posix())


def build_manifest(
    root: Path,
    *,
    author: str,
    reason: str,
    build_id: str = "",
    release_id: str = "",
    policy: str = "dev",
) -> dict[str, Any]:
    if not author.strip():
        raise ValueError("--author is required for authorized rehash")
    if not reason.strip():
        raise ValueError("--reason is required for authorized rehash")
    root = Path(root).resolve(strict=False)
    files = []
    for path in iter_protected_files(root):
        stat = path.stat()
        files.append(
            {
                "manifest_schema_version": SCHEMA_VERSION,
                "relative_path": path.relative_to(root).as_posix(),
                "sha256": calculate_file_sha256(path),
                "hash_algorithm": HASH_ALGORITHM,
                "file_size": int(stat.st_size),
            }
        )
    public_key = b""
    try:
        public_key = load_public_key(DEFAULT_PUBLIC_KEY_PATH)
    except SigningError:
        pass
    signed_payload = {
        "manifest_schema_version": "2",
        "payload_schema_version": SCHEMA_VERSION,
        "project": "macOS Security Audit Agent",
        "generated_at": utc_now_iso(),
        "policy_mode": normalize_policy(policy),
        "source_type": "source_tree",
        "author": author.strip(),
        "reason": reason.strip(),
        "build_id": build_id.strip(),
        "release_id": release_id.strip(),
        "git_commit": git_output(["rev-parse", "HEAD"], root),
        "hash_algorithm": HASH_ALGORITHM,
        "protected_scope": list(PROTECTED_ROOTS),
        "excluded_runtime_scope": sorted(set(default_excluded_patterns()) | EXCLUDED_DIR_PARTS | {suffix for suffix in EXCLUDED_SUFFIXES}),
        "files": files,
    }
    return {
        "manifest_schema_version": "2",
        "payload": signed_payload,
        "metadata": {
            "generated_at": signed_payload["generated_at"],
            "generator_version": GENERATOR_VERSION,
            "baseline_mode": normalize_policy(policy),
            "policy_mode": normalize_policy(policy),
            "git_dirty": bool(git_dirty_files(root)),
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "public_key_id": public_key_id(public_key) if public_key else "",
            "python_executable": sys.executable,
            "python_version": sys.version.split()[0],
            "platform": platform.platform(),
            "controls_statement": (
                "DoD-aligned tamper-evident file integrity monitoring using FIPS 180-4 SHA-256. "
                "This is a backup integrity control and is not a claim of formal DoD certification or compliance."
            ),
        },
    }


def write_manifest(payload: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(payload) + b"\n")
    return path


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def compare_manifest_entries(old: dict[str, Any] | None, new: dict[str, Any]) -> dict[str, list[str]]:
    old_files = {item.get("relative_path", ""): item.get("sha256", "") for item in manifest_files(old or {}) if isinstance(item, dict)}
    new_files = {item.get("relative_path", ""): item.get("sha256", "") for item in manifest_files(new) if isinstance(item, dict)}
    return {
        "added": sorted(path for path in new_files if path and path not in old_files),
        "removed": sorted(path for path in old_files if path and path not in new_files),
        "modified": sorted(path for path, digest in new_files.items() if path in old_files and old_files[path] != digest),
    }


def verify_manifest(
    root: Path,
    *,
    manifest_path: Path | None = None,
    signature_path: Path | None = None,
    public_key_path: Path | None = None,
    require_signature: bool = False,
    policy: str = "dev",
) -> IntegrityVerificationSummary:
    root = Path(root).resolve(strict=False)
    manifest = resolve_manifest_path(root, manifest_path, policy=policy)
    signature = resolve_signature_path(root, signature_path, manifest, policy=policy)
    if not manifest.exists():
        return IntegrityVerificationSummary(
            ok=False,
            manifest_present=False,
            manifest_signature_valid=None,
            signature_required=require_signature,
            unsigned_manifest_warning=False,
            protected_files_verified=0,
            schema_errors=["integrity manifest is missing"],
        )
    try:
        payload = load_manifest(manifest)
    except Exception as exc:
        return IntegrityVerificationSummary(
            ok=False,
            manifest_present=True,
            manifest_signature_valid=None,
            signature_required=require_signature,
            unsigned_manifest_warning=False,
            protected_files_verified=0,
            schema_errors=[f"manifest could not be parsed: {type(exc).__name__}: {exc}"],
        )

    signature_valid: bool | None = None
    signature_errors: list[str] = []
    unsigned_warning = False
    if signature.exists() and signature.name.endswith((".signatures.json", ".signature.json")):
        signature_valid = None
        if require_signature:
            signature_errors.append("strict signature bundle verification is required for developer-machine signature bundles")
    elif signature.exists():
        try:
            signature_valid = verify_manifest_signature(manifest, signature, public_key_path or DEFAULT_PUBLIC_KEY_PATH)
        except Exception as exc:
            signature_valid = False
            signature_errors.append(f"integrity manifest signature verification failed: {type(exc).__name__}: {exc}")
        if not signature_valid:
            signature_errors.append("integrity manifest signature is invalid")
    elif require_signature:
        signature_valid = False
        signature_errors.append("integrity manifest signature is required but missing")
    else:
        unsigned_warning = True

    schema_errors: list[str] = []
    signed_payload = signed_payload_from_manifest(payload)
    metadata_payload = manifest_metadata(payload)
    if signed_payload.get("manifest_schema_version") not in {SCHEMA_VERSION, "2"} and signed_payload.get("payload_schema_version") != SCHEMA_VERSION:
        schema_errors.append(f"unsupported manifest schema: {payload.get('manifest_schema_version')!r}")
    if signed_payload.get("hash_algorithm") != HASH_ALGORITHM:
        schema_errors.append(f"unsupported hash algorithm: {signed_payload.get('hash_algorithm')!r}")

    expected = {item.get("relative_path", ""): item for item in manifest_files(payload) if isinstance(item, dict) and item.get("relative_path")}
    observed_paths = {path.relative_to(root).as_posix(): path for path in iter_protected_files(root)}
    modified: list[IntegrityFinding] = []
    missing: list[IntegrityFinding] = []
    unexpected: list[IntegrityFinding] = []
    verified_count = 0
    for rel, entry in expected.items():
        path = root / rel
        if rel not in observed_paths or not path.exists():
            missing.append(
                IntegrityFinding(
                    relative_path=rel,
                    status="missing",
                    severity="high",
                    expected_hash=str(entry.get("sha256", "")),
                    recommended_action="Restore the protected file from trusted source control or reinstall MSAA.",
                )
            )
            continue
        observed_hash = calculate_file_sha256(path)
        expected_hash = str(entry.get("sha256", ""))
        if observed_hash != expected_hash:
            modified.append(
                IntegrityFinding(
                    relative_path=rel,
                    status="modified",
                    severity="high",
                    expected_hash=expected_hash,
                    observed_hash=observed_hash,
                    recommended_action="Investigate the source change and rehash only through the authorized developer/build workflow.",
                )
            )
        else:
            verified_count += 1

    for rel, path in observed_paths.items():
        if rel not in expected:
            unexpected.append(
                IntegrityFinding(
                    relative_path=rel,
                    status="unexpected",
                    severity="medium",
                    observed_hash=calculate_file_sha256(path),
                    recommended_action="Review the unexpected protected-scope file and either remove it or authorize it in a new manifest.",
                )
            )

    ok = not modified and not missing and not unexpected and not schema_errors and not signature_errors
    metadata = {
        "generated_at": signed_payload.get("generated_at", metadata_payload.get("generated_at", "")),
        "author": signed_payload.get("author", metadata_payload.get("author", "")),
        "build_id": signed_payload.get("build_id", metadata_payload.get("build_id", "")),
        "release_id": signed_payload.get("release_id", metadata_payload.get("release_id", "")),
        "generator_version": metadata_payload.get("generator_version", ""),
        "git_commit": signed_payload.get("git_commit", metadata_payload.get("git_commit", "")),
        "manifest_path": str(manifest),
        "signature_path": str(signature),
        "policy_mode": policy,
    }
    return IntegrityVerificationSummary(
        ok=ok,
        manifest_present=True,
        manifest_signature_valid=signature_valid,
        signature_required=require_signature,
        unsigned_manifest_warning=unsigned_warning,
        protected_files_verified=verified_count,
        modified_files=modified,
        missing_files=missing,
        unexpected_files=unexpected,
        schema_errors=schema_errors,
        signature_errors=signature_errors,
        manifest_metadata=metadata,
    )


def recommended_remediation(summary: IntegrityVerificationSummary) -> str:
    if not summary.manifest_present:
        return "Generate a manifest with the authorized developer/build rehash command before trusting runtime file integrity."
    if summary.signature_errors:
        return "Fail closed: do not trust this manifest until the detached Ed25519 signature is restored or regenerated by release signing."
    if summary.modified_files or summary.missing_files:
        return "Investigate protected file drift, restore trusted source, then run an explicit authorized rehash if the change is legitimate."
    if summary.unexpected_files:
        return "Review unexpected protected-scope files before authorizing them in a regenerated manifest."
    if summary.unsigned_manifest_warning:
        return "Unsigned manifest verified by hash comparison only; sign the manifest for tamper-evident release use."
    return "Protected files match the trusted integrity manifest."


def write_audit_record(
    *,
    action: str,
    status: str,
    root: Path,
    audit_log: Path | None = None,
    author: str = "",
    reason: str = "",
    details: dict[str, Any] | None = None,
) -> Path:
    path = Path(audit_log or DEFAULT_AUDIT_LOG).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": utc_now_iso(),
        "action": action,
        "status": status,
        "author": author,
        "reason": reason,
        "root": str(Path(root).resolve(strict=False)),
        "python_executable": sys.executable,
        "python_version": sys.version.split()[0],
        "git_commit": git_output(["rev-parse", "HEAD"], Path(root).resolve(strict=False)),
        "details": details or {},
    }
    try:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        if audit_log is not None:
            raise
        path = Path("/tmp/msaa_integrity_audit.jsonl")
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    return path


def rehash_manifest(
    root: Path,
    *,
    author: str,
    reason: str,
    manifest_path: Path | None = None,
    signature_path: Path | None = None,
    build_id: str = "",
    release_id: str = "",
    developer_mode: bool = False,
    require_clean_git: bool = False,
    sign: bool = False,
    private_key_path: Path | None = None,
    public_key_path: Path | None = None,
    release_mode: bool = False,
    audit_log: Path | None = None,
    policy: str | None = None,
    legacy_output: bool = False,
) -> tuple[Path, dict[str, list[str]]]:
    root = Path(root).resolve(strict=False)
    selected_policy = normalize_policy(policy or ("public_release" if release_mode else "dev"))
    if developer_mode and release_mode and policy is None:
        raise ValueError("Ambiguous integrity mode: --developer-mode and --release-mode were both provided. Use --policy dev, --policy pre_release, or --policy public_release.")
    if not policy and not is_developer_or_build_mode(developer_mode):
        raise PermissionError("rehash requires explicit developer/build mode")
    if require_clean_git:
        dirty = git_dirty_files(root)
        if dirty:
            raise RuntimeError("refusing to rehash dirty source tree with --require-clean-git:\n" + "\n".join(f"  {item}" for item in dirty))
    manifest = resolve_manifest_path(root, manifest_path, policy=selected_policy)
    if integrity_manifest_paths(root).is_legacy(manifest) and not legacy_output:
        raise RuntimeError("Legacy manifest path was updated, but Pre-UAT validates the canonical release manifest. Run rehash with --policy pre_release or migrate legacy manifest.")
    if legacy_output and not integrity_manifest_paths(root).is_legacy(manifest):
        raise RuntimeError("--legacy-output requires --manifest to point at a legacy manifest path.")
    old_manifest = load_manifest(manifest) if manifest.exists() else None
    payload = build_manifest(root, author=author, reason=reason, build_id=build_id, release_id=release_id, policy=selected_policy)
    diff = compare_manifest_entries(old_manifest, payload)
    write_manifest(payload, manifest)

    signature = resolve_signature_path(root, signature_path, manifest, policy=selected_policy)
    signature_valid: bool | None = None
    if sign:
        sign_manifest_with_release_key(
            root,
            manifest,
            signature,
            private_key_path=private_key_path,
            public_key_path=public_key_path or DEFAULT_PUBLIC_KEY_PATH,
            policy=selected_policy,
            author=author,
            reason=reason,
            build_id=build_id,
            release_id=release_id,
        )
        verification = verify_release_key_signature_bundle(manifest, signature, public_key_path=public_key_path or DEFAULT_PUBLIC_KEY_PATH)
        signature_valid = verification.get("status") == "verified"
        if not signature_valid:
            raise SigningError(f"manifest signature verification failed after signing: {verification.get('reason', 'unknown error')}")

    write_audit_record(
        action="rehash",
        status="succeeded",
        root=root,
        audit_log=audit_log,
        author=author,
        reason=reason,
        details={
            "manifest_path": str(manifest),
            "signature_path": str(signature) if sign else "",
            "signature_valid": signature_valid,
            "files_added": diff["added"],
            "files_removed": diff["removed"],
            "files_modified": diff["modified"],
            "build_id": build_id,
            "release_id": release_id,
            "policy_mode": selected_policy,
        },
    )
    return manifest, diff


def doctor_status(root: Path, **kwargs: Any) -> dict[str, Any]:
    summary = verify_manifest(root, **kwargs)
    return {
        "integrity_manifest_present": summary.manifest_present,
        "manifest_signature_valid": summary.manifest_signature_valid,
        "protected_files_verified": summary.protected_files_verified,
        "modified_files": len(summary.modified_files),
        "missing_files": len(summary.missing_files),
        "unexpected_files": len(summary.unexpected_files),
        "last_manifest_generation_timestamp": summary.manifest_metadata.get("generated_at", ""),
        "author": summary.manifest_metadata.get("author", ""),
        "build_id": summary.manifest_metadata.get("build_id", ""),
        "release_id": summary.manifest_metadata.get("release_id", ""),
        "recommended_remediation": recommended_remediation(summary),
        "status": "verified" if summary.ok else "attention_required",
        "details": summary.to_dict(),
    }
