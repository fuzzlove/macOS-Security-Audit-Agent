from __future__ import annotations

import argparse
import getpass
import grp
import hashlib
import json
import os
import platform
import pwd
import stat
import subprocess
import sys
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from mac_audit_agent.compat.datetime_compat import utc_now
from mac_audit_agent.build_identity import detect_build_identity
from mac_audit_agent.integrity.baseline_modes import baseline_mode_for_source_type
from mac_audit_agent.integrity.exclusions import classify_path_category
from mac_audit_agent.integrity.hasher import DEFAULT_EXCLUDED_PATTERNS, calculate_sha256, collect_integrity_files
from mac_audit_agent.integrity.trust_states import IntegrityTrustState
from mac_audit_agent.version import APP_VERSION


SourceType = Literal[
    "source_tree",
    "pip_package",
    "pypi_wheel",
    "pyinstaller_app",
    "system_daemon_runtime",
    "user_notifier_runtime",
    "system_runtime",
    "user_runtime",
]
TrustState = str

SOURCE_TYPE_ALIASES = {
    "system_runtime": "system_daemon_runtime",
    "user_runtime": "user_notifier_runtime",
    "pypi_wheel": "pip_package",
}


def canonical_source_type(source_type: str) -> str:
    return SOURCE_TYPE_ALIASES.get(str(source_type), str(source_type))

@dataclass
class IntegrityFileEntry:
    relative_path: str
    sha256: str = ""
    size_bytes: int = 0
    mode: str = ""
    owner: str = ""
    group: str = ""
    file_type: str = "file"
    required: bool = True
    executable: bool = False
    source_category: str = "source"
    absolute_path: str | None = None
    last_verified_at: str = ""
    verification_status: str = "unknown"
    symlink_target: str = ""
    error: str = ""

    @property
    def path(self) -> str:
        return self.relative_path

    @property
    def size(self) -> int:
        return self.size_bytes

    @property
    def category(self) -> str:
        return self.source_category


@dataclass
class IntegrityManifest:
    manifest_id: str
    manifest_version: str
    created_at: str
    created_by: str
    source_type: SourceType
    app_version: str
    git_commit: str
    build_id: str
    python_version: str
    platform: str
    file_entries: list[IntegrityFileEntry] = field(default_factory=list)
    excluded_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDED_PATTERNS))
    exclusions: list[str] = field(default_factory=list)
    baseline_mode: str = "source_development"
    source_root: str = ""
    approved_change_id: str | None = None
    generated_by: str = ""
    verification_commands: list[str] = field(default_factory=list)
    verification_results: list[dict[str, Any]] = field(default_factory=list)
    manifest_hash: str = ""
    signature_status: str = "unsigned"
    signature_algorithm: str = ""
    signature_key_id: str = ""
    signature_path: str | None = None
    trust_state: TrustState = "trusted"
    notes: str = ""
    root_path: str = ""
    dirty_source: bool = False

    @property
    def trust_level(self) -> str:
        return self.trust_state

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["files"] = payload["file_entries"]
        return payload

    @property
    def files(self) -> list[IntegrityFileEntry]:
        return self.file_entries


TrustedManifest = IntegrityManifest


def utc_now_iso() -> str:
    return utc_now().isoformat()


def _git(args: list[str], root: Path) -> str:
    try:
        result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, timeout=5, check=False)
    except Exception:
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _git_commit(root: Path) -> str:
    return _git(["rev-parse", "HEAD"], root)


def _git_dirty(root: Path) -> bool:
    status = _git(["status", "--porcelain"], root)
    return bool(status)


def _git_tracked_files(root: Path) -> list[Path]:
    output = _git(["ls-files"], root)
    if not output:
        return []
    files: list[Path] = []
    for line in output.splitlines():
        candidate = (root / line).resolve(strict=False)
        try:
            candidate.relative_to(root.resolve(strict=False))
        except ValueError:
            continue
        if candidate.exists() or candidate.is_symlink():
            files.append(candidate)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def _owner_group(stat_result: os.stat_result) -> tuple[str, str]:
    try:
        owner = pwd.getpwuid(stat_result.st_uid).pw_name
    except KeyError:
        owner = str(stat_result.st_uid)
    try:
        group = grp.getgrgid(stat_result.st_gid).gr_name
    except KeyError:
        group = str(stat_result.st_gid)
    return owner, group


def _entry_for_path(path: Path, root: Path, source_category: str) -> IntegrityFileEntry:
    rel = path.relative_to(root).as_posix()
    try:
        st = path.lstat()
        owner, group = _owner_group(st)
        mode = stat.S_IMODE(st.st_mode)
        if stat.S_ISLNK(st.st_mode):
            return IntegrityFileEntry(
                relative_path=rel,
                sha256="",
                size_bytes=0,
                mode=oct(mode),
                owner=owner,
                group=group,
                file_type="symlink",
                executable=False,
                source_category=source_category,
                symlink_target=os.readlink(path),
            )
        return IntegrityFileEntry(
            relative_path=rel,
            sha256=calculate_sha256(path),
            size_bytes=int(st.st_size),
            mode=oct(mode),
            owner=owner,
            group=group,
            file_type="file",
            executable=bool(mode & 0o111),
            source_category=source_category,
        )
    except Exception as exc:
        return IntegrityFileEntry(relative_path=rel, source_category=source_category, verification_status="unknown", error=str(exc))


def _manifest_hash(manifest: IntegrityManifest) -> str:
    payload = manifest.to_dict()
    payload["manifest_hash"] = ""
    payload.pop("files", None)
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    import hashlib

    return hashlib.sha256(serialized).hexdigest()


def create_integrity_manifest(
    root: Path,
    *,
    source_type: SourceType = "source_tree",
    excluded_patterns: list[str] | None = None,
    app_version: str = APP_VERSION,
    build_id: str | None = None,
    notes: str = "",
    trust_state: TrustState = "trusted",
    baseline_mode: str | None = None,
    approved_change_id: str | None = None,
    verification_commands: list[str] | None = None,
    verification_results: list[dict[str, Any]] | None = None,
    signature_status: str | None = None,
    signature_path: str | None = None,
) -> IntegrityManifest:
    base = Path(root).resolve(strict=False)
    canonical_type = canonical_source_type(source_type)
    identity = detect_build_identity(base, install_mode=canonical_type if canonical_type in {"source_tree", "pip_package", "pyinstaller_app", "system_daemon_runtime", "user_notifier_runtime"} else None)  # type: ignore[arg-type]
    patterns = list(excluded_patterns or DEFAULT_EXCLUDED_PATTERNS)
    mode = baseline_mode or baseline_mode_for_source_type(canonical_type)
    effective_trust = trust_state
    if trust_state == "trusted" and canonical_type == "source_tree":
        effective_trust = (
            IntegrityTrustState.TRUSTED_CODEX_APPROVED_CHANGE.value
            if approved_change_id
            else IntegrityTrustState.TRUSTED_DEVELOPMENT_BASELINE.value
        )
    discovered = _git_tracked_files(base) if canonical_type == "source_tree" else []
    if not discovered:
        discovered = collect_integrity_files(base, canonical_type, patterns)
    else:
        from mac_audit_agent.integrity.hasher import is_excluded

        discovered = [path for path in discovered if not is_excluded(path.relative_to(base).as_posix(), patterns)]
    entries = [_entry_for_path(path, base, _source_category(path)) for path in discovered]
    manifest = IntegrityManifest(
        manifest_id=f"msaa-integrity-{uuid.uuid4().hex}",
        manifest_version="1",
        created_at=utc_now_iso(),
        created_by=getpass.getuser(),
        source_type=canonical_type,  # type: ignore[arg-type]
        app_version=app_version or identity.app_version,
        git_commit=identity.git_commit if canonical_type == "source_tree" else "",
        build_id=identity.build_id if build_id is None else build_id,
        python_version=sys.version.split()[0],
        platform=platform.platform(),
        file_entries=entries,
        excluded_patterns=patterns,
        exclusions=patterns,
        baseline_mode=mode,
        source_root=str(base),
        approved_change_id=approved_change_id,
        generated_by=getpass.getuser(),
        verification_commands=list(verification_commands or []),
        verification_results=list(verification_results or []),
        signature_status="unsigned",
        signature_path=signature_path,
        trust_state=effective_trust,
        notes=notes,
        root_path=str(base),
        dirty_source=_git_dirty(base) if canonical_type == "source_tree" else False,
    )
    manifest.manifest_hash = _manifest_hash(manifest)
    if signature_status:
        manifest.signature_status = signature_status
        manifest.manifest_hash = _manifest_hash(manifest)
    return manifest


def _source_category(path: Path) -> str:
    return classify_path_category(path.as_posix())


def load_integrity_manifest(path: Path) -> IntegrityManifest:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    has_trust_state = "trust_state" in raw
    original_source_type = raw.get("source_type", "source_tree")
    raw.setdefault("trust_state", "trusted")
    raw["source_type"] = canonical_source_type(raw.get("source_type", "source_tree"))
    raw_entries = raw.get("file_entries", raw.get("files", []))
    for item in raw_entries:
        if isinstance(item, dict) and "category" in item and "source_category" not in item:
            item["source_category"] = item.pop("category")
    entries = [IntegrityFileEntry(**{k: v for k, v in item.items() if k in IntegrityFileEntry.__dataclass_fields__}) for item in raw_entries if isinstance(item, dict)]
    raw["file_entries"] = entries
    raw.pop("files", None)
    raw.setdefault("excluded_patterns", raw.get("exclusions", list(DEFAULT_EXCLUDED_PATTERNS)))
    raw.setdefault("exclusions", list(raw.get("excluded_patterns", list(DEFAULT_EXCLUDED_PATTERNS))))
    raw.setdefault("baseline_mode", baseline_mode_for_source_type(raw.get("source_type", "source_tree")))
    raw.setdefault("source_root", raw.get("root_path", ""))
    raw.setdefault("approved_change_id", None)
    raw.setdefault("generated_by", raw.get("created_by", ""))
    raw.setdefault("verification_commands", [])
    raw.setdefault("verification_results", [])
    raw.setdefault("signature_path", None)
    raw = {k: v for k, v in raw.items() if k in IntegrityManifest.__dataclass_fields__}
    manifest = IntegrityManifest(**raw)
    expected = manifest.manifest_hash
    if expected and _manifest_hash(manifest) != expected:
        legacy_payload = manifest.to_dict()
        legacy_payload["manifest_hash"] = ""
        legacy_payload.pop("files", None)
        legacy_payload.pop("trust_state", None)
        for new_key in [
            "exclusions",
            "baseline_mode",
            "source_root",
            "approved_change_id",
            "generated_by",
            "verification_commands",
            "verification_results",
            "signature_path",
        ]:
            legacy_payload.pop(new_key, None)
        legacy_payload["source_type"] = original_source_type
        legacy_hash = hashlib.sha256(
            json.dumps(legacy_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        if has_trust_state or legacy_hash != expected:
            raise ValueError("integrity manifest hash mismatch")
    return manifest


def select_manifest_path_for_root(root: Path, source_type: str = "source_tree") -> Path:
    canonical = canonical_source_type(source_type)
    base = Path(root)
    if canonical == "source_tree":
        return base / "msaa_integrity_manifest.json"
    if canonical == "pip_package":
        return base / "package_integrity_manifest.json"
    return base / "integrity_manifest.json"


def write_integrity_manifest(manifest: IntegrityManifest, path: Path) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return output


def _default_source_manifest_path(root: Path) -> Path:
    return Path(root) / "msaa_integrity_manifest.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create trusted MSAA integrity manifests.")
    parser.add_argument("--root", default=".", help="Root directory to record as trusted.")
    parser.add_argument("--output", default="", help="Manifest output path.")
    parser.add_argument("--create-source-manifest", action="store_true")
    parser.add_argument("--create-runtime-manifest", action="store_true")
    parser.add_argument("--create-user-notifier-manifest", action="store_true")
    parser.add_argument("--source-type", default="")
    parser.add_argument("--draft", action="store_true", help="Create an untrusted draft manifest for preview/diagnostics.")
    parser.add_argument("--preview", action="store_true", help="Alias for --draft; preview files without trusting them.")
    parser.add_argument("--trusted-confirmation", default="", help="Must be TRUST CURRENT FILES for runtime/source trust creation.")
    args = parser.parse_args(argv)
    if not (args.create_source_manifest or args.create_runtime_manifest or args.create_user_notifier_manifest):
        parser.error("choose --create-source-manifest, --create-runtime-manifest, or --create-user-notifier-manifest")
    draft = bool(args.draft or args.preview)
    if not draft and args.trusted_confirmation != "TRUST CURRENT FILES":
        parser.error("refusing to create a trusted manifest without --trusted-confirmation 'TRUST CURRENT FILES'")
    root = Path(args.root).resolve(strict=False)
    source_type: SourceType = "user_notifier_runtime" if args.create_user_notifier_manifest else "system_daemon_runtime" if args.create_runtime_manifest else "source_tree"
    if args.source_type:
        source_type = args.source_type  # type: ignore[assignment]
    output = Path(args.output).expanduser() if args.output else (_default_source_manifest_path(root) if source_type == "source_tree" else root / "integrity_manifest.json")
    manifest = create_integrity_manifest(
        root,
        source_type=source_type,
        notes="Draft manifest for preview; not trusted." if draft else "Created after explicit trusted confirmation.",
        trust_state="draft" if draft else "trusted",
    )
    write_integrity_manifest(manifest, output)
    print(f"{manifest.trust_state} integrity manifest written: {output}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
