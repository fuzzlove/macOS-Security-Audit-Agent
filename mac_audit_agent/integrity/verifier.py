from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import stat
import subprocess
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.build_identity import detect_build_identity
from mac_audit_agent.integrity.hasher import calculate_sha256, is_excluded, iter_integrity_files
from mac_audit_agent.integrity.manifest import canonical_source_type
from mac_audit_agent.integrity.manifest import IntegrityFileEntry, IntegrityManifest, load_integrity_manifest


@dataclass
class IntegrityVerificationResult:
    result_id: str
    checked_at: str
    manifest_path: str
    source_type: str
    overall_status: str
    health_impact: str = "degraded"
    trust_state: str = "unknown"
    manifest_app_version: str = ""
    current_app_version: str = ""
    manifest_build_id: str = ""
    current_build_id: str = ""
    manifest_git_commit: str = ""
    current_git_commit: str = ""
    manifest_hash: str = ""
    manifest_package_version: str = ""
    current_install_mode: str = ""
    current_package_version: str = ""
    manifest_root_path: str = ""
    current_root_path: str = ""
    mismatch_details: list[dict[str, str]] = field(default_factory=list)
    exact_mismatch_reason: str = ""
    cached_result: bool = False
    cache_valid: bool = True
    cache_invalidated_reason: str = ""
    matched_count: int = 0
    mismatched_count: int = 0
    missing_count: int = 0
    extra_count: int = 0
    skipped_count: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    file_results: list[dict[str, Any]] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    ignored_manifests: list[dict[str, str]] = field(default_factory=list)
    manifest_created_at: str = ""
    verification_result_id: str = ""
    verified_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        if not self.verification_result_id:
            self.verification_result_id = self.result_id
        if not self.verified_at:
            self.verified_at = self.checked_at
        return asdict(self)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mode(path: Path) -> str:
    return oct(stat.S_IMODE(path.lstat().st_mode))


def _owner_group(path: Path) -> tuple[str, str]:
    st = path.lstat()
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        owner = str(st.st_uid)
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        group = str(st.st_gid)
    return owner, group


def _entry_result(entry: IntegrityFileEntry, status: str, **extra: Any) -> dict[str, Any]:
    payload = asdict(entry)
    payload["verification_status"] = status
    payload["last_verified_at"] = utc_now_iso()
    payload.update(extra)
    return payload


def _git(args: list[str], root: Path) -> str:
    try:
        result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, timeout=5, check=False)
    except Exception:
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _status(result: IntegrityVerificationResult, *, metadata_mismatch: bool = False) -> str:
    if result.errors and "manifest" in " ".join(result.errors).lower():
        return "failed"
    if result.mismatched_count or result.missing_count or any("unexpected executable" in warning.lower() for warning in result.warnings):
        return "modified"
    if result.overall_status == "incompatible_manifest":
        return "incompatible_manifest"
    if metadata_mismatch:
        return "stale"
    if result.errors or result.skipped_count:
        return "partial"
    if result.warnings:
        return "verified_with_warnings"
    return "verified"


def _health_impact(overall_status: str) -> str:
    return {
        "verified": "healthy",
        "verified_with_warnings": "healthy",
        "unknown": "degraded",
        "draft": "degraded",
        "stale": "degraded",
        "incompatible_manifest": "degraded",
        "partial": "degraded",
        "failed": "degraded",
        "modified": "broken",
    }.get(overall_status, "degraded")


def _add_mismatch(result: IntegrityVerificationResult, field: str, manifest_value: object, current_value: object, message: str) -> None:
    detail = {
        "field": field,
        "manifest": "" if manifest_value is None else str(manifest_value),
        "current": "" if current_value is None else str(current_value),
        "message": message,
    }
    result.mismatch_details.append(detail)
    result.warnings.append(message)


def _compatible_source_type(manifest_type: str, active_type: str) -> bool:
    return canonical_source_type(manifest_type) == canonical_source_type(active_type)


@dataclass(frozen=True)
class ManifestSelection:
    manifest_path: Path
    expected_source_type: str
    root: Path
    install_mode: str
    ignored_manifests: list[dict[str, str]] = field(default_factory=list)


def _candidate_manifest_paths(root: Path, install_mode: str) -> list[tuple[str, Path]]:
    home_runtime = Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "runtime" / "integrity_manifest.json"
    system_runtime = Path("/Library/Application Support/MacAuditAgent/runtime/integrity_manifest.json")
    package_manifest = root / "package_integrity_manifest.json"
    source_manifest = root / "msaa_integrity_manifest.json"
    bundled_manifest = root / "integrity_manifest.json"
    by_mode = {
        "source_tree": [("source_tree", source_manifest)],
        "pip_package": [("pip_package", package_manifest), ("pip_package", root / "integrity_manifest.json")],
        "pyinstaller_app": [("pyinstaller_app", bundled_manifest)],
        "system_daemon_runtime": [("system_daemon_runtime", system_runtime)],
        "user_notifier_runtime": [("user_notifier_runtime", home_runtime)],
    }
    return by_mode.get(install_mode, [(install_mode, bundled_manifest)])


def select_integrity_manifest(root: Path | None = None, *, install_mode: str | None = None) -> ManifestSelection:
    base = Path(root or Path(__file__).resolve().parents[2]).expanduser().resolve(strict=False)
    identity = detect_build_identity(base, install_mode=install_mode) if install_mode else detect_build_identity(base)
    active_mode = canonical_source_type(identity.install_mode)
    candidates = _candidate_manifest_paths(base, active_mode)
    selected_type, selected_path = candidates[0]
    ignored: list[dict[str, str]] = []
    known_paths = {
        "source_tree": base / "msaa_integrity_manifest.json",
        "pip_package": base / "package_integrity_manifest.json",
        "pyinstaller_app": base / "integrity_manifest.json",
        "system_daemon_runtime": Path("/Library/Application Support/MacAuditAgent/runtime/integrity_manifest.json"),
        "user_notifier_runtime": Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "runtime" / "integrity_manifest.json",
    }
    for candidate_type, candidate_path in candidates:
        if candidate_path.exists():
            selected_type, selected_path = candidate_type, candidate_path
            break
    for candidate_type, candidate_path in known_paths.items():
        if candidate_path == selected_path or not candidate_path.exists():
            continue
        reason = "source_type does not match active install mode"
        if canonical_source_type(candidate_type) == active_mode:
            reason = "lower-priority duplicate manifest"
        ignored.append({"path": str(candidate_path), "source_type": candidate_type, "reason": reason})
    return ManifestSelection(
        manifest_path=selected_path,
        expected_source_type=selected_type,
        root=base,
        install_mode=active_mode,
        ignored_manifests=ignored,
    )


def verify_current_install_integrity(
    root: Path | None = None,
    *,
    install_mode: str | None = None,
    bypass_cache: bool = False,
) -> IntegrityVerificationResult:
    selection = select_integrity_manifest(root, install_mode=install_mode)
    result = verify_integrity_manifest(
        selection.manifest_path,
        root=selection.root,
        expected_source_type=selection.expected_source_type,
        bypass_cache=bypass_cache,
    )
    result.current_install_mode = selection.install_mode or result.current_install_mode
    result.ignored_manifests = selection.ignored_manifests
    if selection.ignored_manifests:
        result.warnings.append(
            "Ignored incompatible manifests: "
            + "; ".join(f"{item['path']} ({item['reason']})" for item in selection.ignored_manifests)
        )
    return result


def verify_integrity_manifest(
    manifest_path: Path,
    *,
    root: Path | None = None,
    allow_extra_files: bool = True,
    expected_source_type: str | None = None,
    bypass_cache: bool = False,
) -> IntegrityVerificationResult:
    checked_at = utc_now_iso()
    manifest_file = Path(manifest_path).expanduser()
    if not manifest_file.exists():
        result_id = f"msaa-verify-{uuid.uuid4().hex}"
        return IntegrityVerificationResult(
            result_id=result_id,
            checked_at=checked_at,
            manifest_path=str(manifest_file),
            source_type="unknown",
            overall_status="unknown",
            health_impact="degraded",
            cached_result=False,
            cache_valid=False,
            cache_invalidated_reason="bypassed" if bypass_cache else "manifest_missing",
            verification_result_id=result_id,
            verified_at=checked_at,
            errors=["No trusted integrity manifest exists. Create one only after installing from a trusted source."],
            recommended_actions=["Install or build MSAA from a trusted source, then explicitly create a trusted manifest."],
        )
    try:
        manifest = load_integrity_manifest(manifest_file)
    except Exception as exc:
        result_id = f"msaa-verify-{uuid.uuid4().hex}"
        return IntegrityVerificationResult(
            result_id=result_id,
            checked_at=checked_at,
            manifest_path=str(manifest_file),
            source_type="unknown",
            overall_status="failed",
            health_impact="degraded",
            cached_result=False,
            cache_valid=False,
            cache_invalidated_reason="bypassed" if bypass_cache else "manifest_unreadable",
            verification_result_id=result_id,
            verified_at=checked_at,
            errors=[f"Integrity manifest is unreadable or corrupt: {exc}"],
            recommended_actions=["Reinstall from a trusted source or restore a known-good manifest backup."],
        )
    base = Path(root or manifest.root_path or manifest_file.parent).expanduser().resolve(strict=False)
    active_type = canonical_source_type(expected_source_type or manifest.source_type)
    identity = detect_build_identity(base, install_mode=active_type if active_type in {"source_tree", "pip_package", "pyinstaller_app", "system_daemon_runtime", "user_notifier_runtime"} else None)  # type: ignore[arg-type]
    result_id = f"msaa-verify-{uuid.uuid4().hex}"
    result = IntegrityVerificationResult(
        result_id=result_id,
        checked_at=checked_at,
        manifest_path=str(manifest_file),
        source_type=manifest.source_type,
        overall_status="unknown",
        health_impact="degraded",
        trust_state=manifest.trust_state,
        manifest_app_version=manifest.app_version,
        current_app_version=identity.app_version,
        manifest_build_id=manifest.build_id,
        current_build_id=identity.build_id,
        manifest_git_commit=manifest.git_commit,
        current_git_commit=identity.git_commit,
        manifest_hash=manifest.manifest_hash,
        current_install_mode=identity.install_mode,
        current_package_version=identity.package_version,
        manifest_root_path=manifest.root_path,
        current_root_path=str(base),
        cached_result=False,
        cache_valid=True,
        cache_invalidated_reason="bypassed" if bypass_cache else "",
        manifest_created_at=manifest.created_at,
        verification_result_id=result_id,
        verified_at=checked_at,
    )
    if manifest.trust_state != "trusted":
        status = manifest.trust_state if manifest.trust_state in {"draft", "expired", "revoked", "unknown"} else "unknown"
        result.overall_status = "stale" if status == "expired" else status
        result.health_impact = _health_impact(result.overall_status)
        result.warnings.append(
            "Integrity manifest is not trusted. Draft, expired, revoked, or unknown manifests cannot verify application integrity."
        )
        result.recommended_actions.append(
            "Create a trusted manifest only after verifying this MSAA installation came from a trusted source."
        )
        return result
    if expected_source_type and not _compatible_source_type(manifest.source_type, active_type):
        result.overall_status = "incompatible_manifest"
        result.health_impact = _health_impact(result.overall_status)
        _add_mismatch(
            result,
            "source_type",
            manifest.source_type,
            active_type,
            f"Manifest source_type {manifest.source_type} does not match current mode {active_type}.",
        )
        result.exact_mismatch_reason = result.mismatch_details[0]["message"]
        result.recommended_actions.append("Select or create a trusted manifest for the current install mode.")
        return result
    metadata_mismatch = False
    if manifest.app_version and manifest.app_version != identity.app_version:
        metadata_mismatch = True
        _add_mismatch(
            result,
            "app_version",
            manifest.app_version,
            identity.app_version,
            f"Manifest version {manifest.app_version} differs from current app version {identity.app_version}.",
        )
    if manifest.build_id and result.current_build_id and manifest.build_id != result.current_build_id:
        metadata_mismatch = True
        _add_mismatch(
            result,
            "build_id",
            manifest.build_id,
            result.current_build_id,
            f"Manifest build_id {manifest.build_id} differs from current build_id {result.current_build_id}.",
        )
    expected = {entry.relative_path: entry for entry in manifest.file_entries}
    observed_rel_paths: set[str] = set()
    if manifest.source_type == "source_tree":
        current_commit = identity.git_commit or _git(["rev-parse", "HEAD"], base)
        result.current_git_commit = current_commit
        dirty_status = _git(["status", "--porcelain"], base)
        if manifest.git_commit and current_commit and current_commit != manifest.git_commit:
            metadata_mismatch = True
            _add_mismatch(
                result,
                "git_commit",
                manifest.git_commit,
                current_commit,
                f"Manifest git_commit {manifest.git_commit} differs from current git_commit {current_commit}.",
            )
        if manifest.git_commit and not current_commit:
            result.warnings.append("Manifest contains a git commit but current git commit could not be read.")
        if dirty_status:
            result.warnings.append("Source tree has uncommitted or untracked changes; file hashes are still verified against the trusted manifest.")
    for rel_path, entry in expected.items():
        path = base / rel_path
        if not path.exists() and not path.is_symlink():
            result.missing_count += 1 if entry.required else 0
            result.file_results.append(_entry_result(entry, "missing", absolute_path=str(path)))
            if entry.required:
                _add_mismatch(
                    result,
                    "required_file_missing",
                    entry.relative_path,
                    "",
                    f"Required file missing: {entry.relative_path}.",
                )
            else:
                result.warnings.append(f"Optional manifest file missing: {entry.relative_path}.")
            continue
        observed_rel_paths.add(rel_path)
        try:
            st = path.lstat()
            mode = stat.S_IMODE(st.st_mode)
            owner, group = _owner_group(path)
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(path)
                resolved_target = (path.parent / target).resolve(strict=False)
                outside_root = False
                try:
                    resolved_target.relative_to(base)
                except ValueError:
                    outside_root = True
                if outside_root:
                    result.warnings.append(f"Symlink points outside approved root: {entry.relative_path} -> {target}")
                if entry.file_type != "symlink" or target != entry.symlink_target or outside_root:
                    result.mismatched_count += 1
                    result.file_results.append(_entry_result(entry, "mismatch", absolute_path=str(path), observed_symlink_target=target))
                else:
                    result.matched_count += 1
                    result.file_results.append(_entry_result(entry, "match", absolute_path=str(path)))
                continue
            sha256 = calculate_sha256(path)
            mismatch_reasons = []
            if entry.sha256 and sha256 != entry.sha256:
                mismatch_reasons.append("sha256")
            if entry.size_bytes and int(st.st_size) != int(entry.size_bytes):
                mismatch_reasons.append("size")
            if entry.mode and oct(mode) != entry.mode:
                mismatch_reasons.append("mode")
            if entry.owner and owner != entry.owner:
                mismatch_reasons.append("owner")
            if entry.group and group != entry.group:
                mismatch_reasons.append("group")
            if mismatch_reasons:
                result.mismatched_count += 1
                result.file_results.append(_entry_result(entry, "mismatch", absolute_path=str(path), observed_sha256=sha256, mismatch_reasons=mismatch_reasons))
                if entry.required:
                    reason_text = "hash" if "sha256" in mismatch_reasons else ", ".join(mismatch_reasons)
                    _add_mismatch(
                        result,
                        "required_file_mismatch",
                        entry.relative_path,
                        entry.relative_path,
                        f"Required file {reason_text} mismatch detected: {entry.relative_path}.",
                    )
            else:
                result.matched_count += 1
                result.file_results.append(_entry_result(entry, "match", absolute_path=str(path), observed_sha256=sha256))
        except Exception as exc:
            result.skipped_count += 1
            result.errors.append(f"Could not verify {rel_path}: {exc}")
            result.file_results.append(_entry_result(entry, "unknown", absolute_path=str(path), error=str(exc)))
    for path in iter_integrity_files(base, manifest.excluded_patterns):
        rel = path.relative_to(base).as_posix()
        if rel in expected or is_excluded(rel, manifest.excluded_patterns):
            continue
        try:
            executable = bool(stat.S_IMODE(path.lstat().st_mode) & 0o111)
        except OSError:
            executable = False
        if executable:
            result.extra_count += 1
            result.warnings.append(f"Unexpected executable file: {rel}")
            result.file_results.append({"relative_path": rel, "absolute_path": str(path), "verification_status": "extra", "executable": True})
        elif not allow_extra_files:
            result.extra_count += 1
            result.file_results.append({"relative_path": rel, "absolute_path": str(path), "verification_status": "extra", "executable": False})
    if result.mismatched_count or result.missing_count:
        result.recommended_actions.append("Preserve evidence and reinstall MSAA from a trusted source if the change was not approved.")
    if result.extra_count:
        result.recommended_actions.append("Review unexpected executable files before trusting this installation.")
    if metadata_mismatch and not (result.mismatched_count or result.missing_count):
        result.recommended_actions.append("Manifest appears to belong to a previous build. If this app was updated from a trusted source, create a new trusted manifest after verifying the update.")
    if not result.recommended_actions:
        result.recommended_actions.append("No integrity drift detected against the trusted manifest.")
    result.overall_status = _status(result, metadata_mismatch=metadata_mismatch)
    result.health_impact = _health_impact(result.overall_status)
    if result.mismatch_details:
        result.exact_mismatch_reason = result.mismatch_details[0]["message"]
    if result.overall_status == "stale":
        result.warnings.append("Trusted manifest was generated for a different MSAA build. This does not by itself prove tampering.")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify MSAA files against a trusted integrity manifest.")
    parser.add_argument("--manifest", default="msaa_integrity_manifest.json")
    parser.add_argument("--root", default="")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--verify-source", action="store_true")
    parser.add_argument("--verify-system-runtime", action="store_true")
    parser.add_argument("--verify-user-notifier", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.verify_system_runtime:
        from mac_audit_agent.integrity.daemon_integrity import verify_system_runtime_integrity

        result = verify_system_runtime_integrity()
    elif args.verify_user_notifier:
        from mac_audit_agent.integrity.ui_integrity import verify_user_notifier_integrity

        result = verify_user_notifier_integrity()
    elif args.verify_source or args.verify:
        result = verify_integrity_manifest(Path(args.manifest), root=Path(args.root) if args.root else None, expected_source_type="source_tree", bypass_cache=True)
    else:
        result = verify_integrity_manifest(Path(args.manifest), root=Path(args.root) if args.root else None, bypass_cache=True)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.overall_status == "verified" else 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
