from __future__ import annotations

import argparse
import getpass
import json
import platform
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.exclusions import classify_path_category, default_excluded_patterns
from mac_audit_agent.integrity.hasher import is_excluded
from mac_audit_agent.integrity.manifest_paths import integrity_manifest_paths
from mac_audit_agent.integrity.signing import (
    DEFAULT_PUBLIC_KEY_PATH,
    SIGNATURE_ALGORITHM,
    calculate_file_sha256,
    calculate_manifest_hash,
    canonical_json_bytes,
    load_private_key,
    load_public_key,
    public_key_id,
    sign_manifest,
    verify_manifest_signature,
)
from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.runtime.force_mode import ForceArgumentError, ForceMode, log_force_action, parse_force_argument
from mac_audit_agent.version import APP_VERSION


DEFAULT_RELEASE_MANIFEST = integrity_manifest_paths(Path.cwd()).release_manifest
DEFAULT_RELEASE_SIGNATURE = integrity_manifest_paths(Path.cwd()).release_signature
DEFAULT_ARTIFACT_MANIFEST = Path("dist/MSAA_RELEASE_ARTIFACTS.json")
DEFAULT_ARTIFACT_SIGNATURE = Path("dist/MSAA_RELEASE_ARTIFACTS.sig")


def git_output(args: list[str], root: Path) -> str:
    try:
        result = subprocess.run(["git", *args], cwd=root, text=True, capture_output=True, check=False, timeout=20)
    except Exception:
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def git_dirty_files(root: Path) -> list[str]:
    status = git_output(["status", "--porcelain"], root)
    return [line for line in status.splitlines() if line.strip()]


def git_tracked_files(root: Path) -> list[Path]:
    output = "\n".join(
        part
        for part in [
            git_output(["ls-files"], root),
            git_output(["ls-files", "--others", "--exclude-standard"], root),
        ]
        if part
    )
    files: list[Path] = []
    seen: set[Path] = set()
    for line in output.splitlines():
        path = (root / line).resolve(strict=False)
        if path in seen:
            continue
        seen.add(path)
        if path.exists() and path.is_file():
            files.append(path)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def build_release_manifest(root: Path, *, version: str, public_key_path: Path, mode: str = "release", evidence_id: str = "") -> dict[str, Any]:
    root = Path(root).resolve(strict=False)
    exclusions = default_excluded_patterns()
    files = []
    for path in git_tracked_files(root) or sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel in {
            DEFAULT_RELEASE_MANIFEST.as_posix(),
            DEFAULT_RELEASE_SIGNATURE.as_posix(),
            DEFAULT_ARTIFACT_MANIFEST.as_posix(),
            DEFAULT_ARTIFACT_SIGNATURE.as_posix(),
        }:
            continue
        if is_excluded(rel, exclusions):
            continue
        st = path.stat()
        files.append(
            {
                "relative_path": rel,
                "sha256": calculate_file_sha256(path),
                "size": int(st.st_size),
                "mode": oct(st.st_mode & 0o777),
                "category": classify_path_category(rel),
                "required": True,
            }
        )
    public_key = load_public_key(public_key_path)
    payload = {
        "manifest_schema_version": "1",
        "manifest_id": f"msaa-release-{uuid.uuid4().hex}",
        "app_name": "macOS Security Audit Agent",
        "package_name": "mac-audit-agent",
        "app_version": version,
        "build_id": git_output(["rev-parse", "--short", "HEAD"], root),
        "git_commit": git_output(["rev-parse", "HEAD"], root),
        "git_dirty": bool(git_dirty_files(root)),
        "created_at": utc_now_iso(),
        "baseline_mode": mode,
        "source_root": str(root),
        "package_root": "mac_audit_agent",
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "files": sorted(files, key=lambda item: item["relative_path"]),
        "exclusions": exclusions,
        "manifest_hash": "",
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "public_key_id": public_key_id(public_key),
        "signed_by": getpass.getuser(),
        "verification_evidence_id": evidence_id,
        "notes": "Signed release manifest. Runtime mutable files and manifest/signature files are excluded.",
    }
    payload["manifest_hash"] = calculate_manifest_hash(payload)
    return payload


def write_json(payload: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(payload) + b"\n")
    return path


def create_artifact_manifest(dist: Path, *, version: str, public_key_path: Path, root: Path, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    dist = Path(dist)
    public_key = load_public_key(public_key_path)
    artifacts = []
    for path in sorted(dist.glob("*")):
        if not path.is_file() or path.name in {DEFAULT_ARTIFACT_MANIFEST.name, DEFAULT_ARTIFACT_SIGNATURE.name}:
            continue
        suffix = path.suffix.lower()
        artifact_type = "wheel" if suffix == ".whl" else "sdist" if suffix in {".gz", ".zip"} and "tar" in path.name else "macos_app" if suffix == ".app" else suffix.lstrip(".") or "local"
        artifacts.append(
            {
                "filename": path.name,
                "path": str(path),
                "sha256": calculate_file_sha256(path),
                "size": int(path.stat().st_size),
                "artifact_type": artifact_type,
                "upload_target": "pypi" if artifact_type in {"wheel", "sdist"} else "local",
                "verified": True,
            }
        )
    payload = {
        "manifest_schema_version": "1",
        "app_version": version,
        "git_commit": git_output(["rev-parse", "HEAD"], root),
        "created_at": utc_now_iso(),
        "artifacts": artifacts,
        "build_command": "python3 -m build",
        "twine_check_result": (evidence or {}).get("twine_check_result", "not_recorded"),
        "clean_install_result": (evidence or {}).get("clean_install_result", "not_recorded"),
        "pytest_result": (evidence or {}).get("pytest_result", "not_recorded"),
        "compileall_result": (evidence or {}).get("compileall_result", "not_recorded"),
        "public_key_id": public_key_id(public_key),
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "manifest_hash": "",
    }
    payload["manifest_hash"] = calculate_manifest_hash(payload)
    return payload


def ensure_can_sign(root: Path, *, version: str, dev_allow_incomplete: bool) -> None:
    if version != APP_VERSION and not dev_allow_incomplete:
        raise SystemExit(f"version mismatch: requested {version}, package metadata {APP_VERSION}")
    dirty = git_dirty_files(root)
    if dirty and not dev_allow_incomplete:
        raise SystemExit("refusing to sign dirty source tree without --dev-allow-incomplete")


def command_manifest(args: argparse.Namespace) -> Path:
    root = args.root.resolve(strict=False)
    ensure_can_sign(root, version=args.version, dev_allow_incomplete=args.dev_allow_incomplete)
    payload = build_release_manifest(root, version=args.version, public_key_path=args.public_key, mode=args.mode, evidence_id=args.evidence_id)
    return write_json(payload, args.manifest)


def command_sign(args: argparse.Namespace) -> Path:
    private_key = load_private_key(env_var=args.key_env)
    return sign_manifest(args.manifest, private_key=private_key, signature_path=args.signature)


def command_verify(args: argparse.Namespace) -> bool:
    ok = verify_manifest_signature(args.manifest, args.signature, args.public_key)
    print(json.dumps({"manifest": str(args.manifest), "signature": str(args.signature), "signature_valid": ok}, indent=2, sort_keys=True))
    return ok


def command_sign_artifacts(args: argparse.Namespace) -> Path:
    root = args.root.resolve(strict=False)
    payload = create_artifact_manifest(args.dist, version=args.version, public_key_path=args.public_key, root=root)
    write_json(payload, args.artifact_manifest)
    private_key = load_private_key(env_var=args.key_env)
    sign_manifest(args.artifact_manifest, private_key=private_key, signature_path=args.artifact_signature)
    return args.artifact_manifest


def write_release_evidence(args: argparse.Namespace, *, status: str, extra: dict[str, Any] | None = None) -> Path:
    path = Path("docs/releases") / f"release_evidence_{args.version}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": args.version,
        "git_commit": git_output(["rev-parse", "HEAD"], args.root.resolve(strict=False)),
        "created_at": utc_now_iso(),
        "release_manifest_path": str(args.manifest),
        "release_manifest_signature_path": str(args.signature),
        "artifact_manifest_path": str(args.artifact_manifest),
        "artifact_manifest_signature_path": str(args.artifact_signature),
        "compileall_result": "not_recorded",
        "pytest_result": "not_recorded",
        "pre_uat_result": "not_recorded",
        "build_result": "not_recorded",
        "twine_check_result": "not_recorded",
        "clean_install_result": "not_recorded",
        "artifact_hashes": [],
        "trust_state": "trusted_development_baseline" if status == "verified" and args.mode == "dev" else "trusted_signed_release" if status == "verified" else "verification_error",
        "public_key_id": public_key_id(load_public_key(args.public_key)),
        "status": status,
        **(extra or {}),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sign and verify MSAA release integrity manifests.")
    sub = parser.add_subparsers(dest="command")
    for name in ["prepare", "manifest", "sign", "verify", "sign-artifacts", "verify-artifacts", "all"]:
        p = sub.add_parser(name)
        p.add_argument("--version", default=APP_VERSION)
        p.add_argument("--mode", default="release")
        p.add_argument("--root", type=Path, default=Path.cwd())
        p.add_argument("--manifest", type=Path, default=None)
        p.add_argument("--signature", type=Path, default=None)
        p.add_argument("--dist", type=Path, default=Path("dist"))
        p.add_argument("--artifact-manifest", type=Path, default=DEFAULT_ARTIFACT_MANIFEST)
        p.add_argument("--artifact-signature", type=Path, default=DEFAULT_ARTIFACT_SIGNATURE)
        p.add_argument("--key-env", default="MSAA_RELEASE_SIGNING_KEY")
        p.add_argument("--public-key", type=Path, default=DEFAULT_PUBLIC_KEY_PATH)
        p.add_argument("--evidence-id", default="")
        p.add_argument("--dev-allow-incomplete", action="store_true")
        p.add_argument("--force", "-f", action="store_true", help="Retry manifest/signing workflow after normal validation. Does not bypass dirty-tree, signature, or integrity safeguards.")
    return parser


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    command = raw_argv[0] if raw_argv and not raw_argv[0].startswith("-") else "all"
    try:
        cleaned, force_mode = parse_force_argument(raw_argv, command=f"release_sign {command}", supported_scopes={"rebuild_manifest", "diagnostics"}, default_scope="rebuild_manifest", require_command=False)
    except ForceArgumentError as exc:
        print(str(exc), file=sys.stderr)
        log_force_action("release_sign", ForceMode(enabled=False, scope="unsupported"), result="rejected", error=str(exc))
        return 2
    args = build_parser().parse_args(cleaned)
    if not args.command:
        args.command = "all"
    paths = integrity_manifest_paths(args.root.resolve(strict=False))
    if args.manifest is None:
        args.manifest = paths.release_manifest
    if args.signature is None:
        args.signature = paths.release_signature
    if getattr(args, "force", False):
        force_mode.enabled = True
    if force_mode.enabled:
        log_force_action(f"release_sign {args.command}", force_mode, action_taken="retry_release_signing_after_validation", result="started")
        print("Force enabled: release signing will retry after normal validation. Integrity and signature safeguards remain enforced.", file=sys.stderr)
    if args.command == "prepare":
        ensure_can_sign(args.root.resolve(strict=False), version=args.version, dev_allow_incomplete=args.dev_allow_incomplete)
        print("Release signing preflight passed.")
        if force_mode.enabled:
            log_force_action("release_sign prepare", force_mode, action_taken="retry_release_signing_after_validation", result="prepared")
        return 0
    if args.command == "manifest":
        print(command_manifest(args))
        return 0
    if args.command == "sign":
        print(command_sign(args))
        return 0
    if args.command == "verify":
        return 0 if command_verify(args) else 1
    if args.command == "sign-artifacts":
        print(command_sign_artifacts(args))
        return 0
    if args.command == "verify-artifacts":
        ok = verify_manifest_signature(args.artifact_manifest, args.artifact_signature, args.public_key)
        print(json.dumps({"artifact_manifest": str(args.artifact_manifest), "signature_valid": ok}, indent=2, sort_keys=True))
        return 0 if ok else 1
    command_manifest(args)
    command_sign(args)
    manifest_ok = command_verify(args)
    artifact_path = None
    if args.dist.exists() and any(args.dist.glob("*")):
        artifact_path = str(command_sign_artifacts(args))
    evidence_path = write_release_evidence(args, status="verified" if manifest_ok else "failed", extra={"artifact_manifest_created": artifact_path})
    print(f"Release manifest signed and verified. Evidence: {evidence_path}")
    print("Next: build final dist, run sign-artifacts again if dist changes, then upload signed artifacts.")
    if force_mode.enabled:
        log_force_action(f"release_sign {args.command}", force_mode, action_taken="retry_release_signing_after_validation", result="verified" if manifest_ok else "failed")
    return 0 if manifest_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
