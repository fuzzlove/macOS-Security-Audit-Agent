"""SHA-256 integrity verification for frozen macOS application bundles."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BUNDLE_MANIFEST_RELATIVE_PATH = Path("Resources") / "msaa_bundle_integrity.json"
BUNDLE_MANIFEST_SCHEMA_VERSION = 1
MAX_BUNDLE_FILES = 20_000


@dataclass(frozen=True)
class BundleIntegrityResult:
    status: str
    result_code: str
    manifest_path: str
    manifest_sha256: str
    checked_files: int
    expected_files: int
    modified_files: tuple[str, ...]
    missing_files: tuple[str, ...]
    unexpected_files: tuple[str, ...]
    code_signature_valid: bool | None
    code_signature_detail: str
    reason: str
    build_id: str = ""
    generated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _excluded(relative_path: str) -> bool:
    normalized = relative_path.replace("\\", "/").lstrip("/")
    # The app's primary Mach-O embeds the outer code signature. Hashing it in a
    # manifest that is itself sealed by that signature would create a circular
    # dependency. macOS codesign verifies MacOS/; the SHA-256 inventory covers
    # the remaining immutable resources and nested native libraries.
    return (
        normalized == BUNDLE_MANIFEST_RELATIVE_PATH.as_posix()
        or normalized.startswith("_CodeSignature/")
        or normalized.startswith("MacOS/")
    )


def _bundle_files(contents_root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for path in contents_root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(contents_root).as_posix()
        if not _excluded(relative):
            files[relative] = path
        if len(files) > MAX_BUNDLE_FILES:
            raise ValueError(f"application bundle exceeds the {MAX_BUNDLE_FILES:,}-file integrity limit")
    return files


def build_bundle_integrity_manifest(contents_root: Path, *, build_id: str = "") -> dict[str, Any]:
    """Build a deterministic inventory after PyInstaller assembly and before final signing."""

    root = Path(contents_root).resolve(strict=True)
    if root.name != "Contents" or not (root / "MacOS").is_dir():
        raise ValueError("bundle integrity root must be a macOS application Contents directory")
    entries = []
    for relative, path in sorted(_bundle_files(root).items()):
        info = path.stat()
        entries.append({"path": relative, "size": int(info.st_size), "sha256": _sha256(path)})
    payload: dict[str, Any] = {
        "schema_version": BUNDLE_MANIFEST_SCHEMA_VERSION,
        "hash_algorithm": "sha256",
        "scope": "macos_app_contents",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "build_id": str(build_id),
        "file_count": len(entries),
        "files": entries,
        "exclusions": ["_CodeSignature/", "MacOS/ (verified by macOS code signing)", BUNDLE_MANIFEST_RELATIVE_PATH.as_posix()],
        "trust_qualification": (
            "SHA-256 verifies bundle consistency. Publisher authenticity additionally requires a valid "
            "Developer ID signature and Apple notarization; an ad-hoc signature does not establish publisher identity."
        ),
    }
    payload["inventory_sha256"] = hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    return payload


def write_bundle_integrity_manifest(contents_root: Path, *, build_id: str = "") -> Path:
    root = Path(contents_root).resolve(strict=True)
    destination = root / BUNDLE_MANIFEST_RELATIVE_PATH
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = build_bundle_integrity_manifest(root, build_id=build_id)
    temporary = destination.with_suffix(".tmp")
    temporary.write_bytes(_canonical_bytes(payload) + b"\n")
    os.replace(temporary, destination)
    return destination


def _verify_code_signature(contents_root: Path) -> tuple[bool | None, str]:
    app = contents_root.parent
    if app.suffix != ".app" or not Path("/usr/bin/codesign").is_file():
        return None, "macOS code-signature verification unavailable"
    try:
        result = subprocess.run(
            ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"code-signature verification error: {type(exc).__name__}"
    detail = (result.stderr or result.stdout or "signature valid").strip()
    return result.returncode == 0, detail[:1000]


def verify_bundle_integrity(contents_root: Path, *, verify_code_signature: bool = True) -> BundleIntegrityResult:
    root = Path(contents_root).resolve(strict=False)
    manifest_path = root / BUNDLE_MANIFEST_RELATIVE_PATH
    if not manifest_path.is_file():
        return BundleIntegrityResult(
            "failed", "BUNDLE_MANIFEST_MISSING", str(manifest_path), "", 0, 0, (), (), (), None, "not checked",
            "The packaged application SHA-256 manifest is missing.",
        )
    try:
        raw = manifest_path.read_bytes()
        manifest = json.loads(raw)
        if manifest.get("schema_version") != BUNDLE_MANIFEST_SCHEMA_VERSION or manifest.get("hash_algorithm") != "sha256":
            raise ValueError("unsupported bundle integrity manifest schema or hash algorithm")
        entries = manifest.get("files")
        if not isinstance(entries, list) or len(entries) > MAX_BUNDLE_FILES:
            raise ValueError("invalid bundle integrity file inventory")
        expected: dict[str, dict[str, Any]] = {}
        for entry in entries:
            relative = str(entry.get("path", "")).replace("\\", "/")
            if not relative or relative.startswith("/") or ".." in Path(relative).parts or _excluded(relative):
                raise ValueError("unsafe path in bundle integrity manifest")
            expected[relative] = entry
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return BundleIntegrityResult(
            "failed", "BUNDLE_MANIFEST_INVALID", str(manifest_path), "", 0, 0, (), (), (), None, "not checked",
            f"The packaged application SHA-256 manifest is invalid: {type(exc).__name__}.",
        )

    observed = _bundle_files(root)
    modified: list[str] = []
    missing: list[str] = []
    checked = 0
    for relative, entry in sorted(expected.items()):
        path = observed.get(relative)
        if path is None:
            missing.append(relative)
            continue
        try:
            size_matches = path.stat().st_size == int(entry.get("size", -1))
            hash_matches = size_matches and _sha256(path) == str(entry.get("sha256", ""))
        except (OSError, ValueError, TypeError):
            hash_matches = False
        if hash_matches:
            checked += 1
        else:
            modified.append(relative)
    unexpected = sorted(set(observed) - set(expected))
    signature_valid, signature_detail = _verify_code_signature(root) if verify_code_signature else (None, "not checked")
    manifest_sha256 = hashlib.sha256(raw).hexdigest()
    if modified or missing or unexpected:
        result_code = "HASH_MISMATCH" if modified else "FILE_MISSING" if missing else "UNEXPECTED_FILE"
        return BundleIntegrityResult(
            "failed", result_code, str(manifest_path), manifest_sha256, checked, len(expected), tuple(modified),
            tuple(missing), tuple(unexpected), signature_valid, signature_detail,
            "Packaged application files differ from the build-time SHA-256 inventory.",
            str(manifest.get("build_id", "")), str(manifest.get("generated_at", "")),
        )
    if signature_valid is False:
        return BundleIntegrityResult(
            "failed", "CODE_SIGNATURE_INVALID", str(manifest_path), manifest_sha256, checked, len(expected), (), (), (),
            False, signature_detail, "SHA-256 files match, but the macOS application code signature is invalid.",
            str(manifest.get("build_id", "")), str(manifest.get("generated_at", "")),
        )
    return BundleIntegrityResult(
        "verified", "VALID", str(manifest_path), manifest_sha256, checked, len(expected), (), (), (), signature_valid,
        signature_detail, "All packaged files match the build-time SHA-256 inventory and the macOS code signature is valid."
        if signature_valid else "All packaged files match the build-time SHA-256 inventory; code-signature verification was unavailable.",
        str(manifest.get("build_id", "")), str(manifest.get("generated_at", "")),
    )


def current_bundle_contents_root() -> Path:
    executable = Path(os.path.realpath(os.fspath(Path(sys.executable)))).resolve(strict=False)
    if ".app" in executable.as_posix():
        return executable.parent.parent
    raise ValueError("current executable is not inside a macOS application bundle")


__all__ = [
    "BUNDLE_MANIFEST_RELATIVE_PATH", "BundleIntegrityResult", "build_bundle_integrity_manifest",
    "current_bundle_contents_root", "verify_bundle_integrity", "write_bundle_integrity_manifest",
]
