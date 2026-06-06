from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol


BASELINE_STATE_KEY = "source_integrity_manifest_v1"
SCHEMA = "mac-audit-agent-source-integrity-v1"
HASH_ALGORITHMS = "sha256+blake2b256+sha3_512_merkle_root"
EXCLUDED_DIRS = {"__pycache__", ".git", ".mypy_cache", ".pytest_cache", "build", "dist", "evidence", "tests"}


class IntegrityStateStore(Protocol):
    def get_background_monitor_state(self, key: str, default: str = "") -> str: ...

    def set_background_monitor_state(self, key: str, value: str) -> None: ...


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def tracked_python_files(root: Path | None = None) -> list[Path]:
    base = (root or project_root()).resolve()
    files: list[Path] = []
    for path in base.rglob("*.py"):
        parts = set(path.relative_to(base).parts)
        if parts.intersection(EXCLUDED_DIRS):
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(base).as_posix())


def _file_hashes(path: Path) -> dict[str, Any]:
    sha256 = hashlib.sha256()
    blake2 = hashlib.blake2b(digest_size=32)
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            size += len(chunk)
            sha256.update(chunk)
            blake2.update(chunk)
    return {
        "size": size,
        "sha256": sha256.hexdigest(),
        "blake2b256": blake2.hexdigest(),
    }


def build_source_integrity_manifest(root: Path | None = None) -> dict[str, Any]:
    base = (root or project_root()).resolve()
    files: dict[str, dict[str, Any]] = {}
    for path in tracked_python_files(base):
        try:
            files[path.relative_to(base).as_posix()] = _file_hashes(path)
        except OSError:
            continue

    root_hash = hashlib.sha3_512()
    for rel_path, details in files.items():
        root_hash.update(rel_path.encode("utf-8"))
        root_hash.update(b"\0")
        root_hash.update(str(details["size"]).encode("ascii"))
        root_hash.update(b"\0")
        root_hash.update(str(details["sha256"]).encode("ascii"))
        root_hash.update(b"\0")
        root_hash.update(str(details["blake2b256"]).encode("ascii"))
        root_hash.update(b"\n")

    manifest = {
        "schema": SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "root": str(base),
        "hash_algorithms": HASH_ALGORITHMS,
        "file_count": len(files),
        "files": files,
        "merkle_root_sha3_512": root_hash.hexdigest(),
    }
    manifest["manifest_digest_sha3_512"] = _manifest_digest(manifest)
    return manifest


def _manifest_digest(manifest: dict[str, Any]) -> str:
    payload = {key: value for key, value in manifest.items() if key != "manifest_digest_sha3_512"}
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha3_512(serialized).hexdigest()


def _load_baseline(store: IntegrityStateStore) -> dict[str, Any]:
    raw = store.get_background_monitor_state(BASELINE_STATE_KEY, "")
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def record_source_integrity_baseline(store: IntegrityStateStore, *, root: Path | None = None) -> dict[str, Any]:
    manifest = build_source_integrity_manifest(root)
    store.set_background_monitor_state(BASELINE_STATE_KEY, json.dumps(manifest, sort_keys=True))
    return manifest


def verify_source_integrity(
    store: IntegrityStateStore,
    *,
    root: Path | None = None,
    initialize: bool = True,
) -> dict[str, Any]:
    baseline = _load_baseline(store)
    baseline_valid = bool(
        baseline
        and baseline.get("schema") == SCHEMA
        and baseline.get("manifest_digest_sha3_512") == _manifest_digest(baseline)
    )
    if not baseline_valid:
        if initialize:
            baseline = record_source_integrity_baseline(store, root=root)
            return {
                "status": "baseline-created",
                "tamper_detected": False,
                "baseline_valid": True,
                "file_count": int(baseline.get("file_count", 0)),
                "changed_files": [],
                "missing_files": [],
                "added_files": [],
                "merkle_root_sha3_512": str(baseline.get("merkle_root_sha3_512", "")),
                "hash_algorithms": HASH_ALGORITHMS,
                "last_checked": datetime.now(timezone.utc).isoformat(),
            }
        return {
            "status": "baseline-missing",
            "tamper_detected": True,
            "baseline_valid": False,
            "file_count": 0,
            "changed_files": [],
            "missing_files": [],
            "added_files": [],
            "merkle_root_sha3_512": "",
            "hash_algorithms": HASH_ALGORITHMS,
            "last_checked": datetime.now(timezone.utc).isoformat(),
        }

    current = build_source_integrity_manifest(root)
    expected_files = baseline.get("files", {}) if isinstance(baseline.get("files", {}), dict) else {}
    current_files = current.get("files", {}) if isinstance(current.get("files", {}), dict) else {}
    changed = sorted(
        rel_path
        for rel_path, expected in expected_files.items()
        if rel_path in current_files
        and (
            current_files[rel_path].get("sha256") != expected.get("sha256")
            or current_files[rel_path].get("blake2b256") != expected.get("blake2b256")
        )
    )
    missing = sorted(rel_path for rel_path in expected_files if rel_path not in current_files)
    added = sorted(rel_path for rel_path in current_files if rel_path not in expected_files)
    root_changed = current.get("merkle_root_sha3_512") != baseline.get("merkle_root_sha3_512")
    tamper_detected = bool(changed or missing or added or root_changed)
    return {
        "status": "tamper-detected" if tamper_detected else "verified",
        "tamper_detected": tamper_detected,
        "baseline_valid": True,
        "file_count": int(current.get("file_count", 0)),
        "baseline_file_count": int(baseline.get("file_count", 0) or 0),
        "changed_files": changed,
        "missing_files": missing,
        "added_files": added,
        "merkle_root_sha3_512": str(current.get("merkle_root_sha3_512", "")),
        "baseline_merkle_root_sha3_512": str(baseline.get("merkle_root_sha3_512", "")),
        "hash_algorithms": HASH_ALGORITHMS,
        "last_checked": datetime.now(timezone.utc).isoformat(),
    }
