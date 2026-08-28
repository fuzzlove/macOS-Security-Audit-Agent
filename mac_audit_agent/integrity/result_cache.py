from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mac_audit_agent.integrity.dev_manifest import utc_now_iso
from mac_audit_agent.integrity.hash_scope import build_hash_scope_report
from mac_audit_agent.integrity.signing import calculate_file_sha256


SCHEMA_VERSION = "1"
DEFAULT_ACTIVE_DB_PATH = Path("/Library/Application Support/MacAuditAgent/mac_audit_agent.sqlite3")


@dataclass(slots=True)
class CurrentIntegrityStatus:
    schema_version: str = SCHEMA_VERSION
    generated_at: str = ""
    status: str = ""
    trust_state: str = ""
    policy: str = "dev"
    canonical_manifest_path: str = ""
    canonical_signature_path: str = ""
    developer_machine_id: str = ""
    public_key_fingerprint: str = ""
    manifest_sha256: str = ""
    signature_valid: bool | None = None
    files_match: bool = False
    source_modified_files: list[str] = field(default_factory=list)
    generated_modified_files: list[str] = field(default_factory=list)
    trust_metadata_files: list[str] = field(default_factory=list)
    legacy_ignored_files: list[str] = field(default_factory=list)
    deprecated_artifacts: list[str] = field(default_factory=list)
    pre_uat_compatible: bool = False
    integrity_unknown: bool = False
    evidence_path: str = ""
    supersedes_event_ids: list[str] = field(default_factory=list)
    failure_code: str = ""
    result_code: str = ""
    release_id: str = ""
    build_id: str = ""
    git_commit: str = ""
    signing_key_fingerprint: str = ""
    recommended_action: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def default_result_cache_path() -> Path:
    return Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "integrity" / "current_integrity_status.json"


def developer_diagnostic_cache_path(root: Path) -> Path:
    return Path(root).resolve(strict=False) / "reports" / "integrity" / "current_integrity_status.json"


def build_current_integrity_status(
    status: Any,
    *,
    root: Path,
    evidence_path: str = "",
    supersedes_event_ids: list[str] | None = None,
) -> CurrentIntegrityStatus:
    root = Path(root).resolve(strict=False)
    scope = build_hash_scope_report(root, policy=getattr(status, "policy_mode", "dev"))
    manifest_path = Path(getattr(status, "canonical_manifest_path", "") or getattr(status, "manifest_path", ""))
    manifest_sha256 = ""
    if manifest_path.is_file():
        manifest_sha256 = calculate_file_sha256(manifest_path)
    signer = (getattr(status, "signer_status", None) or [{}])[0]
    files_match = not bool(getattr(status, "modified_files", []) or getattr(status, "missing_files", []) or getattr(status, "extra_files", []))
    return CurrentIntegrityStatus(
        generated_at=utc_now_iso(),
        status=getattr(status, "status", ""),
        trust_state=getattr(status, "trust_state", ""),
        policy=getattr(status, "policy_mode", "dev"),
        canonical_manifest_path=str(manifest_path),
        canonical_signature_path=getattr(status, "signature_path", ""),
        developer_machine_id=str(signer.get("developer_machine_id", "")) if isinstance(signer, dict) else "",
        public_key_fingerprint=getattr(status, "signing_key_fingerprint", ""),
        manifest_sha256=manifest_sha256,
        signature_valid=getattr(status, "signature_valid", None),
        files_match=files_match,
        source_modified_files=list(getattr(status, "source_modified_files", []) or getattr(status, "modified_files", []) or []),
        generated_modified_files=list(getattr(status, "generated_modified_files", []) or []),
        trust_metadata_files=scope.trust_metadata_files,
        legacy_ignored_files=scope.legacy_ignored_files,
        deprecated_artifacts=scope.deprecated_artifacts,
        pre_uat_compatible=bool(getattr(status, "pre_uat_compatible", False)),
        integrity_unknown="unknown" in str(getattr(status, "trust_state", "")),
        evidence_path=evidence_path,
        supersedes_event_ids=supersedes_event_ids or [],
        failure_code=getattr(status, "failure_code", ""),
        result_code=getattr(status, "result_code", ""),
        release_id=getattr(status, "release_id", ""),
        build_id=getattr(status, "build_id", ""),
        git_commit=getattr(status, "git_commit", ""),
        signing_key_fingerprint=getattr(status, "signing_key_fingerprint", ""),
        recommended_action=getattr(status, "recommended_action", ""),
    )


def write_current_integrity_status(
    current: CurrentIntegrityStatus,
    *,
    cache_path: Path | None = None,
    root: Path | None = None,
    write_developer_copy: bool = False,
) -> Path:
    path = Path(cache_path or default_result_cache_path()).expanduser()
    payload = json.dumps(current.to_dict(), indent=2, sort_keys=True) + "\n"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
    except OSError:
        if root is None:
            raise
        path = developer_diagnostic_cache_path(root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
    if write_developer_copy and root is not None:
        diagnostic = developer_diagnostic_cache_path(root)
        diagnostic.parent.mkdir(parents=True, exist_ok=True)
        diagnostic.write_text(payload, encoding="utf-8")
    return path


def write_current_integrity_status_db(
    current: CurrentIntegrityStatus,
    *,
    db_path: Path = DEFAULT_ACTIVE_DB_PATH,
    consumer_compare_status: str = "",
    stale_after_seconds: int = 300,
) -> Path:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS integrity_current_status (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                generated_at TEXT,
                policy TEXT,
                status TEXT,
                result_code TEXT,
                failure_code TEXT,
                trust_state TEXT,
                manifest_path TEXT,
                signature_path TEXT,
                manifest_sha256 TEXT,
                signature_valid INTEGER,
                developer_machine_id TEXT,
                public_key_fingerprint TEXT,
                source_modified_count INTEGER,
                generated_modified_count INTEGER,
                pre_uat_compatible INTEGER,
                consumer_compare_status TEXT,
                evidence_path TEXT,
                stale_after_seconds INTEGER
            )
            """
        )
        conn.execute(
            """
            INSERT INTO integrity_current_status (
                id, generated_at, policy, status, result_code, failure_code, trust_state,
                manifest_path, signature_path, manifest_sha256, signature_valid,
                developer_machine_id, public_key_fingerprint, source_modified_count,
                generated_modified_count, pre_uat_compatible, consumer_compare_status,
                evidence_path, stale_after_seconds
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                generated_at=excluded.generated_at,
                policy=excluded.policy,
                status=excluded.status,
                result_code=excluded.result_code,
                failure_code=excluded.failure_code,
                trust_state=excluded.trust_state,
                manifest_path=excluded.manifest_path,
                signature_path=excluded.signature_path,
                manifest_sha256=excluded.manifest_sha256,
                signature_valid=excluded.signature_valid,
                developer_machine_id=excluded.developer_machine_id,
                public_key_fingerprint=excluded.public_key_fingerprint,
                source_modified_count=excluded.source_modified_count,
                generated_modified_count=excluded.generated_modified_count,
                pre_uat_compatible=excluded.pre_uat_compatible,
                consumer_compare_status=excluded.consumer_compare_status,
                evidence_path=excluded.evidence_path,
                stale_after_seconds=excluded.stale_after_seconds
            """,
            (
                current.generated_at,
                current.policy,
                current.status,
                current.result_code,
                current.failure_code,
                current.trust_state,
                current.canonical_manifest_path,
                current.canonical_signature_path,
                current.manifest_sha256,
                None if current.signature_valid is None else int(current.signature_valid),
                current.developer_machine_id,
                current.public_key_fingerprint,
                len(current.source_modified_files),
                len(current.generated_modified_files),
                int(current.pre_uat_compatible),
                consumer_compare_status,
                current.evidence_path,
                stale_after_seconds,
            ),
        )
    return path


def read_current_integrity_status_db(*, db_path: Path = DEFAULT_ACTIVE_DB_PATH) -> dict[str, Any] | None:
    path = Path(db_path)
    if not path.exists():
        return None
    try:
        with sqlite3.connect(path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM integrity_current_status WHERE id = 1").fetchone()
            return dict(row) if row else None
    except sqlite3.Error:
        return None


def read_current_integrity_status(*, cache_path: Path | None = None) -> CurrentIntegrityStatus | None:
    path = Path(cache_path or default_result_cache_path()).expanduser()
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    defaults = CurrentIntegrityStatus()
    payload = {key: data.get(key, getattr(defaults, key)) for key in CurrentIntegrityStatus.__dataclass_fields__}
    for key in (
        "source_modified_files",
        "generated_modified_files",
        "trust_metadata_files",
        "legacy_ignored_files",
        "deprecated_artifacts",
        "supersedes_event_ids",
    ):
        if payload.get(key) is None:
            payload[key] = []
    return CurrentIntegrityStatus(**payload)


def cache_is_stale(current: CurrentIntegrityStatus | None, live_manifest_sha256: str, *, stale_after_seconds: int = 300) -> bool:
    if current is None:
        return True
    if live_manifest_sha256 and current.manifest_sha256 and current.manifest_sha256 != live_manifest_sha256:
        return True
    try:
        generated = datetime.fromisoformat(current.generated_at.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - generated.astimezone(timezone.utc)).total_seconds() > stale_after_seconds
    except (ValueError, TypeError):
        return True


__all__ = [
    "CurrentIntegrityStatus",
    "DEFAULT_ACTIVE_DB_PATH",
    "build_current_integrity_status",
    "cache_is_stale",
    "default_result_cache_path",
    "developer_diagnostic_cache_path",
    "read_current_integrity_status",
    "read_current_integrity_status_db",
    "write_current_integrity_status_db",
    "write_current_integrity_status",
]
