"""Normalized release intelligence, source health, and bounded file-hash cache."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import (
    DefinitionLifecycle,
    DefinitionType,
    SourcePolicy,
    ThreatDefinition,
    utc_now,
)
from .normalization import NormalizationError, normalize_value

SCHEMA_VERSION = 1
HASH_TYPES = {DefinitionType.SHA256, DefinitionType.SHA1, DefinitionType.MD5}
INACTIVE = {
    DefinitionLifecycle.EXPIRED,
    DefinitionLifecycle.REVOKED,
    DefinitionLifecycle.FALSE_POSITIVE,
    DefinitionLifecycle.DISABLED,
    DefinitionLifecycle.SUPERSEDED,
}


def _connect(path: Path, *, read_only: bool = False) -> sqlite3.Connection:
    path = Path(path)
    if read_only:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path, timeout=30.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=5000")
    return connection


def _release_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE schema_metadata (
            schema_version INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE definition_sources (
            source_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            source_type TEXT NOT NULL,
            url TEXT,
            enabled INTEGER NOT NULL,
            trust_level INTEGER NOT NULL,
            current_version TEXT,
            current_sha256 TEXT,
            rules_received INTEGER NOT NULL DEFAULT 0,
            rules_accepted INTEGER NOT NULL DEFAULT 0,
            rules_rejected INTEGER NOT NULL DEFAULT 0,
            indicators_received INTEGER NOT NULL DEFAULT 0,
            indicators_accepted INTEGER NOT NULL DEFAULT 0,
            indicators_rejected INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE malware_hashes (
            hash_id TEXT PRIMARY KEY,
            sha256 TEXT,
            sha1 TEXT,
            md5 TEXT,
            family TEXT,
            malware_name TEXT,
            platform TEXT,
            architecture TEXT,
            classification TEXT,
            first_seen TEXT,
            last_seen TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            inserted_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            CHECK (sha256 IS NOT NULL OR sha1 IS NOT NULL OR md5 IS NOT NULL)
        );
        CREATE TABLE malware_hash_sources (
            hash_id TEXT NOT NULL REFERENCES malware_hashes(hash_id) ON DELETE CASCADE,
            source_id TEXT NOT NULL,
            source_reference TEXT NOT NULL DEFAULT '',
            source_confidence REAL NOT NULL,
            trust_level INTEGER NOT NULL,
            retrieved_at TEXT NOT NULL,
            PRIMARY KEY (hash_id, source_id, source_reference)
        ) WITHOUT ROWID;
        CREATE TABLE yara_rules (
            definition_id TEXT PRIMARY KEY,
            rule_name TEXT,
            namespace TEXT NOT NULL,
            family TEXT,
            severity TEXT NOT NULL,
            source_id TEXT NOT NULL,
            trust_level INTEGER NOT NULL,
            source_reference TEXT,
            metadata_json TEXT NOT NULL
        );
        CREATE INDEX malware_hashes_sha256_idx ON malware_hashes(sha256) WHERE sha256 IS NOT NULL;
        CREATE INDEX malware_hashes_sha1_idx ON malware_hashes(sha1) WHERE sha1 IS NOT NULL;
        CREATE INDEX malware_hashes_md5_idx ON malware_hashes(md5) WHERE md5 IS NOT NULL;
        CREATE INDEX malware_hashes_family_idx ON malware_hashes(family);
        CREATE INDEX malware_hashes_classification_idx ON malware_hashes(classification);
        CREATE INDEX malware_hashes_active_idx ON malware_hashes(active);
        CREATE INDEX malware_hash_sources_source_idx ON malware_hash_sources(source_id);
        CREATE INDEX yara_rules_source_idx ON yara_rules(source_id);
        """
    )
    connection.execute(
        "INSERT INTO schema_metadata(schema_version, created_at) VALUES (?, ?)",
        (SCHEMA_VERSION, utc_now().isoformat()),
    )


def _trust_level_from_policy(policy: SourcePolicy | None, fallback: int = 3) -> int:
    return int(policy.trust_level) if policy is not None else fallback


def build_release_database(
    destination: Path,
    definitions: Iterable[ThreatDefinition],
    *,
    source_policies: dict[str, SourcePolicy] | None = None,
    source_versions: dict[str, str] | None = None,
    batch_size: int = 10_000,
) -> dict[str, int]:
    """Build a closed SQLite database beside a staged release, then atomically place it."""

    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    counts = {
        "hashes": 0, "hash_provenance": 0, "yara_rules": 0, "sources": 0,
        "sha256": 0, "sha1": 0, "md5": 0,
    }
    policies = source_policies or {}
    versions = source_versions or {}
    try:
        with _connect(temporary) as connection:
            connection.execute("PRAGMA journal_mode=OFF")
            connection.execute("PRAGMA synchronous=OFF")
            _release_schema(connection)
            observed_sources: set[str] = set()
            hash_rows: list[tuple[Any, ...]] = []
            provenance_rows: list[tuple[Any, ...]] = []
            yara_rows: list[tuple[Any, ...]] = []
            now = utc_now().isoformat()

            def flush() -> None:
                if hash_rows:
                    connection.executemany(
                        "INSERT INTO malware_hashes "
                        "(hash_id,sha256,sha1,md5,family,malware_name,platform,architecture,classification,first_seen,last_seen,active,inserted_at,updated_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                        "ON CONFLICT(hash_id) DO UPDATE SET "
                        "sha256=COALESCE(excluded.sha256,malware_hashes.sha256),"
                        "sha1=COALESCE(excluded.sha1,malware_hashes.sha1),md5=COALESCE(excluded.md5,malware_hashes.md5),"
                        "family=COALESCE(excluded.family,malware_hashes.family),malware_name=COALESCE(excluded.malware_name,malware_hashes.malware_name),"
                        "platform=COALESCE(excluded.platform,malware_hashes.platform),architecture=COALESCE(excluded.architecture,malware_hashes.architecture),"
                        "classification=COALESCE(excluded.classification,malware_hashes.classification),"
                        "first_seen=COALESCE(malware_hashes.first_seen,excluded.first_seen),last_seen=COALESCE(excluded.last_seen,malware_hashes.last_seen),"
                        "active=MAX(excluded.active,malware_hashes.active),updated_at=excluded.updated_at",
                        hash_rows,
                    )
                    hash_rows.clear()
                if provenance_rows:
                    connection.executemany(
                        "INSERT OR IGNORE INTO malware_hash_sources "
                        "(hash_id,source_id,source_reference,source_confidence,trust_level,retrieved_at) VALUES (?,?,?,?,?,?)",
                        provenance_rows,
                    )
                    provenance_rows.clear()
                if yara_rows:
                    connection.executemany(
                        "INSERT OR REPLACE INTO yara_rules "
                        "(definition_id,rule_name,namespace,family,severity,source_id,trust_level,source_reference,metadata_json) VALUES (?,?,?,?,?,?,?,?,?)",
                        yara_rows,
                    )
                    yara_rows.clear()

            for definition in definitions:
                active = int(definition.lifecycle not in INACTIVE)
                if definition.definition_type in HASH_TYPES:
                    columns = {"sha256": None, "sha1": None, "md5": None}
                    columns[definition.definition_type.value.lower()] = definition.value
                    metadata = definition.metadata if isinstance(definition.metadata, dict) else {}
                    # A provider may supply correlated hashes for the same sample.
                    for name, kind in (("sha256", DefinitionType.SHA256), ("sha1", DefinitionType.SHA1), ("md5", DefinitionType.MD5)):
                        candidate = metadata.get(name)
                        if candidate:
                            try:
                                columns[name] = normalize_value(kind, str(candidate))
                            except NormalizationError:
                                pass
                    sample_hash_id = f"sample-sha256-{columns['sha256']}" if columns["sha256"] else definition.definition_id
                    hash_rows.append((
                        sample_hash_id, columns["sha256"], columns["sha1"], columns["md5"],
                        definition.malware_family, metadata.get("malware_name"), metadata.get("platform", "macos"),
                        metadata.get("architecture"), metadata.get("classification", "malware_indicator"),
                        definition.first_seen.isoformat() if definition.first_seen else None,
                        definition.last_seen.isoformat() if definition.last_seen else None,
                        active, now, now,
                    ))
                    counts["hashes"] += 1
                    for provenance in definition.provenance:
                        observed_sources.add(provenance.source_id)
                        policy = policies.get(provenance.source_id)
                        provenance_rows.append((
                            sample_hash_id, provenance.source_id, provenance.source_reference or "",
                            float(provenance.source_confidence), _trust_level_from_policy(policy),
                            provenance.retrieved_at.isoformat(),
                        ))
                        counts["hash_provenance"] += 1
                elif definition.definition_type == DefinitionType.YARA_RULE:
                    from .validation import split_yara_rules
                    provenance = definition.provenance[0] if definition.provenance else None
                    source_id = provenance.source_id if provenance else "unknown"
                    observed_sources.add(source_id)
                    policy = policies.get(source_id)
                    metadata = definition.metadata if isinstance(definition.metadata, dict) else {}
                    rules = split_yara_rules(definition.value) or [(str(metadata.get("rule_name") or definition.definition_id), definition.value)]
                    for rule_name, _source in rules:
                        rule_id = f"{definition.definition_id}-{hashlib.sha256(rule_name.encode('utf-8')).hexdigest()[:12]}"
                        yara_rows.append((
                            rule_id, rule_name,
                            metadata.get("namespace") or _safe_namespace(source_id), definition.malware_family,
                            definition.severity.value, source_id, _trust_level_from_policy(policy),
                            provenance.source_reference if provenance else None,
                            json.dumps(metadata, sort_keys=True, separators=(",", ":")),
                        ))
                        counts["yara_rules"] += 1
                if len(hash_rows) + len(provenance_rows) + len(yara_rows) >= max(100, batch_size):
                    flush()
            flush()
            for source_id in sorted(observed_sources | set(policies)):
                policy = policies.get(source_id)
                connection.execute(
                    "INSERT INTO definition_sources "
                    "(source_id,name,source_type,url,enabled,trust_level,current_version) VALUES (?,?,?,?,?,?,?)",
                    (
                        source_id, policy.display_name if policy else source_id, "mixed",
                        None, int(policy.enabled) if policy else 1, _trust_level_from_policy(policy), versions.get(source_id),
                    ),
                )
                counts["sources"] += 1
            connection.commit()
            row = connection.execute(
                "SELECT COUNT(*),COALESCE(SUM(sha256 IS NOT NULL),0),"
                "COALESCE(SUM(sha1 IS NOT NULL),0),COALESCE(SUM(md5 IS NOT NULL),0) "
                "FROM malware_hashes WHERE active=1"
            ).fetchone()
            counts.update({"hashes": int(row[0]), "sha256": int(row[1]), "sha1": int(row[2]), "md5": int(row[3])})
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise sqlite3.DatabaseError(f"release intelligence database integrity check failed: {integrity}")
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        return counts
    finally:
        temporary.unlink(missing_ok=True)


def _safe_namespace(value: str) -> str:
    output = "".join(character if character.isalnum() or character == "_" else "_" for character in value)
    output = output.strip("_")[:96]
    if not output or output[0].isdigit():
        output = f"source_{output}"
    return output


class MalwareIntelligenceDatabase:
    """Read-only hash lookup API for an immutable active release."""

    def __init__(self, path: Path, *, release_id: str = "") -> None:
        self.path = Path(path)
        self.release_id = release_id

    def verify(self) -> dict[str, Any]:
        with _connect(self.path, read_only=True) as connection:
            version = connection.execute("SELECT schema_version FROM schema_metadata LIMIT 1").fetchone()
            if not version or int(version[0]) != SCHEMA_VERSION:
                raise sqlite3.DatabaseError("unsupported threat-intelligence database schema")
            integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
            if integrity != "ok":
                raise sqlite3.DatabaseError(f"threat-intelligence database failed quick_check: {integrity}")
            return {
                "schema_version": int(version[0]),
                "hash_count": int(connection.execute("SELECT COUNT(*) FROM malware_hashes WHERE active=1").fetchone()[0]),
                "indicator_count": int(connection.execute(
                    "SELECT COALESCE(SUM((sha256 IS NOT NULL)+(sha1 IS NOT NULL)+(md5 IS NOT NULL)),0) FROM malware_hashes WHERE active=1"
                ).fetchone()[0]),
                "yara_rule_count": int(connection.execute("SELECT COUNT(*) FROM yara_rules").fetchone()[0]),
            }

    def lookup_sha256(self, value: str) -> dict[str, Any]:
        return self._lookup("sha256", normalize_value(DefinitionType.SHA256, value))

    def lookup_sha1(self, value: str) -> dict[str, Any]:
        return self._lookup("sha1", normalize_value(DefinitionType.SHA1, value))

    def lookup_md5(self, value: str) -> dict[str, Any]:
        return self._lookup("md5", normalize_value(DefinitionType.MD5, value))

    def _lookup(self, column: str, value: str) -> dict[str, Any]:
        if column not in {"sha256", "sha1", "md5"}:
            raise ValueError("unsupported hash algorithm")
        with _connect(self.path, read_only=True) as connection:
            row = connection.execute(
                f"SELECT * FROM malware_hashes WHERE {column}=? AND active=1 LIMIT 1", (value,),
            ).fetchone()
            if row is None:
                return {"matched": False, "algorithm": column, "value": value, "definition_release": self.release_id, "sources": []}
            sources = [dict(item) for item in connection.execute(
                "SELECT source_id AS source, source_confidence, trust_level, source_reference "
                "FROM malware_hash_sources WHERE hash_id=? ORDER BY trust_level DESC, source_id",
                (row["hash_id"],),
            )]
            result = dict(row)
            result.update({"matched": True, "algorithm": column, "value": value, "definition_release": self.release_id, "sources": sources})
            return result


class SourceHealthDatabase:
    """Mutable operational source state; release data remains immutable."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def initialize(self) -> None:
        with _connect(self.path) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS definition_sources (
                    source_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    url TEXT,
                    enabled INTEGER NOT NULL,
                    trust_level INTEGER NOT NULL,
                    required INTEGER NOT NULL DEFAULT 0,
                    last_checked TEXT,
                    last_success TEXT,
                    last_failure TEXT,
                    last_http_status INTEGER,
                    etag TEXT,
                    last_modified TEXT,
                    current_version TEXT,
                    current_sha256 TEXT,
                    failure_count INTEGER NOT NULL DEFAULT 0,
                    rules_received INTEGER NOT NULL DEFAULT 0,
                    rules_accepted INTEGER NOT NULL DEFAULT 0,
                    rules_rejected INTEGER NOT NULL DEFAULT 0,
                    indicators_received INTEGER NOT NULL DEFAULT 0,
                    indicators_accepted INTEGER NOT NULL DEFAULT 0,
                    indicators_rejected INTEGER NOT NULL DEFAULT 0,
                    average_latency REAL NOT NULL DEFAULT 0,
                    check_count INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    last_sequence TEXT,
                    last_timestamp TEXT,
                    last_cursor TEXT
                );
                """
            )
            columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(definition_sources)")}
            if "check_count" not in columns:
                connection.execute("ALTER TABLE definition_sources ADD COLUMN check_count INTEGER NOT NULL DEFAULT 0")

    def sync_policy(self, policy: SourcePolicy, *, source_type: str, url: str | None) -> None:
        self.initialize()
        with _connect(self.path) as connection:
            connection.execute(
                "INSERT INTO definition_sources(source_id,name,source_type,url,enabled,trust_level,required) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT(source_id) DO UPDATE SET name=excluded.name,source_type=excluded.source_type,url=excluded.url,"
                "enabled=excluded.enabled,trust_level=excluded.trust_level,required=excluded.required",
                (policy.source_id, policy.display_name, source_type, url, int(policy.enabled), int(policy.trust_level), int(policy.required)),
            )

    def record(self, source_id: str, *, outcome: str, latency: float = 0.0, **values: Any) -> None:
        self.initialize()
        now = utc_now().isoformat()
        with _connect(self.path) as connection:
            row = connection.execute(
                "SELECT average_latency,check_count FROM definition_sources WHERE source_id=?", (source_id,),
            ).fetchone()
        previous_average = float(row[0]) if row else 0.0
        check_count = int(row[1]) if row else 0
        measured_latency = max(0.0, float(latency))
        assignments: dict[str, Any] = {
            "last_checked": now,
            "average_latency": ((previous_average * check_count) + measured_latency) / (check_count + 1),
            "check_count": check_count + 1,
        }
        if outcome == "success":
            assignments.update({"last_success": now, "failure_count": 0, "last_error": None})
        elif outcome == "failure":
            assignments.update({"last_failure": now, "last_error": str(values.pop("last_error", ""))[:512]})
        allowed = {
            "last_http_status", "etag", "last_modified", "current_version", "current_sha256",
            "rules_received", "rules_accepted", "rules_rejected", "indicators_received",
            "indicators_accepted", "indicators_rejected", "last_sequence", "last_timestamp", "last_cursor",
        }
        assignments.update({key: value for key, value in values.items() if key in allowed})
        with _connect(self.path) as connection:
            if outcome == "failure":
                connection.execute("UPDATE definition_sources SET failure_count=failure_count+1 WHERE source_id=?", (source_id,))
            sql = ",".join(f"{key}=?" for key in assignments)
            connection.execute(f"UPDATE definition_sources SET {sql} WHERE source_id=?", (*assignments.values(), source_id))

    def rows(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        with _connect(self.path, read_only=True) as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM definition_sources ORDER BY source_id")]


class FileHashCache:
    """Metadata-keyed SHA-256-first cache; legacy digests are calculated lazily."""

    def __init__(self, path: Path, *, maximum_entries: int = 100_000) -> None:
        self.path = Path(path)
        self.maximum_entries = max(100, int(maximum_entries))
        with _connect(self.path) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS file_hash_cache ("
                "path TEXT NOT NULL,device INTEGER NOT NULL,inode INTEGER NOT NULL,size INTEGER NOT NULL,mtime_ns INTEGER NOT NULL,"
                "sha256 TEXT NOT NULL,sha1 TEXT,md5 TEXT,last_verified TEXT NOT NULL,PRIMARY KEY(device,inode,size,mtime_ns))"
            )

    def digest(self, path: Path, *, include_legacy: bool = False, maximum_bytes: int = 512 * 1024 * 1024) -> dict[str, str]:
        path = Path(path)
        info = path.lstat()
        if path.is_symlink() or not path.is_file() or info.st_size > maximum_bytes:
            raise ValueError("hash target is not a bounded regular file")
        key = (int(info.st_dev), int(info.st_ino), int(info.st_size), int(info.st_mtime_ns))
        with _connect(self.path) as connection:
            row = connection.execute(
                "SELECT sha256,sha1,md5 FROM file_hash_cache WHERE device=? AND inode=? AND size=? AND mtime_ns=?", key,
            ).fetchone()
            if row and (not include_legacy or (row["sha1"] and row["md5"])):
                return {name: str(row[name]) for name in ("sha256", "sha1", "md5") if row[name]}
            hashers = {"sha256": hashlib.sha256()}
            if include_legacy:
                hashers.update({"sha1": hashlib.sha1(), "md5": hashlib.md5()})
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    for hasher in hashers.values():
                        hasher.update(chunk)
            values = {name: hasher.hexdigest() for name, hasher in hashers.items()}
            connection.execute(
                "INSERT OR REPLACE INTO file_hash_cache(path,device,inode,size,mtime_ns,sha256,sha1,md5,last_verified) VALUES (?,?,?,?,?,?,?,?,?)",
                (str(path), *key, values["sha256"], values.get("sha1"), values.get("md5"), utc_now().isoformat()),
            )
            count = int(connection.execute("SELECT COUNT(*) FROM file_hash_cache").fetchone()[0])
            if count > self.maximum_entries:
                connection.execute(
                    "DELETE FROM file_hash_cache WHERE rowid IN (SELECT rowid FROM file_hash_cache ORDER BY last_verified LIMIT ?)",
                    (count - self.maximum_entries,),
                )
            return values


__all__ = [
    "SCHEMA_VERSION",
    "FileHashCache",
    "MalwareIntelligenceDatabase",
    "SourceHealthDatabase",
    "build_release_database",
]
