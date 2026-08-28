from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 3


class EvidenceStoreCorruptError(RuntimeError): pass
class EvidenceStoreDowngradeError(RuntimeError): pass
class EvidenceStoreMigrationRecoveryError(RuntimeError): pass


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    incident_id: str
    created_at: str
    kind: str
    payload: dict[str, Any]

    @property
    def sha256(self) -> str:
        return hashlib.sha256(json.dumps(self.payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class IncidentRecord:
    incident_id: str; first_event_time: str; last_event_time: str; boot_session_id: str; endpoint_id: str
    severity: str; confidence: str; score: int; policy_version: str; ruleset_version: str
    containment_state: str; notification_state: str; created_at: str; updated_at: str
    risk_score_version: str = "1.0"; user_context: dict[str, Any] | None = None
    responsible_process: dict[str, Any] | None = None; process_tree: list[dict[str, Any]] | None = None
    signals: list[dict[str, Any]] | None = None; affected_file_count: int = 0
    affected_directories: tuple[str, ...] = (); affected_volumes: tuple[str, ...] = ()
    canary_state: str = "not_observed"; backup_sabotage_state: str = "not_observed"
    tamper_state: str = "not_observed"; analyst_state: str = "unreviewed"
    resolution: str = ""; limitations: tuple[str, ...] = (); closed_at: str | None = None


class RansomwareEvidenceStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        parent_existed = self.path.parent.exists()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not parent_existed:
            os.chmod(self.path.parent, 0o700)
        self.migration_marker = self.path.with_suffix(self.path.suffix + ".migration.json")
        self._recover_interrupted_migration()
        existed = self.path.exists() and self.path.stat().st_size > 0
        self.connection = sqlite3.connect(self.path)
        if existed:
            try:
                quick = self.connection.execute("PRAGMA quick_check").fetchone()
                if not quick or quick[0] != "ok": raise sqlite3.DatabaseError(str(quick))
            except sqlite3.DatabaseError as exc:
                self.connection.close()
                recovery = self.path.with_suffix(self.path.suffix + ".corrupt")
                shutil.copy2(self.path, recovery)
                raise EvidenceStoreCorruptError(f"incident vault is corrupt; preserved at {recovery}") from exc
        prior_version = self._existing_schema_version()
        if prior_version > SCHEMA_VERSION:
            self.connection.close()
            raise EvidenceStoreDowngradeError(f"vault schema {prior_version} is newer than supported schema {SCHEMA_VERSION}")
        self.migration_backup: Path | None = None
        if existed and prior_version < SCHEMA_VERSION:
            self.migration_backup = self.path.with_suffix(self.path.suffix + f".pre-v{SCHEMA_VERSION}.bak")
            backup = sqlite3.connect(self.migration_backup)
            self.connection.backup(backup); backup.close()
            self.migration_marker.write_text(json.dumps({"from_version": prior_version, "to_version": SCHEMA_VERSION, "backup": self.migration_backup.name}, sort_keys=True), encoding="utf-8")
            os.chmod(self.migration_marker, 0o600)
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA journal_size_limit=8388608")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS anti_ransomware_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS anti_ransomware_schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL, migration_sha256 TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS anti_ransomware_incidents(
              incident_id TEXT PRIMARY KEY, first_event_time TEXT NOT NULL, last_event_time TEXT NOT NULL,
              boot_session_id TEXT NOT NULL, endpoint_id TEXT NOT NULL, severity TEXT NOT NULL,
              confidence TEXT NOT NULL, score INTEGER NOT NULL, policy_version TEXT NOT NULL,
              ruleset_version TEXT NOT NULL, containment_state TEXT NOT NULL,
              notification_state TEXT NOT NULL, resolution TEXT NOT NULL DEFAULT '', limitations_json TEXT NOT NULL,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL, closed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS anti_ransomware_process_identities(
              process_key TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES anti_ransomware_incidents(incident_id),
              pid INTEGER NOT NULL, pid_version INTEGER NOT NULL, executable_path_token TEXT NOT NULL,
              executable_sha256 TEXT NOT NULL, uid INTEGER NOT NULL, identity_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS anti_ransomware_process_edges(
              edge_id INTEGER PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES anti_ransomware_incidents(incident_id),
              parent_key TEXT NOT NULL, child_key TEXT NOT NULL, observed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS anti_ransomware_file_mutations(
              mutation_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES anti_ransomware_incidents(incident_id),
              process_key TEXT NOT NULL, occurred_at TEXT NOT NULL, path_token TEXT NOT NULL,
              operation TEXT NOT NULL, statistics_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS anti_ransomware_detection_signals(
              signal_row_id INTEGER PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES anti_ransomware_incidents(incident_id),
              signal_id TEXT NOT NULL, weight INTEGER NOT NULL, rationale TEXT NOT NULL, evidence_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS anti_ransomware_decisions(
              decision_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES anti_ransomware_incidents(incident_id),
              created_at TEXT NOT NULL, score INTEGER NOT NULL, decision_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS anti_ransomware_containment_leases(
              lease_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES anti_ransomware_incidents(incident_id),
              process_key TEXT NOT NULL, state TEXT NOT NULL, started_at TEXT NOT NULL, expires_at TEXT NOT NULL,
              policy TEXT NOT NULL, owner TEXT NOT NULL, renewal_count INTEGER NOT NULL DEFAULT 0,
              maximum_renewal INTEGER NOT NULL DEFAULT 0, rollback_action TEXT NOT NULL, updated_at TEXT NOT NULL,
              no_user_policy TEXT NOT NULL DEFAULT 'PAUSE_BOUNDED_THEN_RESUME', criticality TEXT NOT NULL DEFAULT 'noncritical',
              evidence_state TEXT NOT NULL DEFAULT 'preserved', process_identity_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS anti_ransomware_containment_actions(
              action_id TEXT PRIMARY KEY, lease_id TEXT NOT NULL REFERENCES anti_ransomware_containment_leases(lease_id),
              previous_state TEXT NOT NULL, new_state TEXT NOT NULL, actor TEXT NOT NULL,
              reason TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS anti_ransomware_notification_deliveries(
              delivery_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES anti_ransomware_incidents(incident_id),
              user_id_token TEXT NOT NULL, state TEXT NOT NULL, sanitized_json TEXT NOT NULL,
              created_at TEXT NOT NULL, updated_at TEXT NOT NULL, expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS anti_ransomware_rules(rule_id TEXT PRIMARY KEY, current_revision INTEGER NOT NULL, rule_hash TEXT NOT NULL, status TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS anti_ransomware_rule_revisions(rule_id TEXT NOT NULL REFERENCES anti_ransomware_rules(rule_id), revision INTEGER NOT NULL, rule_json TEXT NOT NULL, created_at TEXT NOT NULL, actor TEXT NOT NULL, PRIMARY KEY(rule_id,revision));
            CREATE TABLE IF NOT EXISTS anti_ransomware_policy_versions(policy_version TEXT PRIMARY KEY, policy_sha256 TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS anti_ransomware_health_samples(sample_id INTEGER PRIMARY KEY, sampled_at TEXT NOT NULL, state TEXT NOT NULL, metrics_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS anti_ransomware_sequence_gaps(gap_id TEXT PRIMARY KEY, observed_at TEXT NOT NULL, event_type TEXT NOT NULL, first_missing INTEGER NOT NULL, last_missing INTEGER NOT NULL, queue_depth INTEGER NOT NULL, resolved_at TEXT);
            CREATE TABLE IF NOT EXISTS anti_ransomware_evidence(
              evidence_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, created_at TEXT NOT NULL,
              kind TEXT NOT NULL, payload_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ar_evidence_incident_time ON anti_ransomware_evidence(incident_id, created_at);
            CREATE INDEX IF NOT EXISTS ar_incidents_time ON anti_ransomware_incidents(last_event_time);
            CREATE INDEX IF NOT EXISTS ar_incidents_state ON anti_ransomware_incidents(containment_state, notification_state);
            CREATE INDEX IF NOT EXISTS ar_mutations_incident_time ON anti_ransomware_file_mutations(incident_id, occurred_at);
            CREATE TABLE IF NOT EXISTS anti_ransomware_chain_of_custody(
              sequence INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL,
              created_at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
              object_id TEXT NOT NULL, previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL, details_json TEXT NOT NULL
            );
            """
        )
        with self.connection:
            for column, declaration in {
                "no_user_policy": "TEXT NOT NULL DEFAULT 'PAUSE_BOUNDED_THEN_RESUME'", "criticality": "TEXT NOT NULL DEFAULT 'noncritical'",
                "evidence_state": "TEXT NOT NULL DEFAULT 'preserved'", "process_identity_json": "TEXT NOT NULL DEFAULT '{}'",
            }.items(): self._ensure_column("anti_ransomware_containment_leases", column, declaration)
            incident_columns = {
                "risk_score_version": "TEXT NOT NULL DEFAULT '1.0'", "user_context_json": "TEXT NOT NULL DEFAULT '{}'",
                "responsible_process_json": "TEXT NOT NULL DEFAULT '{}'", "process_tree_json": "TEXT NOT NULL DEFAULT '[]'",
                "signals_json": "TEXT NOT NULL DEFAULT '[]'", "affected_file_count": "INTEGER NOT NULL DEFAULT 0",
                "affected_directories_json": "TEXT NOT NULL DEFAULT '[]'", "affected_volumes_json": "TEXT NOT NULL DEFAULT '[]'",
                "canary_state": "TEXT NOT NULL DEFAULT 'not_observed'", "backup_sabotage_state": "TEXT NOT NULL DEFAULT 'not_observed'",
                "tamper_state": "TEXT NOT NULL DEFAULT 'not_observed'", "analyst_state": "TEXT NOT NULL DEFAULT 'unreviewed'",
            }
            for column, declaration in incident_columns.items(): self._ensure_column("anti_ransomware_incidents", column, declaration)
            self.connection.execute("INSERT OR REPLACE INTO anti_ransomware_meta(key,value) VALUES('schema_version',?)", (str(SCHEMA_VERSION),))
            migration_hash = hashlib.sha256(b"anti-ransomware-schema-v3-complete-incident").hexdigest()
            self.connection.execute("INSERT OR IGNORE INTO anti_ransomware_schema_migrations VALUES(3,datetime('now'),?)", (migration_hash,))
        os.chmod(self.path, 0o600)
        if self.migration_marker.exists(): self.migration_marker.unlink()

    def _recover_interrupted_migration(self) -> None:
        if not self.migration_marker.exists(): return
        try:
            marker = json.loads(self.migration_marker.read_text(encoding="utf-8"))
            backup = self.path.parent / str(marker["backup"])
            if backup.parent != self.path.parent or not backup.is_file(): raise ValueError("backup unavailable")
            check = sqlite3.connect(f"file:{backup}?mode=ro", uri=True)
            result = check.execute("PRAGMA quick_check").fetchone(); check.close()
            if not result or result[0] != "ok": raise ValueError("backup corrupt")
            temporary = self.path.with_suffix(self.path.suffix + ".recovery.tmp")
            shutil.copy2(backup, temporary); os.replace(temporary, self.path)
            self.migration_marker.unlink()
        except (OSError, ValueError, KeyError, json.JSONDecodeError, sqlite3.DatabaseError) as exc:
            raise EvidenceStoreMigrationRecoveryError("interrupted vault migration requires administrator recovery") from exc

    def _existing_schema_version(self) -> int:
        try:
            exists = self.connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='anti_ransomware_meta'").fetchone()
            if not exists: return 0
            row = self.connection.execute("SELECT value FROM anti_ransomware_meta WHERE key='schema_version'").fetchone()
            return int(row[0]) if row else 0
        except (sqlite3.DatabaseError, ValueError, TypeError):
            return 0

    def _ensure_column(self, table: str, column: str, declaration: str) -> None:
        allowed_tables = {"anti_ransomware_containment_leases", "anti_ransomware_incidents"}
        if table not in allowed_tables or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", column):
            raise ValueError("invalid anti-ransomware schema identifier")
        if ";" in declaration or "--" in declaration or not re.fullmatch(r"[A-Za-z0-9_'()\[\] {},.:-]+", declaration):
            raise ValueError("invalid anti-ransomware column declaration")
        existing = {str(row[1]) for row in self.connection.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            self.connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")

    def append(self, record: EvidenceRecord) -> None:
        payload_json = json.dumps(record.payload, sort_keys=True, separators=(",", ":"))
        with self.connection:
            self.connection.execute(
                "INSERT INTO anti_ransomware_evidence VALUES(?,?,?,?,?,?)",
                (record.evidence_id, record.incident_id, record.created_at, record.kind, payload_json, record.sha256),
            )

    def upsert_incident(self, incident: IncidentRecord) -> None:
        columns = (
            "incident_id", "first_event_time", "last_event_time", "boot_session_id", "endpoint_id", "severity", "confidence", "score",
            "policy_version", "ruleset_version", "containment_state", "notification_state", "resolution", "limitations_json", "created_at",
            "updated_at", "closed_at", "risk_score_version", "user_context_json", "responsible_process_json", "process_tree_json", "signals_json",
            "affected_file_count", "affected_directories_json", "affected_volumes_json", "canary_state", "backup_sabotage_state", "tamper_state", "analyst_state",
        )
        values = (
            incident.incident_id, incident.first_event_time, incident.last_event_time, incident.boot_session_id, incident.endpoint_id,
            incident.severity, incident.confidence, incident.score, incident.policy_version, incident.ruleset_version,
            incident.containment_state, incident.notification_state, incident.resolution, json.dumps(incident.limitations),
            incident.created_at, incident.updated_at, incident.closed_at, incident.risk_score_version,
            json.dumps(incident.user_context or {}, sort_keys=True), json.dumps(incident.responsible_process or {}, sort_keys=True),
            json.dumps(incident.process_tree or [], sort_keys=True), json.dumps(incident.signals or [], sort_keys=True), incident.affected_file_count,
            json.dumps(incident.affected_directories), json.dumps(incident.affected_volumes), incident.canary_state,
            incident.backup_sabotage_state, incident.tamper_state, incident.analyst_state,
        )
        with self.connection:
            self.connection.execute(
                "INSERT INTO anti_ransomware_incidents(" + ",".join(columns) + ") VALUES(" + ",".join("?" for _ in values) + ") ON CONFLICT(incident_id) DO UPDATE SET " + ",".join(f"{column}=excluded.{column}" for column in columns if column != "incident_id"),
                values,
            )

    def checkpoint_wal(self) -> tuple[int, int, int]:
        row = self.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        return tuple(int(value) for value in row)

    def record_notification(self, *, delivery_id: str, incident_id: str, user_id_token: str, state: str, sanitized: dict[str, Any], created_at: str, updated_at: str, expires_at: str) -> None:
        forbidden = {"full_path", "file_content", "environment", "raw_command_line", "root_database"}
        if forbidden & set(sanitized):
            raise ValueError("notification payload contains privileged evidence fields")
        payload = json.dumps(sanitized, sort_keys=True, separators=(",", ":"))
        with self.connection:
            self.connection.execute(
                "INSERT OR REPLACE INTO anti_ransomware_notification_deliveries(delivery_id,incident_id,user_id_token,state,sanitized_json,created_at,updated_at,expires_at) VALUES(?,?,?,?,?,?,?,?)",
                (delivery_id, incident_id, user_id_token, state, payload, created_at, updated_at, expires_at),
            )
        self.append_chain_entry(incident_id=incident_id, created_at=updated_at, actor="system_engine", action="notification_state", object_id=delivery_id, details={"state": state})

    def verify(self, evidence_id: str) -> bool:
        row = self.connection.execute("SELECT payload_json,payload_sha256 FROM anti_ransomware_evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
        return bool(row and hashlib.sha256(str(row[0]).encode()).hexdigest() == row[1])

    def close(self) -> None:
        self.connection.close()

    def integrity_check(self) -> bool:
        row = self.connection.execute("PRAGMA integrity_check").fetchone()
        return bool(row and row[0] == "ok")

    def append_chain_entry(self, *, incident_id: str, created_at: str, actor: str, action: str, object_id: str, details: dict[str, Any]) -> str:
        previous = self.connection.execute("SELECT entry_hash FROM anti_ransomware_chain_of_custody ORDER BY sequence DESC LIMIT 1").fetchone()
        previous_hash = str(previous[0]) if previous else "0" * 64
        details_json = json.dumps(details, sort_keys=True, separators=(",", ":"))
        material = "|".join((previous_hash, incident_id, created_at, actor, action, object_id, details_json))
        entry_hash = hashlib.sha256(material.encode()).hexdigest()
        with self.connection:
            self.connection.execute("INSERT INTO anti_ransomware_chain_of_custody(incident_id,created_at,actor,action,object_id,previous_hash,entry_hash,details_json) VALUES(?,?,?,?,?,?,?,?)", (incident_id, created_at, actor, action, object_id, previous_hash, entry_hash, details_json))
        return entry_hash

    def verify_chain(self) -> bool:
        previous = "0" * 64
        rows = self.connection.execute("SELECT incident_id,created_at,actor,action,object_id,previous_hash,entry_hash,details_json FROM anti_ransomware_chain_of_custody ORDER BY sequence").fetchall()
        for incident_id, created_at, actor, action, object_id, stored_previous, entry_hash, details_json in rows:
            material = "|".join((previous, incident_id, created_at, actor, action, object_id, details_json))
            if stored_previous != previous or hashlib.sha256(material.encode()).hexdigest() != entry_hash:
                return False
            previous = entry_hash
        return True

    def export_incident(self, incident_id: str, destination: Path) -> dict[str, Any]:
        """Create a read-only JSON evidence export and hash manifest."""
        tables = (
            "anti_ransomware_incidents", "anti_ransomware_process_identities",
            "anti_ransomware_file_mutations", "anti_ransomware_detection_signals",
            "anti_ransomware_decisions", "anti_ransomware_evidence",
            "anti_ransomware_chain_of_custody",
        )
        payload: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "incident_id": incident_id, "tables": {}}
        for table in tables:
            columns = [row[1] for row in self.connection.execute(f"PRAGMA table_info({table})")]
            rows = self.connection.execute(f"SELECT * FROM {table} WHERE incident_id=?", (incident_id,)).fetchall()
            payload["tables"][table] = [dict(zip(columns, row, strict=True)) for row in rows]
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(encoded)
        manifest = {"path": destination.name, "sha256": hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded)}
        destination.with_suffix(destination.suffix + ".manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8")
        return manifest

    def apply_retention(self, *, days: int, authorized: bool, now: datetime | None = None) -> int:
        if not authorized:
            raise PermissionError("retention purge requires explicit authorization")
        if days < 1:
            raise ValueError("retention must be at least one day")
        cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=days)
        with self.connection:
            rows = self.connection.execute(
                "SELECT incident_id FROM anti_ransomware_incidents WHERE closed_at IS NOT NULL AND closed_at < ?",
                (cutoff.isoformat(),),
            ).fetchall()
            for (incident_id,) in rows:
                # Dependent operational rows are purged; chain entries remain as an audit record.
                for table in ("anti_ransomware_detection_signals", "anti_ransomware_file_mutations", "anti_ransomware_process_identities", "anti_ransomware_decisions", "anti_ransomware_evidence"):
                    self.connection.execute(f"DELETE FROM {table} WHERE incident_id=?", (incident_id,))
                self.connection.execute("DELETE FROM anti_ransomware_incidents WHERE incident_id=?", (incident_id,))
        return len(rows)


def create_evidence_bundle(destination: Path, *, detection: dict[str, Any], redact: bool = True) -> dict[str, Any]:
    """Write a reproducible metadata-only bundle and chain-of-custody manifest."""
    forbidden = {"file_content", "contents", "secret", "credential", "raw_bytes"}

    def sanitize(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: sanitize(item) for key, item in value.items() if key.lower() not in forbidden}
        if isinstance(value, list):
            return [sanitize(item) for item in value]
        if redact and isinstance(value, str):
            home = str(Path.home())
            return value.replace(home, "<HOME>") if home and home != "/" else value
        return value

    payload = {
        "schema_version": "1.0", "evidence_type": "anti_ransomware_detection_metadata",
        "created_at": datetime.now(timezone.utc).isoformat(), "privacy": {
            "file_contents_included": False, "credentials_included": False, "redacted": redact,
        }, "detection": sanitize(detection),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(encoded)
    digest = hashlib.sha256(encoded).hexdigest()
    manifest = {"evidence_file": destination.name, "sha256": digest, "bytes": len(encoded),
                "chain_of_custody": [{"sequence": 1, "action": "created", "object_sha256": digest}]}
    manifest_path = destination.with_suffix(destination.suffix + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8")
    return {**manifest, "path": str(destination), "manifest_path": str(manifest_path)}
