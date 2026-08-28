from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from mac_audit_agent.anti_ransomware.evidence import EvidenceStoreCorruptError, EvidenceStoreDowngradeError, EvidenceStoreMigrationRecoveryError, IncidentRecord, RansomwareEvidenceStore, SCHEMA_VERSION


def incident(identifier="incident-1"):
    return IncidentRecord(identifier, "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", "boot", "endpoint", "critical", "high", 97, "policy-1", "rules-1", "PAUSED", "QUEUED", "2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", user_context={"uid": 501}, responsible_process={"pid": 20}, process_tree=[{"pid": 20}, {"pid": 21}], signals=[{"id": "rapid_encryption"}], affected_file_count=7, affected_directories=("token-a",), affected_volumes=("volume-a",), canary_state="modified", backup_sabotage_state="suspected", tamper_state="not_observed")


def test_complete_incident_persists_across_restart_and_permissions_are_private(tmp_path: Path):
    path = tmp_path / "vault" / "incidents.sqlite3"
    store = RansomwareEvidenceStore(path); store.upsert_incident(incident()); store.close()
    assert os.stat(path).st_mode & 0o777 == 0o600
    reopened = RansomwareEvidenceStore(path)
    row = reopened.connection.execute("SELECT affected_file_count,user_context_json,process_tree_json,canary_state FROM anti_ransomware_incidents WHERE incident_id='incident-1'").fetchone()
    assert row == (7, '{"uid": 501}', '[{"pid": 20}, {"pid": 21}]', "modified")
    assert reopened.integrity_check()
    reopened.close()


def test_v2_upgrade_creates_backup_and_preserves_incident(tmp_path: Path):
    path = tmp_path / "legacy.sqlite3"; connection = sqlite3.connect(path)
    connection.executescript("CREATE TABLE anti_ransomware_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL); INSERT INTO anti_ransomware_meta VALUES('schema_version','2'); CREATE TABLE anti_ransomware_incidents(incident_id TEXT PRIMARY KEY,first_event_time TEXT NOT NULL,last_event_time TEXT NOT NULL,boot_session_id TEXT NOT NULL,endpoint_id TEXT NOT NULL,severity TEXT NOT NULL,confidence TEXT NOT NULL,score INTEGER NOT NULL,policy_version TEXT NOT NULL,ruleset_version TEXT NOT NULL,containment_state TEXT NOT NULL,notification_state TEXT NOT NULL,resolution TEXT NOT NULL DEFAULT '',limitations_json TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,closed_at TEXT);")
    connection.execute("INSERT INTO anti_ransomware_incidents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("legacy", "a", "b", "boot", "endpoint", "high", "high", 80, "p", "r", "OPEN", "QUEUED", "", "[]", "a", "b", None)); connection.commit(); connection.close()
    store = RansomwareEvidenceStore(path)
    assert store.migration_backup and store.migration_backup.exists()
    assert store.connection.execute("SELECT incident_id FROM anti_ransomware_incidents").fetchone()[0] == "legacy"
    assert store.connection.execute("SELECT value FROM anti_ransomware_meta WHERE key='schema_version'").fetchone()[0] == str(SCHEMA_VERSION)
    store.close()


def test_newer_schema_downgrade_is_refused(tmp_path: Path):
    path = tmp_path / "future.sqlite3"; connection = sqlite3.connect(path)
    connection.executescript("CREATE TABLE anti_ransomware_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL); INSERT INTO anti_ransomware_meta VALUES('schema_version','999');"); connection.close()
    with pytest.raises(EvidenceStoreDowngradeError): RansomwareEvidenceStore(path)


def test_corruption_is_preserved_and_refused(tmp_path: Path):
    path = tmp_path / "corrupt.sqlite3"; path.write_bytes(b"not a sqlite database")
    with pytest.raises(EvidenceStoreCorruptError): RansomwareEvidenceStore(path)
    assert path.with_suffix(".sqlite3.corrupt").read_bytes() == b"not a sqlite database"


def test_notification_history_is_sanitized_and_chain_verified(tmp_path: Path):
    store = RansomwareEvidenceStore(tmp_path / "vault.sqlite3"); store.upsert_incident(incident())
    store.record_notification(delivery_id="delivery", incident_id="incident-1", user_id_token="user-token", state="QUEUED", sanitized={"process": "fixture", "redacted_path": "<protected>"}, created_at="2026-01-01T00:00:00Z", updated_at="2026-01-01T00:00:01Z", expires_at="2026-01-01T01:00:00Z")
    assert store.connection.execute("SELECT state FROM anti_ransomware_notification_deliveries").fetchone()[0] == "QUEUED"
    assert store.verify_chain()
    with pytest.raises(ValueError): store.record_notification(delivery_id="bad", incident_id="incident-1", user_id_token="user", state="QUEUED", sanitized={"full_path": "/secret"}, created_at="a", updated_at="b", expires_at="c")
    store.close()


def test_wal_checkpoint_is_bounded_operation(tmp_path: Path):
    store = RansomwareEvidenceStore(tmp_path / "vault.sqlite3")
    for index in range(50): store.upsert_incident(replace(incident(f"incident-{index}"), affected_file_count=index))
    busy, log_frames, checkpointed = store.checkpoint_wal()
    assert busy == 0 and log_frames >= 0 and checkpointed >= 0
    store.close()


def test_incident_update_preserves_dependent_evidence(tmp_path: Path):
    store = RansomwareEvidenceStore(tmp_path / "vault.sqlite3"); store.upsert_incident(incident())
    store.connection.execute("INSERT INTO anti_ransomware_evidence VALUES(?,?,?,?,?,?)", ("e1", "incident-1", "now", "summary", "{}", "x"))
    store.upsert_incident(replace(incident(), containment_state="RESUMED", updated_at="2026-01-01T00:02:00Z"))
    assert store.connection.execute("SELECT containment_state FROM anti_ransomware_incidents").fetchone()[0] == "RESUMED"
    assert store.connection.execute("SELECT count(*) FROM anti_ransomware_evidence WHERE incident_id='incident-1'").fetchone()[0] == 1
    store.close()


def test_concurrent_bounded_writers_commit_without_loss(tmp_path: Path):
    path = tmp_path / "vault.sqlite3"; RansomwareEvidenceStore(path).close()
    def writer(worker):
        store = RansomwareEvidenceStore(path)
        for index in range(25): store.upsert_incident(incident(f"worker-{worker}-{index}"))
        store.close()
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(writer, range(4)))
    store = RansomwareEvidenceStore(path)
    assert store.connection.execute("SELECT count(*) FROM anti_ransomware_incidents").fetchone()[0] == 100
    assert store.integrity_check(); store.close()


def test_interrupted_migration_restores_verified_backup_then_retries(tmp_path: Path):
    path = tmp_path / "vault.sqlite3"; original = RansomwareEvidenceStore(path); original.upsert_incident(incident()); original.close()
    backup = path.with_suffix(".sqlite3.pre-v3.bak"); backup.write_bytes(path.read_bytes())
    connection = sqlite3.connect(path); connection.execute("UPDATE anti_ransomware_meta SET value='999' WHERE key='schema_version'"); connection.commit(); connection.close()
    marker = path.with_suffix(".sqlite3.migration.json")
    marker.write_text('{"backup":"vault.sqlite3.pre-v3.bak","from_version":2,"to_version":3}', encoding="utf-8")
    recovered = RansomwareEvidenceStore(path)
    assert recovered.connection.execute("SELECT incident_id FROM anti_ransomware_incidents").fetchone()[0] == "incident-1"
    assert not marker.exists() and recovered.integrity_check(); recovered.close()


def test_interrupted_migration_refuses_missing_backup(tmp_path: Path):
    path = tmp_path / "vault.sqlite3"; path.write_bytes(b"placeholder")
    path.with_suffix(".sqlite3.migration.json").write_text('{"backup":"missing.bak","from_version":2,"to_version":3}', encoding="utf-8")
    with pytest.raises(EvidenceStoreMigrationRecoveryError): RansomwareEvidenceStore(path)


def test_database_full_rolls_back_transaction_without_partial_incident(tmp_path: Path):
    store = RansomwareEvidenceStore(tmp_path / "vault.sqlite3")
    page_count = store.connection.execute("PRAGMA page_count").fetchone()[0]
    store.connection.execute(f"PRAGMA max_page_count={page_count}")
    huge = replace(incident("too-large"), signals=[{"padding": "x" * 2_000_000}])
    with pytest.raises(sqlite3.OperationalError, match="full"):
        store.upsert_incident(huge)
    assert store.connection.execute("SELECT count(*) FROM anti_ransomware_incidents WHERE incident_id='too-large'").fetchone()[0] == 0
    assert store.integrity_check(); store.close()


def test_locked_database_fails_bounded_then_recovers(tmp_path: Path):
    path = tmp_path / "vault.sqlite3"; first = RansomwareEvidenceStore(path); second = RansomwareEvidenceStore(path)
    second.connection.execute("PRAGMA busy_timeout=25")
    first.connection.execute("BEGIN EXCLUSIVE")
    with pytest.raises(sqlite3.OperationalError, match="locked"):
        second.upsert_incident(incident("locked"))
    first.connection.rollback()
    second.upsert_incident(incident("recovered"))
    assert second.connection.execute("SELECT incident_id FROM anti_ransomware_incidents").fetchone()[0] == "recovered"
    first.close(); second.close()


def test_read_only_vault_refuses_writes(tmp_path: Path):
    path = tmp_path / "vault.sqlite3"; store = RansomwareEvidenceStore(path); store.close(); os.chmod(path, 0o400)
    readonly = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        readonly.execute("DELETE FROM anti_ransomware_incidents")
    readonly.close(); os.chmod(path, 0o600)


def test_user_notifier_queue_has_no_protected_vault_dependency():
    source = (Path(__file__).resolve().parents[2] / "mac_audit_agent/anti_ransomware/notifier_channel.py").read_text(encoding="utf-8")
    assert "RansomwareEvidenceStore" not in source
    assert "anti_ransomware_incidents" not in source
    assert "sqlite3" not in source
