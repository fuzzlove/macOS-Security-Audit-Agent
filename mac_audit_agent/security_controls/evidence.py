from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .diff_engine import canonical_json
from .models import SecurityControlChangeEvent
from .redaction import redact

SCHEMA_VERSION = 1
GENESIS_DIGEST = "0" * 64


class EvidenceIntegrityError(RuntimeError):
    pass


class EvidenceStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.exists()
        self.connection = sqlite3.connect(str(self.path), timeout=5.0)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self._migrate()
        if not existed:
            try: os.chmod(self.path, 0o600)
            except OSError: pass

    def _migrate(self) -> None:
        with self.connection:
            self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS security_control_schema(version INTEGER NOT NULL, migration_checksum TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS security_control_events(
              sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL,
              occurred_at TEXT NOT NULL, payload_json TEXT NOT NULL, previous_record_digest TEXT NOT NULL,
              record_digest TEXT NOT NULL UNIQUE, segment_id TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS security_control_states(
              control_id TEXT PRIMARY KEY, state_json TEXT NOT NULL, state_digest TEXT NOT NULL, collected_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS security_control_alerts(
              event_id TEXT PRIMARY KEY, severity TEXT NOT NULL, presentation_state TEXT NOT NULL DEFAULT 'queued',
              viewed_at TEXT, acknowledged_at TEXT, occurrence_count INTEGER NOT NULL DEFAULT 1,
              first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, native_status TEXT NOT NULL DEFAULT 'not_requested',
              FOREIGN KEY(event_id) REFERENCES security_control_events(event_id));
            CREATE TABLE IF NOT EXISTS security_control_acknowledgments(
              id INTEGER PRIMARY KEY, event_id TEXT NOT NULL, actor TEXT NOT NULL, reason TEXT NOT NULL,
              previous_status TEXT NOT NULL, new_status TEXT NOT NULL, device_identity TEXT NOT NULL,
              acknowledged_at TEXT NOT NULL, audit_digest TEXT NOT NULL,
              FOREIGN KEY(event_id) REFERENCES security_control_events(event_id));
            CREATE TABLE IF NOT EXISTS security_control_authorizations(
              authorization_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS security_control_incidents(
              incident_id TEXT PRIMARY KEY, status TEXT NOT NULL, event_ids_json TEXT NOT NULL, risk_score REAL NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS security_control_sensor_health(
              id INTEGER PRIMARY KEY, mode TEXT NOT NULL, payload_json TEXT NOT NULL, recorded_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS security_control_delivery(
              id INTEGER PRIMARY KEY, event_id TEXT NOT NULL, stage TEXT NOT NULL, success INTEGER NOT NULL,
              error_code TEXT NOT NULL DEFAULT '', latency_ms REAL, recorded_at TEXT NOT NULL,
              FOREIGN KEY(event_id) REFERENCES security_control_events(event_id));
            CREATE TABLE IF NOT EXISTS security_control_checkpoints(
              segment_id TEXT PRIMARY KEY, record_count INTEGER NOT NULL, head_digest TEXT NOT NULL,
              updated_at TEXT NOT NULL);
            """)
            row = self.connection.execute("SELECT version FROM security_control_schema LIMIT 1").fetchone()
            checksum = hashlib.sha256(b"security-control-schema-v1").hexdigest()
            if row is None: self.connection.execute("INSERT INTO security_control_schema VALUES(?,?)", (SCHEMA_VERSION, checksum))
            elif int(row[0]) != SCHEMA_VERSION: raise EvidenceIntegrityError("SECURITY_CONTROL_SCHEMA_UNSUPPORTED")

    def append_event(self, event: SecurityControlChangeEvent, segment_id: str = "primary") -> str:
        payload = redact(asdict(event)); payload["integrity_digest"] = ""
        payload_json = canonical_json(payload).decode("ascii")
        with self.connection:
            last = self.connection.execute("SELECT record_digest FROM security_control_events ORDER BY sequence DESC LIMIT 1").fetchone()
            previous = str(last[0]) if last else GENESIS_DIGEST
            digest = hashlib.sha256(previous.encode("ascii") + payload_json.encode("ascii")).hexdigest()
            self.connection.execute("INSERT INTO security_control_events(event_id,occurred_at,payload_json,previous_record_digest,record_digest,segment_id,created_at) VALUES(?,?,?,?,?,?,?)", (event.event_id, event.detected_at_utc.isoformat(), payload_json, previous, digest, segment_id, datetime.now(timezone.utc).isoformat()))
            self.connection.execute("INSERT INTO security_control_alerts(event_id,severity,first_seen,last_seen) VALUES(?,?,?,?)", (event.event_id,event.severity,event.first_seen_utc.isoformat(),event.last_seen_utc.isoformat()))
            count=int(self.connection.execute("SELECT COUNT(*) FROM security_control_events WHERE segment_id=?",(segment_id,)).fetchone()[0])
            self.connection.execute("INSERT OR REPLACE INTO security_control_checkpoints(segment_id,record_count,head_digest,updated_at) VALUES(?,?,?,?)",(segment_id,count,digest,datetime.now(timezone.utc).isoformat()))
        return digest

    def verify_chain(self) -> dict[str, Any]:
        previous = GENESIS_DIGEST; count = 0
        for row in self.connection.execute("SELECT sequence,payload_json,previous_record_digest,record_digest FROM security_control_events ORDER BY sequence"):
            expected = hashlib.sha256(previous.encode("ascii") + str(row["payload_json"]).encode("ascii")).hexdigest()
            if row["previous_record_digest"] != previous or row["record_digest"] != expected:
                return {"valid":False,"error_code":"EVIDENCE_CHAIN_MISMATCH","sequence":row["sequence"],"records_verified":count}
            previous = str(row["record_digest"]); count += 1
        checkpoint=self.connection.execute("SELECT record_count,head_digest FROM security_control_checkpoints WHERE segment_id='primary'").fetchone()
        if checkpoint and (int(checkpoint[0])!=count or str(checkpoint[1])!=previous):
            return {"valid":False,"error_code":"EVIDENCE_CHAIN_TRUNCATED_OR_REORDERED","records_verified":count,"head_digest":previous}
        return {"valid":True,"error_code":"","records_verified":count,"head_digest":previous}

    def pending_alerts(self) -> list[dict[str, Any]]:
        rows=self.connection.execute("SELECT e.event_id,e.payload_json,a.severity,a.presentation_state,a.occurrence_count FROM security_control_events e JOIN security_control_alerts a ON a.event_id=e.event_id WHERE a.acknowledged_at IS NULL ORDER BY e.sequence").fetchall()
        return [{"event_id":row["event_id"],"event":json.loads(row["payload_json"]),"severity":row["severity"],"presentation_state":row["presentation_state"],"occurrence_count":row["occurrence_count"]} for row in rows]

    def acknowledge(self, event_id: str, *, actor: str, reason: str, device_identity: str) -> None:
        if not actor.strip() or not reason.strip(): raise ValueError("Acknowledgment requires actor and reason.")
        now=datetime.now(timezone.utc).isoformat(); payload={"event_id":event_id,"actor":actor,"reason":reason,"device":device_identity,"at":now}
        digest=hashlib.sha256(canonical_json(payload)).hexdigest()
        with self.connection:
            row=self.connection.execute("SELECT presentation_state FROM security_control_alerts WHERE event_id=?",(event_id,)).fetchone()
            if row is None: raise KeyError(event_id)
            self.connection.execute("UPDATE security_control_alerts SET presentation_state='acknowledged',acknowledged_at=? WHERE event_id=?",(now,event_id))
            self.connection.execute("INSERT INTO security_control_acknowledgments(event_id,actor,reason,previous_status,new_status,device_identity,acknowledged_at,audit_digest) VALUES(?,?,?,?,?,?,?,?)",(event_id,actor,reason,row[0],"acknowledged",device_identity,now,digest))

    def record_delivery(self,event_id:str,stage:str,success:bool,error_code:str="",latency_ms:float|None=None)->None:
        with self.connection: self.connection.execute("INSERT INTO security_control_delivery(event_id,stage,success,error_code,latency_ms,recorded_at) VALUES(?,?,?,?,?,?)",(event_id,stage,int(success),error_code,latency_ms,datetime.now(timezone.utc).isoformat()))

    def close(self) -> None: self.connection.close()

    def __enter__(self) -> "EvidenceStore": return self
    def __exit__(self,*_args:object)->None: self.close()
