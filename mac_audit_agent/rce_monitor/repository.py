from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from .models import Disposition, EventType, RCEEvent, ReviewState, utc_now


class RCERepository:
    SCHEMA_VERSION = 3

    def __init__(self, database: Path | sqlite3.Connection) -> None:
        self.path = None if isinstance(database, sqlite3.Connection) else Path(database)
        self.conn = database if isinstance(database, sqlite3.Connection) else sqlite3.connect(str(self.path), timeout=10)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.migrate()

    def migrate(self) -> None:
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS rce_schema(version INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS rce_events(
          event_id TEXT PRIMARY KEY, group_id TEXT NOT NULL, event_type TEXT NOT NULL,
          observed_at TEXT NOT NULL, first_observed_at TEXT NOT NULL, last_observed_at TEXT NOT NULL,
          severity TEXT NOT NULL, confidence TEXT NOT NULL, review_state TEXT NOT NULL,
          disposition TEXT NOT NULL DEFAULT '', occurrence_count INTEGER NOT NULL DEFAULT 1,
          suppressed INTEGER NOT NULL DEFAULT 0, payload_json TEXT NOT NULL,
          previous_digest TEXT NOT NULL, record_digest TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_rce_events_time ON rce_events(observed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_rce_events_group ON rce_events(group_id,last_observed_at DESC);
        CREATE TABLE IF NOT EXISTS rce_raw_evidence(
          evidence_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,observed_at TEXT NOT NULL,content_hash TEXT NOT NULL,
          redacted_payload_json TEXT NOT NULL,FOREIGN KEY(event_id) REFERENCES rce_events(event_id)
        );
        CREATE TABLE IF NOT EXISTS rce_review_history(
          review_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,reviewer_reference TEXT NOT NULL,reviewed_at TEXT NOT NULL,
          previous_state TEXT NOT NULL,new_state TEXT NOT NULL,reason TEXT NOT NULL,case_reference TEXT NOT NULL DEFAULT '',
          evidence_json TEXT NOT NULL DEFAULT '[]',expires_at TEXT NOT NULL DEFAULT '',suppression_created INTEGER NOT NULL DEFAULT 0,
          FOREIGN KEY(event_id) REFERENCES rce_events(event_id)
        );
        CREATE TABLE IF NOT EXISTS rce_suppressions(
          suppression_id TEXT PRIMARY KEY,owner_reference TEXT NOT NULL,reason TEXT NOT NULL,matcher_json TEXT NOT NULL,
          created_at TEXT NOT NULL,expires_at TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,broad INTEGER NOT NULL DEFAULT 0,
          occurrence_count INTEGER NOT NULL DEFAULT 0,last_match_at TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS rce_cve_records(
          cve_id TEXT PRIMARY KEY,source_name TEXT NOT NULL,source_record_id TEXT NOT NULL,retrieved_at TEXT NOT NULL,
          published_at TEXT NOT NULL,last_modified_at TEXT NOT NULL,format_version TEXT NOT NULL,content_hash TEXT NOT NULL,
          parser_version TEXT NOT NULL,validation_status TEXT NOT NULL,expires_at TEXT NOT NULL,payload_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rce_health_events(
          health_id TEXT PRIMARY KEY,event_type TEXT NOT NULL,observed_at TEXT NOT NULL,sensor TEXT NOT NULL,status TEXT NOT NULL,
          reason_code TEXT NOT NULL,details TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rce_reason_evidence(
          reason_evidence_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,reason_code TEXT NOT NULL,description TEXT NOT NULL,
          telemetry_source TEXT NOT NULL,observed_at TEXT NOT NULL,confidence_contribution INTEGER NOT NULL,
          evidence_reference TEXT NOT NULL,payload_json TEXT NOT NULL,FOREIGN KEY(event_id) REFERENCES rce_events(event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_rce_reason_event ON rce_reason_evidence(event_id,observed_at);
        CREATE TABLE IF NOT EXISTS rce_exploit_primitives(
          primitive_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,category TEXT NOT NULL,observed_at TEXT NOT NULL,
          telemetry_source TEXT NOT NULL,confidence TEXT NOT NULL,process_id INTEGER,evidence_reference TEXT NOT NULL,
          payload_json TEXT NOT NULL,FOREIGN KEY(event_id) REFERENCES rce_events(event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_rce_primitive_event ON rce_exploit_primitives(event_id,observed_at);
        CREATE TABLE IF NOT EXISTS rce_timeline_events(
          timeline_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,observed_at TEXT NOT NULL,event_type TEXT NOT NULL,
          summary TEXT NOT NULL,source TEXT NOT NULL,evidence_reference TEXT NOT NULL,
          FOREIGN KEY(event_id) REFERENCES rce_events(event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_rce_timeline_event ON rce_timeline_events(event_id,observed_at);
        CREATE TABLE IF NOT EXISTS rce_processes(
          process_record_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,relationship TEXT NOT NULL,pid INTEGER,ppid INTEGER,
          executable TEXT NOT NULL,sha256 TEXT NOT NULL,signing_status TEXT NOT NULL,team_id TEXT NOT NULL,
          bundle_id TEXT NOT NULL,payload_json TEXT NOT NULL,FOREIGN KEY(event_id) REFERENCES rce_events(event_id)
        );
        CREATE TABLE IF NOT EXISTS rce_memory_indicators(
          memory_indicator_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,indicator_type TEXT NOT NULL,observed_at TEXT NOT NULL,
          payload_json TEXT NOT NULL,FOREIGN KEY(event_id) REFERENCES rce_events(event_id)
        );
        CREATE TABLE IF NOT EXISTS rce_file_events(
          file_event_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,observed_at TEXT NOT NULL,path TEXT NOT NULL,
          action TEXT NOT NULL,payload_json TEXT NOT NULL,FOREIGN KEY(event_id) REFERENCES rce_events(event_id)
        );
        CREATE TABLE IF NOT EXISTS rce_network_events(
          network_event_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,observed_at TEXT NOT NULL,remote_address TEXT NOT NULL,
          remote_port TEXT NOT NULL,protocol TEXT NOT NULL,payload_json TEXT NOT NULL,FOREIGN KEY(event_id) REFERENCES rce_events(event_id)
        );
        CREATE TABLE IF NOT EXISTS rce_cve_correlations(
          correlation_record_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,cve_id TEXT NOT NULL,relationship_type TEXT NOT NULL,
          confidence TEXT NOT NULL,similarity INTEGER NOT NULL DEFAULT 0,payload_json TEXT NOT NULL,
          FOREIGN KEY(event_id) REFERENCES rce_events(event_id)
        );
        CREATE TABLE IF NOT EXISTS rce_sensor_coverage(
          coverage_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,sensor TEXT NOT NULL,state TEXT NOT NULL,
          observed_at TEXT NOT NULL,FOREIGN KEY(event_id) REFERENCES rce_events(event_id)
        );
        CREATE TABLE IF NOT EXISTS rce_analyst_dispositions(
          disposition_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,analyst_reference TEXT NOT NULL,recorded_at TEXT NOT NULL,
          original_classification TEXT NOT NULL,original_score INTEGER NOT NULL,analyst_classification TEXT NOT NULL,
          reason TEXT NOT NULL,evidence_reference TEXT NOT NULL,FOREIGN KEY(event_id) REFERENCES rce_events(event_id)
        );
        CREATE TABLE IF NOT EXISTS rce_crash_signatures(
          signature TEXT PRIMARY KEY,event_id TEXT NOT NULL,first_observed_at TEXT NOT NULL,last_observed_at TEXT NOT NULL,
          occurrence_count INTEGER NOT NULL DEFAULT 1,payload_json TEXT NOT NULL,FOREIGN KEY(event_id) REFERENCES rce_events(event_id)
        );
        CREATE TABLE IF NOT EXISTS rce_ingest_spool(
          ingestion_id TEXT PRIMARY KEY,observed_at TEXT NOT NULL,sensor TEXT NOT NULL,status TEXT NOT NULL,
          content_hash TEXT NOT NULL,payload_json TEXT NOT NULL,error_type TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_rce_ingest_status ON rce_ingest_spool(status,observed_at);
        CREATE TABLE IF NOT EXISTS process_injection_primitives(
          primitive_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,graph_id TEXT NOT NULL,observed_at TEXT NOT NULL,
          source_process_id TEXT NOT NULL,target_process_id TEXT NOT NULL,primitive TEXT NOT NULL,sensor TEXT NOT NULL,
          sensor_reliability TEXT NOT NULL,raw_reference TEXT NOT NULL,payload_json TEXT NOT NULL,
          FOREIGN KEY(event_id) REFERENCES rce_events(event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_pi_primitives_graph ON process_injection_primitives(graph_id,observed_at);
        CREATE TABLE IF NOT EXISTS process_injection_research(
          candidate_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,nearest_technique TEXT NOT NULL,similarity_score INTEGER NOT NULL,
          novelty_score INTEGER NOT NULL,evidence_completeness INTEGER NOT NULL,independent_observations INTEGER NOT NULL DEFAULT 1,
          affected_hosts INTEGER NOT NULL DEFAULT 1,first_observed_at TEXT NOT NULL,last_observed_at TEXT NOT NULL,
          research_state TEXT NOT NULL,payload_json TEXT NOT NULL,FOREIGN KEY(event_id) REFERENCES rce_events(event_id)
        );
        CREATE TABLE IF NOT EXISTS process_injection_benign_contexts(
          catalog_record_id TEXT PRIMARY KEY,tool_name TEXT NOT NULL,publisher TEXT NOT NULL,signer TEXT NOT NULL,
          package_identity TEXT NOT NULL,approved_hashes_json TEXT NOT NULL,version_range_json TEXT NOT NULL,
          paths_json TEXT NOT NULL,source_conditions_json TEXT NOT NULL,target_conditions_json TEXT NOT NULL,
          expected_primitives_json TEXT NOT NULL,owner_reference TEXT NOT NULL,approval_reference TEXT NOT NULL,
          created_at TEXT NOT NULL,reviewed_at TEXT NOT NULL,expires_at TEXT NOT NULL,reviewer_reference TEXT NOT NULL,
          evidence_json TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1,occurrence_count INTEGER NOT NULL DEFAULT 0,last_observed_at TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS process_injection_evidence_bundles(
          bundle_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,case_id TEXT NOT NULL,created_at TEXT NOT NULL,capture_tier INTEGER NOT NULL,
          classification TEXT NOT NULL,retention_expires_at TEXT NOT NULL,manifest_path TEXT NOT NULL,manifest_hash TEXT NOT NULL,
          encryption_status TEXT NOT NULL,verification_status TEXT NOT NULL,collection_failures_json TEXT NOT NULL,
          FOREIGN KEY(event_id) REFERENCES rce_events(event_id)
        );
        CREATE TABLE IF NOT EXISTS process_injection_access_audit(
          audit_id TEXT PRIMARY KEY,occurred_at TEXT NOT NULL,actor_reference TEXT NOT NULL,action TEXT NOT NULL,
          object_reference TEXT NOT NULL,outcome TEXT NOT NULL,reason TEXT NOT NULL
        );
        """)
        suppression_columns={row[1] for row in self.conn.execute("PRAGMA table_info(rce_suppressions)").fetchall()}
        for name,declaration in (("reviewer_reference","TEXT NOT NULL DEFAULT ''"),("rule_version","TEXT NOT NULL DEFAULT '1.0'"),("host_scope","TEXT NOT NULL DEFAULT ''"),("audit_json","TEXT NOT NULL DEFAULT '[]'")):
            if name not in suppression_columns:self.conn.execute(f"ALTER TABLE rce_suppressions ADD COLUMN {name} {declaration}")
        row = self.conn.execute("SELECT version FROM rce_schema LIMIT 1").fetchone()
        if row is None:
            self.conn.execute("INSERT INTO rce_schema(version) VALUES(?)", (self.SCHEMA_VERSION,))
        elif int(row[0]) in {1, 2}:
            self.conn.execute("UPDATE rce_schema SET version=?",(self.SCHEMA_VERSION,))
        elif int(row[0]) != self.SCHEMA_VERSION:
            raise RuntimeError("unsupported RCE database schema")
        self.conn.commit()

    @staticmethod
    def _canonical(payload: dict[str, Any]) -> str:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def store_event(self, event: RCEEvent, *, raw_payload: dict[str, Any] | None = None, max_representatives: int = 20) -> str:
        payload = event.to_dict()
        with self.conn:
            prior = self.conn.execute("SELECT event_id,payload_json,occurrence_count,severity FROM rce_events WHERE group_id=? ORDER BY last_observed_at DESC LIMIT 1", (event.group_id,)).fetchone()
            prior_payload = json.loads(prior["payload_json"]) if prior else {}
            severity_rank = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            material_escalation = bool(prior and (
                event.confidence_score > int(prior_payload.get("confidence_score", 0) or 0) + 9
                or severity_rank.get(event.severity, 0) > severity_rank.get(str(prior["severity"]), 0)
                or event.rce_classification != str(prior_payload.get("rce_classification", "")) and event.event_type == EventType.SUSPECTED.value
            ))
            if prior and not material_escalation:
                occurrence = int(prior["occurrence_count"]) + 1
                # The chained first-occurrence payload stays immutable. Mutable
                # grouping counters live in separate columns; every occurrence
                # can still retain a separately hashed raw evidence row.
                self.conn.execute("UPDATE rce_events SET last_observed_at=?,occurrence_count=?,updated_at=? WHERE event_id=?", (event.last_observed_at, occurrence, utc_now(), prior["event_id"]))
                event_id = str(prior["event_id"])
            else:
                previous = self.conn.execute("SELECT record_digest FROM rce_events ORDER BY rowid DESC LIMIT 1").fetchone()
                previous_digest = str(previous[0]) if previous else "0" * 64
                digest_payload = dict(payload); digest_payload["previous_digest"] = previous_digest
                record_digest = hashlib.sha256(self._canonical(digest_payload).encode()).hexdigest()
                self.conn.execute("INSERT INTO rce_events(event_id,group_id,event_type,observed_at,first_observed_at,last_observed_at,severity,confidence,review_state,disposition,payload_json,previous_digest,record_digest,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (event.event_id,event.group_id,event.event_type,event.observed_at,event.first_observed_at,event.last_observed_at,event.severity,event.confidence,event.review_state,event.disposition,self._canonical(payload),previous_digest,record_digest,event.created_at,event.updated_at))
                event_id = event.event_id
            if raw_payload is not None:
                canonical = self._canonical(raw_payload)
                content_hash = hashlib.sha256(canonical.encode()).hexdigest()
                representative_count = int(self.conn.execute("SELECT COUNT(*) FROM rce_raw_evidence WHERE event_id=?", (event_id,)).fetchone()[0])
                duplicate = self.conn.execute("SELECT 1 FROM rce_raw_evidence WHERE event_id=? AND content_hash=? LIMIT 1", (event_id, content_hash)).fetchone()
                if representative_count < max(1, min(int(max_representatives), 100)) and duplicate is None:
                    self.conn.execute("INSERT INTO rce_raw_evidence(evidence_id,event_id,observed_at,content_hash,redacted_payload_json) VALUES(?,?,?,?,?)", (f"rce-raw-{uuid4()}",event_id,event.observed_at,content_hash,canonical))
            self._store_normalized(event_id, event)
        return event_id

    def _store_normalized(self, event_id: str, event: RCEEvent) -> None:
        for item in event.reason_evidence:
            payload = asdict(item)
            identity = self._stable_id("reason", event_id, payload)
            self.conn.execute("INSERT OR IGNORE INTO rce_reason_evidence VALUES(?,?,?,?,?,?,?,?,?)", (identity,event_id,item.code,item.description,item.telemetry_source,item.observed_at,item.confidence_contribution,item.evidence_reference,self._canonical(payload)))
        for item in event.exploit_primitives:
            payload = asdict(item)
            identity = self._stable_id("primitive", event_id, payload)
            self.conn.execute("INSERT OR IGNORE INTO rce_exploit_primitives VALUES(?,?,?,?,?,?,?,?,?)", (identity,event_id,item.category,item.observed_at,item.telemetry_source,item.confidence,item.process_id,item.evidence_reference,self._canonical(payload)))
        for item in event.timeline:
            payload = asdict(item)
            identity = self._stable_id("timeline", event_id, payload)
            self.conn.execute("INSERT OR IGNORE INTO rce_timeline_events VALUES(?,?,?,?,?,?,?)", (identity,event_id,item.timestamp,item.event_type,item.summary,item.source,item.evidence_reference))
        processes = [("target", event.process), ("parent", event.parent_process), ("source", event.source_process), *[(f"ancestor_{index}", item) for index, item in enumerate(event.process_ancestry[:16])]]
        for relationship, process in processes:
            if not process:
                continue
            identity = self._stable_id("process", event_id, {"relationship": relationship, **process})
            self.conn.execute("INSERT OR IGNORE INTO rce_processes VALUES(?,?,?,?,?,?,?,?,?,?,?)", (identity,event_id,relationship,process.get("pid"),process.get("ppid"),str(process.get("executable") or process.get("path") or ""),str(process.get("sha256", "")),str(process.get("signing_status", "")),str(process.get("team_id") or process.get("teamID") or ""),str(process.get("bundle_id", "")),self._canonical(process)))
        for primitive in event.exploit_primitives:
            if primitive.category not in {"memory_corruption", "stack_corruption", "heap_corruption", "control_flow_anomaly", "executable_memory", "write_then_execute"}:
                continue
            payload = asdict(primitive)
            identity = self._stable_id("memory", event_id, payload)
            self.conn.execute("INSERT OR IGNORE INTO rce_memory_indicators VALUES(?,?,?,?,?)", (identity,event_id,primitive.category,primitive.observed_at,self._canonical(payload)))
        if event.file_context:
            identity = self._stable_id("file", event_id, {"time": event.observed_at, **event.file_context})
            self.conn.execute("INSERT OR IGNORE INTO rce_file_events VALUES(?,?,?,?,?,?)", (identity,event_id,event.observed_at,str(event.file_context.get("path", "")),str(event.file_context.get("action") or event.file_context.get("event_type") or "observed"),self._canonical(event.file_context)))
        if event.network_context:
            identity = self._stable_id("network", event_id, {"time": event.observed_at, **event.network_context})
            self.conn.execute("INSERT OR IGNORE INTO rce_network_events VALUES(?,?,?,?,?,?,?)", (identity,event_id,event.observed_at,str(event.network_context.get("remote_address") or event.network_context.get("destination") or ""),str(event.network_context.get("remote_port", "")),str(event.network_context.get("protocol", "")),self._canonical(event.network_context)))
        for item in event.cve_correlations:
            payload = asdict(item)
            identity = self._stable_id("cve", event_id, payload)
            similarity = int(item.similarity_percent)
            self.conn.execute("INSERT OR IGNORE INTO rce_cve_correlations VALUES(?,?,?,?,?,?,?)", (identity,event_id,item.cve_id,item.relationship_type,item.confidence,similarity,self._canonical(payload)))
        for sensor, state in event.sensor_coverage.items():
            identity = self._stable_id("coverage", event_id, {"sensor": sensor, "state": state, "time": event.observed_at})
            self.conn.execute("INSERT OR IGNORE INTO rce_sensor_coverage VALUES(?,?,?,?,?)", (identity,event_id,str(sensor),str(state),event.observed_at))
        if event.memory_context:
            signature_material = {
                "binary": event.process.get("sha256") or event.process.get("executable"),
                "exception": event.memory_context.get("exception_type"),
                "signal": event.memory_context.get("exception_signal") or event.memory_context.get("signal"),
                "module": event.memory_context.get("faulting_module"),
                "instruction": event.memory_context.get("instruction_pointer"),
                "stack": event.memory_context.get("stack_signature"),
                "crash": event.memory_context.get("crash_signature"),
            }
            signature = hashlib.sha256(self._canonical(signature_material).encode()).hexdigest()
            prior = self.conn.execute("SELECT occurrence_count FROM rce_crash_signatures WHERE signature=?", (signature,)).fetchone()
            if prior:
                self.conn.execute("UPDATE rce_crash_signatures SET last_observed_at=?,occurrence_count=occurrence_count+1 WHERE signature=?", (event.observed_at, signature))
            else:
                self.conn.execute("INSERT INTO rce_crash_signatures VALUES(?,?,?,?,?,?)", (signature,event_id,event.observed_at,event.observed_at,1,self._canonical(signature_material)))

    def _stable_id(self, prefix: str, event_id: str, payload: dict[str, Any]) -> str:
        digest = hashlib.sha256(f"{event_id}|{self._canonical(payload)}".encode()).hexdigest()[:28]
        return f"rce-{prefix}-{digest}"

    def store_raw_observation(self, payload: dict[str, Any], *, observed_at: str, sensor: str, maximum_rows: int = 10_000) -> str:
        canonical = self._canonical(payload)
        ingestion_id = f"rce-ingest-{uuid4()}"
        with self.conn:
            self.conn.execute("INSERT INTO rce_ingest_spool(ingestion_id,observed_at,sensor,status,content_hash,payload_json,created_at) VALUES(?,?,?,?,?,?,?)", (ingestion_id,observed_at,sensor,"STORED",hashlib.sha256(canonical.encode()).hexdigest(),canonical,utc_now()))
            excess = int(self.conn.execute("SELECT MAX(0,COUNT(*)-?) FROM rce_ingest_spool", (max(100, min(maximum_rows, 100_000)),)).fetchone()[0])
            if excess:
                self.conn.execute("DELETE FROM rce_ingest_spool WHERE ingestion_id IN (SELECT ingestion_id FROM rce_ingest_spool ORDER BY observed_at LIMIT ?)", (excess,))
        return ingestion_id

    def complete_raw_observation(self, ingestion_id: str, *, status: str, error_type: str = "") -> None:
        with self.conn:
            self.conn.execute("UPDATE rce_ingest_spool SET status=?,error_type=? WHERE ingestion_id=?", (status[:32],error_type[:128],ingestion_id))

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT event_id,event_type,observed_at,last_observed_at,severity,confidence,review_state,disposition,occurrence_count,suppressed FROM rce_events ORDER BY last_observed_at DESC LIMIT ?", (max(1,min(limit,1000)),)).fetchall()
        return [dict(row) for row in rows]

    def event_detail(self, event_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM rce_events WHERE event_id=?", (event_id,)).fetchone()
        if not row: return None
        result = json.loads(row["payload_json"])
        result.update({"occurrence_count": row["occurrence_count"], "suppressed": bool(row["suppressed"]), "record_digest": row["record_digest"], "review_state": row["review_state"], "disposition": row["disposition"]})
        result["disposition_history"] = [dict(item) for item in self.conn.execute("SELECT * FROM rce_review_history WHERE event_id=? ORDER BY reviewed_at", (event_id,)).fetchall()]
        result["raw_evidence"] = [dict(item) for item in self.conn.execute("SELECT evidence_id,observed_at,content_hash FROM rce_raw_evidence WHERE event_id=? ORDER BY observed_at", (event_id,)).fetchall()]
        result["reason_evidence"] = [dict(item) for item in self.conn.execute("SELECT reason_code AS code,description,telemetry_source,observed_at,confidence_contribution,evidence_reference FROM rce_reason_evidence WHERE event_id=? ORDER BY observed_at", (event_id,)).fetchall()]
        result["exploit_primitives"] = [json.loads(item[0]) for item in self.conn.execute("SELECT payload_json FROM rce_exploit_primitives WHERE event_id=? ORDER BY observed_at", (event_id,)).fetchall()]
        result["timeline"] = [dict(item) for item in self.conn.execute("SELECT observed_at AS timestamp,event_type,summary,source,evidence_reference FROM rce_timeline_events WHERE event_id=? ORDER BY observed_at", (event_id,)).fetchall()]
        result["sensor_coverage"] = {str(item["sensor"]): str(item["state"]) for item in self.conn.execute("SELECT sensor,state FROM rce_sensor_coverage WHERE event_id=?", (event_id,)).fetchall()}
        return result

    def disposition(self, event_id: str, new_state: str, *, reviewer: str, reason: str, authorized: bool, case_reference: str = "") -> None:
        if not authorized or not reviewer.strip(): raise PermissionError("authorized reviewer identity is required")
        if not reason.strip(): raise ValueError("a disposition reason is required")
        disposition = Disposition(new_state)
        if disposition in {Disposition.FALSE_POSITIVE,Disposition.BENIGN_AUTHORIZED_INSTRUMENTATION,Disposition.EXPECTED_ADMINISTRATIVE_ACTIVITY,Disposition.BENIGN_SOFTWARE_BEHAVIOR,Disposition.FUZZING_TEST_ACTIVITY,Disposition.DEBUGGER_ACTIVITY} and not case_reference.strip():
            raise ValueError("benign or false-positive dispositions require supporting case or evidence reference")
        row = self.conn.execute("SELECT review_state,payload_json FROM rce_events WHERE event_id=?", (event_id,)).fetchone()
        if not row: raise KeyError(event_id)
        review_state = ReviewState.OPEN.value if disposition == Disposition.REOPENED else ReviewState.INVESTIGATING.value
        updated_at = utc_now()
        with self.conn:
            # Review decisions are intentionally separate from the immutable,
            # chained observed-evidence payload.
            self.conn.execute("UPDATE rce_events SET review_state=?,disposition=?,updated_at=? WHERE event_id=?", (review_state,disposition.value,updated_at,event_id))
            self.conn.execute("INSERT INTO rce_review_history(review_id,event_id,reviewer_reference,reviewed_at,previous_state,new_state,reason,case_reference) VALUES(?,?,?,?,?,?,?,?)", (f"review-{uuid4()}",event_id,reviewer,utc_now(),row["review_state"],disposition.value,reason,case_reference))
            payload = json.loads(row["payload_json"])
            self.conn.execute("INSERT INTO rce_analyst_dispositions VALUES(?,?,?,?,?,?,?,?,?)", (f"rce-disposition-{uuid4()}",event_id,reviewer,updated_at,str(payload.get("original_classification") or payload.get("rce_classification", "")),int(payload.get("original_confidence_score") or payload.get("confidence_score", 0)),disposition.value,reason,case_reference))

    def create_suppression(self, matcher: dict[str, str], *, owner: str, reason: str, expires_at: str, authorized: bool, elevated: bool = False,reviewer:str="",rule_version:str="1.0",host_scope:str="") -> str:
        if not authorized: raise PermissionError("authorized reviewer required")
        if not owner.strip() or not reason.strip() or not expires_at: raise ValueError("owner, reason, and expiration are required")
        broad = any(value == "*" for value in matcher.values()) or not matcher
        if broad and not elevated: raise PermissionError("broad suppression requires elevated authorization")
        suppression_id = f"suppression-{uuid4()}"
        with self.conn:
            now=utc_now(); audit=self._canonical([{"timestamp":now,"action":"created","reviewer":reviewer or owner,"reason":reason}])
            self.conn.execute("INSERT INTO rce_suppressions(suppression_id,owner_reference,reason,matcher_json,created_at,expires_at,broad,reviewer_reference,rule_version,host_scope,audit_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (suppression_id,owner,reason,self._canonical(matcher),now,expires_at,int(broad),reviewer or owner,rule_version,host_scope,audit))
        return suppression_id

    def record_health(self, event: RCEEvent, reason_code: str) -> None:
        with self.conn:
            self.conn.execute("INSERT INTO rce_health_events VALUES(?,?,?,?,?,?,?)", (f"health-{uuid4()}",event.event_type,event.observed_at,event.source_sensor,event.sensor_health,reason_code,"; ".join(event.observed_behavior)[:2048]))
        self.store_event(event)

    def status(self) -> dict[str, Any]:
        latest = self.conn.execute("SELECT observed_at,event_type,status,reason_code FROM rce_health_events ORDER BY observed_at DESC LIMIT 1").fetchone()
        count = self.conn.execute("SELECT COUNT(*) FROM rce_events").fetchone()[0]
        ingest = {str(row["status"]): int(row["count"]) for row in self.conn.execute("SELECT status,COUNT(*) AS count FROM rce_ingest_spool GROUP BY status").fetchall()}
        return {"schema_version": self.SCHEMA_VERSION,"event_count": count,"latest_health": dict(latest) if latest else {},"state": "NO_DATA" if not latest and count == 0 else "ACTIVE_DEGRADED","raw_observations":sum(ingest.values()),"ingest_status":ingest,"parser_failures":ingest.get("ENRICHMENT_FAILED",0),"crash_signature_count":int(self.conn.execute("SELECT COUNT(*) FROM rce_crash_signatures").fetchone()[0])}

    def verify_chain(self) -> tuple[bool, str]:
        previous = "0" * 64
        rows = self.conn.execute("SELECT payload_json,previous_digest,record_digest FROM rce_events ORDER BY rowid").fetchall()
        for index,row in enumerate(rows,1):
            if row["previous_digest"] != previous: return False, f"chain link mismatch at record {index}"
            payload = json.loads(row["payload_json"]); digest_payload = dict(payload); digest_payload["previous_digest"] = previous
            actual = hashlib.sha256(self._canonical(digest_payload).encode()).hexdigest()
            if actual != row["record_digest"]: return False, f"record digest mismatch at record {index}"
            previous = actual
        return True, "verified"

    def management_authorized(self, allowed_uids: tuple[int, ...]) -> bool:
        return os.geteuid() in allowed_uids

    def store_injection_analysis(self,event_id:str,analysis:dict[str,Any],*,host_id:str="local")->str:
        behavioral=dict(analysis.get("behavioral_analysis",{})); graph=dict(behavioral.get("graph",{})); graph_id=str(graph.get("graph_id", ""))
        with self.conn:
            for edge in graph.get("edges",[]):
                primitive_id="primitive-"+hashlib.sha256(self._canonical(edge).encode()).hexdigest()[:24]
                self.conn.execute("INSERT OR IGNORE INTO process_injection_primitives VALUES(?,?,?,?,?,?,?,?,?,?,?)",(primitive_id,event_id,graph_id,str(edge.get("observed_at","")),str(edge.get("source","")),str(edge.get("target","")),str(edge.get("relationship","")),str(edge.get("sensor","")),str(edge.get("sensor_reliability","unknown")),str(edge.get("raw_reference","")),self._canonical(edge)))
            if behavioral.get("research_required"):
                year=(str(graph.get("first_observed_at",""))[:4] or datetime.now(timezone.utc).strftime("%Y")); prefix=f"MSAA-PI-{year}-"
                existing=self.conn.execute("SELECT candidate_id,event_id,independent_observations FROM process_injection_research WHERE payload_json=?",(self._canonical(behavioral),)).fetchone()
                if existing:
                    candidate_id=str(existing["candidate_id"]); self.conn.execute("UPDATE process_injection_research SET independent_observations=independent_observations+1,last_observed_at=? WHERE candidate_id=?",(str(graph.get("last_observed_at","")),candidate_id))
                else:
                    sequence=int(self.conn.execute("SELECT COUNT(*) FROM process_injection_research WHERE candidate_id LIKE ?",(prefix+"%",)).fetchone()[0])+1; candidate_id=f"{prefix}{sequence:04d}"
                    nearest=dict(behavioral.get("nearest_known_technique",{})); self.conn.execute("INSERT INTO process_injection_research(candidate_id,event_id,nearest_technique,similarity_score,novelty_score,evidence_completeness,first_observed_at,last_observed_at,research_state,payload_json) VALUES(?,?,?,?,?,?,?,?,?,?)",(candidate_id,event_id,str(nearest.get("technique_name","")),int(nearest.get("similarity_score",0)),int(behavioral.get("novelty_score",0)),int(behavioral.get("evidence_completeness",0)),str(graph.get("first_observed_at","")),str(graph.get("last_observed_at","")),"TRIAGE_REQUIRED",self._canonical(behavioral)))
                return candidate_id
        return ""

    def list_research(self)->list[dict[str,Any]]:
        return [dict(row) for row in self.conn.execute("SELECT candidate_id,event_id,nearest_technique,similarity_score,novelty_score,evidence_completeness,independent_observations,affected_hosts,first_observed_at,last_observed_at,research_state FROM process_injection_research ORDER BY last_observed_at DESC").fetchall()]

    def create_benign_context(self,record:dict[str,Any],*,authorized:bool)->str:
        if not authorized: raise PermissionError("authorized reviewer required")
        required=("tool_name","publisher","signer","owner_reference","approval_reference","expires_at","reviewer_reference","expected_primitives","evidence")
        if any(not record.get(key) for key in required): raise ValueError("benign context is incomplete")
        context_id=str(record.get("catalog_record_id") or f"benign-{uuid4()}"); now=utc_now()
        with self.conn:self.conn.execute("INSERT INTO process_injection_benign_contexts(catalog_record_id,tool_name,publisher,signer,package_identity,approved_hashes_json,version_range_json,paths_json,source_conditions_json,target_conditions_json,expected_primitives_json,owner_reference,approval_reference,created_at,reviewed_at,expires_at,reviewer_reference,evidence_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(context_id,str(record["tool_name"]),str(record["publisher"]),str(record["signer"]),str(record.get("package_identity","")),self._canonical(record.get("approved_hashes",[])),self._canonical(record.get("version_range",{})),self._canonical(record.get("paths",[])),self._canonical(record.get("source_conditions",{})),self._canonical(record.get("target_conditions",{})),self._canonical(record["expected_primitives"]),str(record["owner_reference"]),str(record["approval_reference"]),now,now,str(record["expires_at"]),str(record["reviewer_reference"]),self._canonical(record["evidence"])))
        return context_id

    def list_benign_contexts(self)->list[dict[str,Any]]:
        output=[]
        for row in self.conn.execute("SELECT * FROM process_injection_benign_contexts WHERE enabled=1").fetchall():
            item=dict(row); item["expected_primitives"]=json.loads(item.pop("expected_primitives_json")); output.append(item)
        return output

    def audit_access(self,actor:str,action:str,object_reference:str,outcome:str,reason:str="")->None:
        with self.conn:self.conn.execute("INSERT INTO process_injection_access_audit VALUES(?,?,?,?,?,?,?)",(f"pi-audit-{uuid4()}",utc_now(),actor,action,object_reference,outcome,reason))
