from __future__ import annotations

import hashlib
import grp
import ipaddress
import json
import logging
import os
import shutil
import sqlite3
import threading
import time
from dataclasses import fields, is_dataclass, asdict
from datetime import date, datetime, time as datetime_time, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from mac_audit_agent.models import (
    BaselineComparison,
    BackgroundMonitorEvent,
    BackgroundMonitorStatus,
    AlertDeliveryRecord,
    CommandExecutionResult,
    FileIssueSnapshot,
    Finding,
    FindingSuppressionRule,
    EventAlertTrace,
    NotificationCapabilities,
    HistoryIndicator,
    InvestigationAuditEntry,
    InvestigationNote,
    LaunchItemSnapshot,
    PermissionSnapshot,
    PortSnapshot,
    ProcessSnapshot,
    NetworkDiscoveryComparison,
    NetworkHostSnapshot,
    RawLogEntry,
    ReviewChecklistItem,
    ScanError,
    ScanResult,
    ScanSummary,
    UserSnapshot,
    safe_int,
    utc_now_iso,
)
from mac_audit_agent.version import DATABASE_SCHEMA_VERSION

LOGGER = logging.getLogger(__name__)
SYSTEM_MONITOR_DB_PATH = Path("/Library/Application Support/MacAuditAgent/mac_audit_agent.sqlite3")
FINDING_FIELD_NAMES = {item.name for item in fields(Finding)}
FINDING_PROVENANCE_FIELDS = {
    "rule_id",
    "rule_name",
    "event_id",
    "event_type",
    "trigger_source",
    "trigger_subsource",
    "trigger_rule_id",
    "trigger_rule_name",
    "raw_signal_summary",
    "normalized_signal",
    "evidence_hash",
    "related_process",
    "related_pid",
    "related_parent_pid",
    "related_path",
    "related_user",
    "related_network_endpoint",
    "related_url",
    "related_dom_selector",
    "related_file_hash",
    "first_seen",
    "last_seen",
    "previous_state",
    "current_state",
    "baseline_status",
    "correlation_id",
    "suppression_reason",
    "false_positive_hints",
    "recommended_verification_steps",
    "source_trace",
}
EVENT_PROVENANCE_FIELDS = {
    "rule_id",
    "rule_name",
    "trigger_source",
    "trigger_subsource",
    "trigger_rule_id",
    "trigger_rule_name",
    "raw_signal_summary",
    "normalized_signal",
    "evidence_hash",
    "related_process",
    "related_pid",
    "related_parent_pid",
    "related_path",
    "related_user",
    "related_network_endpoint",
    "related_url",
    "related_dom_selector",
    "related_file_hash",
    "first_seen",
    "last_seen",
    "previous_state",
    "current_state",
    "baseline_status",
    "correlation_id",
    "suppression_reason",
    "false_positive_hints",
    "recommended_verification_steps",
    "source_trace",
}


class _LockedConnection:
    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock) -> None:
        self._conn = conn
        self._lock = lock

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)

    @property
    def row_factory(self):  # type: ignore[override]
        return self._conn.row_factory

    @row_factory.setter
    def row_factory(self, value) -> None:  # type: ignore[override]
        self._conn.row_factory = value

    def _with_retry(self, fn, *args, **kwargs):
        last_exc: sqlite3.OperationalError | None = None
        for attempt in range(6):
            try:
                with self._lock:
                    return fn(*args, **kwargs)
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                    raise
                last_exc = exc
                time.sleep(min(0.25 * (attempt + 1), 1.5))
        if last_exc is not None:
            raise last_exc
        return fn(*args, **kwargs)

    def execute(self, *args, **kwargs):
        return self._with_retry(self._conn.execute, *args, **kwargs)

    def executemany(self, *args, **kwargs):
        return self._with_retry(self._conn.executemany, *args, **kwargs)

    def executescript(self, *args, **kwargs):
        return self._with_retry(self._conn.executescript, *args, **kwargs)

    def commit(self):
        return self._with_retry(self._conn.commit)

    def rollback(self):
        return self._with_retry(self._conn.rollback)

    def close(self):
        return self._with_retry(self._conn.close)


def normalize_finding_payload(payload: dict) -> dict:
    normalized = dict(payload)

    if "recommendation" in normalized and "recommended_next_steps" not in normalized:
        normalized["recommended_next_steps"] = normalized["recommendation"]
    if "command" in normalized and "command_or_source" not in normalized:
        normalized["command_or_source"] = normalized["command"]
    if "command" in normalized and "command_used" not in normalized:
        normalized["command_used"] = normalized["command"]

    normalized.setdefault("id", f"legacy-finding-{utc_timestamp_slug()}")
    normalized.setdefault("category", "Legacy Finding")
    normalized.setdefault("title", "Legacy Finding")
    normalized.setdefault("severity", "low")
    normalized.setdefault("description", "")
    normalized.setdefault("evidence", "")
    normalized.setdefault("command_used", normalized.get("command_or_source", "legacy payload"))
    normalized.setdefault("remediation_suggestion", normalized.get("recommended_next_steps", "Review the original saved finding payload."))
    normalized.setdefault("warning", normalized.get("what_can_go_wrong", "Legacy finding payload may be incomplete or inconsistent."))
    normalized.setdefault("redacted", False)
    normalized.setdefault("command_or_source", normalized.get("command_used", "legacy payload"))
    normalized.setdefault("needs_admin_for_followup", False)
    normalized.setdefault("evidence_summary", normalized.get("evidence", ""))
    normalized.setdefault("raw_evidence_ref", "")
    normalized.setdefault("why_this_matters", "")
    normalized.setdefault("false_positive_notes", "")
    normalized.setdefault("recommended_next_steps", normalized.get("remediation_suggestion", "Review the original saved finding payload."))
    normalized.setdefault("what_can_go_wrong", normalized.get("warning", "Legacy finding payload may be incomplete or inconsistent."))
    normalized.setdefault("remediation_steps", [normalized.get("recommended_next_steps", "Review the original saved finding payload.")])
    normalized.setdefault("remediation_commands", [])
    normalized.setdefault("remediation_risk", "safe")
    normalized.setdefault("requires_admin", normalized.get("needs_admin_for_followup", False))
    normalized.setdefault("reversible", True)
    normalized.setdefault("estimated_impact", "low")
    normalized.setdefault("verification_steps", [f"Run a fresh scan and verify whether {normalized.get('title', 'the finding')} still appears."])
    normalized.setdefault("remediation_references", [])
    normalized.setdefault("business_impact", "")
    normalized.setdefault("local_network_impact", "")
    normalized.setdefault("privilege_escalation_context", "")
    normalized.setdefault("provenance_json", "{}")
    provenance_json = normalized.get("provenance_json", "")
    if isinstance(provenance_json, str) and provenance_json.strip():
        try:
            provenance_payload = json.loads(provenance_json)
        except json.JSONDecodeError:
            provenance_payload = {}
        if isinstance(provenance_payload, dict):
            normalized.update(provenance_payload)
    normalized.setdefault("provenance_json", normalized.get("provenance_json", "{}"))
    normalized.setdefault("created_at", utc_timestamp_slug())

    return {key: value for key, value in normalized.items() if key in FINDING_FIELD_NAMES}


def normalize_finding_for_db(scan_id: str, finding: Finding | dict | Any) -> dict[str, Any]:
    if hasattr(finding, "to_dict"):
        data = finding.to_dict()
    elif isinstance(finding, dict):
        data = dict(finding)
    else:
        data = dict(getattr(finding, "__dict__", {}))

    evidence = data.get("evidence", "")
    if isinstance(evidence, (dict, list)):
        serialized_evidence = json.dumps(evidence)
    else:
        serialized_evidence = str(evidence)
    evidence_summary = data.get("evidence_summary", serialized_evidence)
    if isinstance(evidence_summary, (dict, list)):
        evidence_summary = json.dumps(evidence_summary)
    else:
        evidence_summary = str(evidence_summary)

    recommendation = data.get("recommendation") or data.get("recommended_next_step") or data.get("recommended_next_steps") or data.get("remediation_suggestion", "")
    command_or_source = data.get("command_or_source") or data.get("command_used", "") or data.get("command", "")
    created_at = data.get("created_at") or utc_timestamp_slug()
    finding_id = data.get("id") or data.get("finding_id") or f"legacy-finding-{utc_timestamp_slug()}"
    return {
        "scan_id": scan_id,
        "id": finding_id,
        "finding_id": finding_id,
        "title": data.get("title", ""),
        "severity": data.get("severity", "info"),
        "category": data.get("category", ""),
        "description": data.get("description", ""),
        "evidence": serialized_evidence,
        "redacted": int(bool(data.get("redacted", False))),
        "recommendation": recommendation,
        "false_positive_notes": data.get("false_positive_notes", ""),
        "what_can_go_wrong": data.get("what_can_go_wrong", data.get("warning", "")),
        "command_or_source": command_or_source,
        "needs_admin_for_followup": int(bool(data.get("needs_admin_for_followup", False))),
        "remediation_steps": json.dumps(data.get("remediation_steps", [])),
        "remediation_commands": json.dumps(data.get("remediation_commands", [])),
        "remediation_risk": data.get("remediation_risk", "safe"),
        "requires_admin": int(bool(data.get("requires_admin", False))),
        "reversible": int(bool(data.get("reversible", False))),
        "estimated_impact": data.get("estimated_impact", "low"),
        "verification_steps": json.dumps(data.get("verification_steps", [])),
        "created_at": created_at,
        "command_used": data.get("command_used", command_or_source),
        "remediation_suggestion": data.get("remediation_suggestion", recommendation),
        "warning": data.get("warning", data.get("what_can_go_wrong", "")),
        "evidence_summary": evidence_summary,
        "raw_evidence_ref": data.get("raw_evidence_ref", ""),
        "why_this_matters": data.get("why_this_matters", ""),
        "recommended_next_steps": data.get("recommended_next_steps", recommendation),
        "remediation_references": json.dumps(data.get("remediation_references", [])),
        "business_impact": data.get("business_impact", ""),
        "local_network_impact": data.get("local_network_impact", ""),
        "privilege_escalation_context": data.get("privilege_escalation_context", ""),
        "provenance_json": json.dumps({key: json_safe(data.get(key)) for key in FINDING_PROVENANCE_FIELDS if key in data}, sort_keys=True),
    }


def normalize_event_provenance(event: BackgroundMonitorEvent | dict | Any) -> dict[str, Any]:
    if hasattr(event, "to_dict"):
        data = event.to_dict()
    elif isinstance(event, dict):
        data = dict(event)
    else:
        data = dict(getattr(event, "__dict__", {}))
    return {key: json_safe(data.get(key)) for key in EVENT_PROVENANCE_FIELDS if key in data}


def _provenance_from_json(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {key: parsed.get(key) for key in parsed.keys() if key in FINDING_PROVENANCE_FIELDS or key in EVENT_PROVENANCE_FIELDS}


def utc_timestamp_slug() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_safe(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address, ipaddress.IPv4Network, ipaddress.IPv6Network, ipaddress.IPv4Interface, ipaddress.IPv6Interface)):
        return str(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, datetime_time):
        return value.isoformat()
    if isinstance(value, tuple):
        return [json_safe(item) for item in value]
    if isinstance(value, set):
        return [json_safe(item) for item in value]
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if hasattr(value, "to_dict"):
        return json_safe(value.to_dict())
    if is_dataclass(value):
        return json_safe(asdict(value))
    return value


class AuditDatabase:
    RECORD_FINDING_SQL = """
    INSERT OR REPLACE INTO findings (
        id,
        finding_id,
        scan_id,
        title,
        severity,
        category,
        description,
        evidence,
        redacted,
        recommendation,
        false_positive_notes,
        what_can_go_wrong,
        command_or_source,
        needs_admin_for_followup,
        remediation_steps,
        remediation_commands,
        remediation_risk,
        requires_admin,
        reversible,
        estimated_impact,
        verification_steps,
        command_used,
        remediation_suggestion,
        warning,
        evidence_summary,
        raw_evidence_ref,
        why_this_matters,
        recommended_next_steps,
        remediation_references,
        business_impact,
        local_network_impact,
        privilege_escalation_context,
        provenance_json,
        created_at
    ) VALUES (
        :id,
        :finding_id,
        :scan_id,
        :title,
        :severity,
        :category,
        :description,
        :evidence,
        :redacted,
        :recommendation,
        :false_positive_notes,
        :what_can_go_wrong,
        :command_or_source,
        :needs_admin_for_followup,
        :remediation_steps,
        :remediation_commands,
        :remediation_risk,
        :requires_admin,
        :reversible,
        :estimated_impact,
        :verification_steps,
        :command_used,
        :remediation_suggestion,
        :warning,
        :evidence_summary,
        :raw_evidence_ref,
        :why_this_matters,
        :recommended_next_steps,
        :remediation_references,
        :business_impact,
        :local_network_impact,
        :privilege_escalation_context,
        :provenance_json,
        :created_at
    )
    """

    def __init__(self, path: Path, logs_dir: Path | None = None, log_retention_days: int = 30) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_shared_system_db_permissions()
        self.logs_dir = logs_dir or (Path.home() / ".mac_audit_agent" / "logs")
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.log_retention_days = log_retention_days
        self._db_lock = threading.RLock()
        self._closed = False
        raw_conn = sqlite3.connect(path, timeout=30, check_same_thread=False)
        self.conn = _LockedConnection(raw_conn, self._db_lock)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()
        self._ensure_shared_system_db_permissions()

    def close(self) -> None:
        if getattr(self, "_closed", True):
            return
        self._closed = True
        try:
            self.conn.close()
        except Exception:
            LOGGER.debug("Unable to close audit database %s", self.path, exc_info=True)

    def __enter__(self) -> "AuditDatabase":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _ensure_shared_system_db_permissions(self) -> None:
        if self.path != SYSTEM_MONITOR_DB_PATH:
            return
        try:
            admin_gid = grp.getgrnam("admin").gr_gid
        except KeyError:
            try:
                admin_gid = grp.getgrnam("wheel").gr_gid
            except KeyError:
                return
        targets = [
            (self.path.parent, 0o775),
            (self.path, 0o660),
            (self.path.with_suffix(self.path.suffix + "-wal"), 0o660),
            (self.path.with_suffix(self.path.suffix + "-shm"), 0o660),
        ]
        for target, mode in targets:
            try:
                if not target.exists():
                    continue
                os.chown(target, 0, admin_gid)
                target.chmod(mode)
            except OSError:
                LOGGER.debug("Unable to adjust shared system DB permissions for %s", target, exc_info=True)

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                findings_count INTEGER NOT NULL,
                security_score INTEGER NOT NULL,
                notes TEXT NOT NULL,
                new_items_count INTEGER NOT NULL DEFAULT 0,
                score_label TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS scan_results (
                scan_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL DEFAULT '',
                scan_id TEXT NOT NULL,
                redacted INTEGER NOT NULL DEFAULT 0,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                command_or_source TEXT NOT NULL DEFAULT '',
                needs_admin_for_followup INTEGER NOT NULL DEFAULT 0,
                recommendation TEXT NOT NULL DEFAULT '',
                command_used TEXT NOT NULL,
                remediation_suggestion TEXT NOT NULL,
                warning TEXT NOT NULL,
                evidence_summary TEXT NOT NULL,
                raw_evidence_ref TEXT NOT NULL,
                why_this_matters TEXT NOT NULL,
                false_positive_notes TEXT NOT NULL,
                recommended_next_steps TEXT NOT NULL,
                what_can_go_wrong TEXT NOT NULL,
                remediation_steps TEXT NOT NULL DEFAULT '[]',
                remediation_commands TEXT NOT NULL DEFAULT '[]',
                remediation_risk TEXT NOT NULL DEFAULT 'safe',
                requires_admin INTEGER NOT NULL DEFAULT 0,
                reversible INTEGER NOT NULL DEFAULT 1,
                estimated_impact TEXT NOT NULL DEFAULT 'low',
                verification_steps TEXT NOT NULL DEFAULT '[]',
                remediation_references TEXT NOT NULL DEFAULT '[]',
                business_impact TEXT NOT NULL DEFAULT '',
                local_network_impact TEXT NOT NULL DEFAULT '',
                privilege_escalation_context TEXT NOT NULL DEFAULT '',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS command_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                command_id TEXT NOT NULL,
                command_preview TEXT NOT NULL,
                executed_at TEXT NOT NULL,
                stdout TEXT NOT NULL,
                stderr TEXT NOT NULL,
                exit_code INTEGER,
                timed_out INTEGER NOT NULL,
                truncated INTEGER NOT NULL,
                dry_run INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command_id TEXT NOT NULL,
                approved_at TEXT NOT NULL,
                approval_text TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS remediation_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                command_text TEXT NOT NULL,
                explanation TEXT NOT NULL,
                user_approval INTEGER NOT NULL,
                approval_text TEXT NOT NULL,
                result_text TEXT NOT NULL,
                exit_code INTEGER,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS port_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                item_key TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                item_key TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS history_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                item_key TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS permission_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                item_key TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS file_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                item_key TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS launch_item_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                item_key TEXT NOT NULL,
                payload_json TEXT
            );
            CREATE TABLE IF NOT EXISTS process_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                item_key TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS network_discovery_runs (
                scan_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS network_discovery_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                item_key TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS nmap_scans (
                scan_id TEXT PRIMARY KEY,
                profile TEXT NOT NULL DEFAULT '',
                target TEXT NOT NULL DEFAULT '127.0.0.1',
                timestamp TEXT NOT NULL DEFAULT '',
                nmap_path TEXT NOT NULL DEFAULT '',
                command_used TEXT NOT NULL DEFAULT '',
                warnings_json TEXT NOT NULL DEFAULT '[]',
                errors_json TEXT NOT NULL DEFAULT '[]',
                sudo_required INTEGER NOT NULL DEFAULT 0,
                fallback_used INTEGER NOT NULL DEFAULT 0,
                raw_xml TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS nmap_scan_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                host TEXT NOT NULL DEFAULT '',
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL DEFAULT '',
                service TEXT NOT NULL DEFAULT '',
                product TEXT NOT NULL DEFAULT '',
                version TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '',
                confidence TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS baseline_drift_snapshots (
                baseline_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                trusted INTEGER NOT NULL DEFAULT 1,
                source TEXT NOT NULL DEFAULT '',
                note TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS baseline_drift_expected (
                drift_id TEXT PRIMARY KEY,
                marked_at TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS cve_radar_cache (
                cache_key TEXT PRIMARY KEY,
                updated_at TEXT NOT NULL,
                source TEXT NOT NULL,
                expires_at TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cve_radar_alerts (
                alert_id TEXT PRIMARY KEY,
                cve_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                status TEXT NOT NULL,
                source TEXT NOT NULL,
                kev INTEGER NOT NULL DEFAULT 0,
                apple_related INTEGER NOT NULL DEFAULT 0,
                applicability_confidence TEXT NOT NULL DEFAULT '',
                published_date TEXT NOT NULL DEFAULT '',
                last_modified_date TEXT NOT NULL DEFAULT '',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                snoozed_until TEXT NOT NULL DEFAULT '',
                review_notes TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cve_radar_reviews (
                review_id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                reviewed_at TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                snoozed_until TEXT NOT NULL DEFAULT '',
                snooze_scope TEXT NOT NULL DEFAULT '',
                version_marker TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS cve_radar_inventory (
                inventory_id TEXT PRIMARY KEY,
                collected_at TEXT NOT NULL,
                source TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS apple_security_forecasts (
                forecast_id TEXT PRIMARY KEY,
                generated_at TEXT NOT NULL,
                level TEXT NOT NULL,
                summary TEXT NOT NULL,
                source_mode TEXT NOT NULL DEFAULT '',
                simulated INTEGER NOT NULL DEFAULT 0,
                affected_products TEXT NOT NULL DEFAULT '[]',
                cve_count INTEGER NOT NULL DEFAULT 0,
                kev_count INTEGER NOT NULL DEFAULT 0,
                highest_severity TEXT NOT NULL DEFAULT 'info',
                recommended_action TEXT NOT NULL DEFAULT '',
                previous_level TEXT NOT NULL DEFAULT '',
                next_check_at TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS apple_security_forecast_cards (
                card_id TEXT PRIMARY KEY,
                forecast_id TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                forecast_level TEXT NOT NULL,
                simulated INTEGER NOT NULL DEFAULT 0,
                affected_local_product TEXT NOT NULL DEFAULT '',
                detected_version TEXT NOT NULL DEFAULT '',
                fixed_version TEXT NOT NULL DEFAULT '',
                cves TEXT NOT NULL DEFAULT '[]',
                kev_cves TEXT NOT NULL DEFAULT '[]',
                epss_high_cves TEXT NOT NULL DEFAULT '[]',
                applicability TEXT NOT NULL DEFAULT '',
                confidence TEXT NOT NULL DEFAULT '',
                why_shown TEXT NOT NULL DEFAULT '',
                what_to_do TEXT NOT NULL DEFAULT '',
                update_path TEXT NOT NULL DEFAULT '',
                references_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'new',
                snooze_until TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS apple_security_cve_cache (
                cve_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS apple_security_review_state (
                card_id TEXT PRIMARY KEY,
                cve_id TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'new',
                reviewed_at TEXT NOT NULL DEFAULT '',
                snooze_until TEXT NOT NULL DEFAULT '',
                snooze_scope TEXT NOT NULL DEFAULT '',
                version_marker TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS system_recovery_baselines (
                baseline_key TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                path TEXT NOT NULL,
                baseline_bytes INTEGER NOT NULL DEFAULT 0,
                observed_at TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS system_recovery_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                snapshot_path TEXT NOT NULL,
                assessment_level TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS system_cleanup_actions (
                action_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                action_type TEXT NOT NULL,
                category TEXT NOT NULL,
                risk_level TEXT NOT NULL DEFAULT '',
                snapshot_id TEXT NOT NULL DEFAULT '',
                preview_json TEXT NOT NULL DEFAULT '{}',
                rollback_json TEXT NOT NULL DEFAULT '{}',
                deleted_json TEXT NOT NULL DEFAULT '[]',
                result_text TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS background_monitor_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                process_name TEXT NOT NULL DEFAULT '',
                pid INTEGER,
                evidence TEXT NOT NULL,
                confidence TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                simulated INTEGER NOT NULL DEFAULT 0,
                notification_sent INTEGER NOT NULL DEFAULT 0,
                notification_error TEXT NOT NULL DEFAULT '',
                notification_returncode INTEGER,
                notification_decision TEXT NOT NULL DEFAULT 'log_only',
                notification_reason TEXT NOT NULL DEFAULT '',
                cooldown_remaining_seconds INTEGER NOT NULL DEFAULT 0,
                popup_allowed INTEGER NOT NULL DEFAULT 0,
                visible_alert_shown INTEGER NOT NULL DEFAULT 0,
                alert_style TEXT NOT NULL DEFAULT 'neutral_grey',
                cooldown_suppressed INTEGER NOT NULL DEFAULT 0,
                last_suppression_reason TEXT NOT NULL DEFAULT '',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                provenance_json TEXT NOT NULL DEFAULT '{}',
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                duplicate_count INTEGER NOT NULL DEFAULT 0,
                duplicate_group_key TEXT NOT NULL DEFAULT '',
                duplicate_category TEXT NOT NULL DEFAULT 'single',
                first_seen TEXT NOT NULL DEFAULT '',
                last_seen TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS background_monitor_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS event_alert_traces (
                trace_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                original_event_type TEXT NOT NULL DEFAULT '',
                normalized_event_type TEXT NOT NULL DEFAULT '',
                detector_source TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                stored_db_path TEXT NOT NULL DEFAULT '',
                stored_success INTEGER NOT NULL DEFAULT 0,
                notifier_db_path TEXT NOT NULL DEFAULT '',
                notifier_seen INTEGER NOT NULL DEFAULT 0,
                notifier_seen_at TEXT NOT NULL DEFAULT '',
                notification_policy_checked INTEGER NOT NULL DEFAULT 0,
                notification_policy_result TEXT NOT NULL DEFAULT '',
                notification_policy_reason TEXT NOT NULL DEFAULT '',
                severity_before_policy TEXT NOT NULL DEFAULT '',
                severity_after_policy TEXT NOT NULL DEFAULT '',
                alert_required INTEGER NOT NULL DEFAULT 0,
                alert_suppressed INTEGER NOT NULL DEFAULT 0,
                alert_suppression_reason TEXT NOT NULL DEFAULT '',
                overlay_dispatch_attempted INTEGER NOT NULL DEFAULT 0,
                overlay_dispatch_at TEXT NOT NULL DEFAULT '',
                overlay_dispatch_result TEXT NOT NULL DEFAULT '',
                overlay_error TEXT NOT NULL DEFAULT '',
                visible_alert_id TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS notification_capabilities (
                scope TEXT PRIMARY KEY,
                updated_at TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS alert_delivery_records (
                event_id TEXT PRIMARY KEY,
                alert_type TEXT NOT NULL,
                overlay_attempted INTEGER NOT NULL DEFAULT 0,
                overlay_success INTEGER NOT NULL DEFAULT 0,
                dialog_attempted INTEGER NOT NULL DEFAULT 0,
                dialog_success INTEGER NOT NULL DEFAULT 0,
                notification_attempted INTEGER NOT NULL DEFAULT 0,
                notification_success INTEGER NOT NULL DEFAULT 0,
                delivery_method_used TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS background_monitor_heartbeats (
                heartbeat_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                status_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS legal_notice_acknowledgements (
                notice_version TEXT PRIMARY KEY,
                acknowledged_at TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 1,
                payload_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS security_decoy_connections (
                connection_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_port INTEGER NOT NULL,
                destination_port INTEGER NOT NULL,
                listen_address TEXT NOT NULL DEFAULT '',
                protocol_profile TEXT NOT NULL,
                bytes_sent INTEGER NOT NULL DEFAULT 0,
                bytes_received INTEGER NOT NULL DEFAULT 0,
                connection_count INTEGER NOT NULL DEFAULT 1,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                correlation_id TEXT NOT NULL DEFAULT '',
                payload_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS investigation_notes (
                note_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '[]',
                linked_finding_id TEXT NOT NULL DEFAULT '',
                linked_scan_id TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open',
                priority TEXT NOT NULL DEFAULT 'medium',
                investigator_name TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS review_checklist (
                item_type TEXT NOT NULL,
                item_key TEXT NOT NULL,
                label TEXT NOT NULL,
                review_state TEXT NOT NULL DEFAULT 'not reviewed',
                linked_scan_id TEXT NOT NULL DEFAULT '',
                linked_finding_id TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (item_type, item_key, linked_scan_id)
            );
            CREATE TABLE IF NOT EXISTS finding_suppression_rules (
                fingerprint TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                review_state TEXT NOT NULL,
                rationale TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                matched_count INTEGER NOT NULL DEFAULT 0,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS investigation_audit_trail (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action_type TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                previous_status TEXT NOT NULL DEFAULT '',
                new_status TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT ''
            );
            """
        )
        self._ensure_column("scans", "score_label", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("launch_item_snapshots", "payload_json", "TEXT")
        self._ensure_column("findings", "finding_id", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("findings", "redacted", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("findings", "command_or_source", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("findings", "needs_admin_for_followup", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("findings", "recommendation", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("findings", "remediation_steps", "TEXT NOT NULL DEFAULT '[]'")
        self._ensure_column("findings", "remediation_commands", "TEXT NOT NULL DEFAULT '[]'")
        self._ensure_column("findings", "remediation_risk", "TEXT NOT NULL DEFAULT 'safe'")
        self._ensure_column("findings", "requires_admin", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("findings", "reversible", "INTEGER NOT NULL DEFAULT 1")
        self._ensure_column("findings", "estimated_impact", "TEXT NOT NULL DEFAULT 'low'")
        self._ensure_column("findings", "verification_steps", "TEXT NOT NULL DEFAULT '[]'")
        self._ensure_column("findings", "remediation_references", "TEXT NOT NULL DEFAULT '[]'")
        self._ensure_column("findings", "business_impact", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("findings", "local_network_impact", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("findings", "privilege_escalation_context", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("findings", "provenance_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("network_discovery_runs", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("network_discovery_hosts", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("cve_radar_cache", "expires_at", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("cve_radar_alerts", "applicability_confidence", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("cve_radar_alerts", "published_date", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("cve_radar_alerts", "last_modified_date", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("cve_radar_alerts", "first_seen", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("cve_radar_alerts", "last_seen", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("cve_radar_alerts", "snoozed_until", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("cve_radar_alerts", "review_notes", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("cve_radar_reviews", "notes", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("cve_radar_reviews", "snoozed_until", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("cve_radar_reviews", "snooze_scope", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("cve_radar_reviews", "version_marker", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("cve_radar_reviews", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("cve_radar_inventory", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("apple_security_forecasts", "affected_products", "TEXT NOT NULL DEFAULT '[]'")
        self._ensure_column("apple_security_forecasts", "source_mode", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("apple_security_forecasts", "simulated", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("apple_security_forecasts", "previous_level", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("apple_security_forecasts", "next_check_at", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("apple_security_forecasts", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("apple_security_forecast_cards", "simulated", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("apple_security_forecast_cards", "kev_cves", "TEXT NOT NULL DEFAULT '[]'")
        self._ensure_column("apple_security_forecast_cards", "epss_high_cves", "TEXT NOT NULL DEFAULT '[]'")
        self._ensure_column("apple_security_forecast_cards", "references_json", "TEXT NOT NULL DEFAULT '[]'")
        self._ensure_column("apple_security_forecast_cards", "snooze_until", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("apple_security_forecast_cards", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("apple_security_cve_cache", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("apple_security_review_state", "reviewed_at", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("apple_security_review_state", "snooze_until", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("apple_security_review_state", "snooze_scope", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("apple_security_review_state", "version_marker", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("apple_security_review_state", "notes", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("apple_security_review_state", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("system_recovery_baselines", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("system_recovery_snapshots", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("system_cleanup_actions", "preview_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("system_cleanup_actions", "rollback_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("system_cleanup_actions", "deleted_json", "TEXT NOT NULL DEFAULT '[]'")
        self._ensure_column("system_cleanup_actions", "result_text", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("system_cleanup_actions", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("finding_suppression_rules", "rationale", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("finding_suppression_rules", "active", "INTEGER NOT NULL DEFAULT 1")
        self._ensure_column("finding_suppression_rules", "matched_count", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("finding_suppression_rules", "first_seen_at", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("finding_suppression_rules", "last_seen_at", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("background_monitor_events", "simulated", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("background_monitor_events", "notification_sent", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("background_monitor_events", "notification_error", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("background_monitor_events", "notification_returncode", "INTEGER")
        self._ensure_column("background_monitor_events", "notification_decision", "TEXT NOT NULL DEFAULT 'log_only'")
        self._ensure_column("background_monitor_events", "notification_reason", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("background_monitor_events", "cooldown_remaining_seconds", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("background_monitor_events", "popup_allowed", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("background_monitor_events", "visible_alert_shown", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("background_monitor_events", "alert_style", "TEXT NOT NULL DEFAULT 'neutral_grey'")
        self._ensure_column("background_monitor_events", "cooldown_suppressed", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("background_monitor_events", "last_suppression_reason", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("background_monitor_events", "metadata_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("background_monitor_events", "provenance_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("background_monitor_events", "occurrence_count", "INTEGER NOT NULL DEFAULT 1")
        self._ensure_column("background_monitor_events", "duplicate_count", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("background_monitor_events", "duplicate_group_key", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("background_monitor_events", "duplicate_category", "TEXT NOT NULL DEFAULT 'single'")
        self._ensure_column("background_monitor_events", "first_seen", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("background_monitor_events", "last_seen", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "original_event_type", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "normalized_event_type", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "detector_source", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "stored_db_path", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "stored_success", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("event_alert_traces", "notifier_db_path", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "notifier_poll_seen", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("event_alert_traces", "notifier_poll_time", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "notifier_cursor_before", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "notifier_cursor_after", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "notifier_seen", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("event_alert_traces", "notifier_seen_at", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "notification_policy_checked", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("event_alert_traces", "notification_policy_result", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "notification_policy_reason", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "severity_before_policy", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "severity_after_policy", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "cooldown_checked", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("event_alert_traces", "cooldown_result", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "alert_required", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("event_alert_traces", "alert_suppressed", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("event_alert_traces", "alert_suppression_reason", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "alert_queue_enqueued", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("event_alert_traces", "alert_queue_length_before", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("event_alert_traces", "alert_queue_length_after", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("event_alert_traces", "overlay_dispatch_attempted", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("event_alert_traces", "overlay_dispatch_at", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "overlay_dispatch_result", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "overlay_error", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "visible_alert_id", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("event_alert_traces", "displayed_at", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("notification_capabilities", "updated_at", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("notification_capabilities", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("alert_delivery_records", "alert_type", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("alert_delivery_records", "overlay_attempted", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("alert_delivery_records", "overlay_success", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("alert_delivery_records", "dialog_attempted", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("alert_delivery_records", "dialog_success", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("alert_delivery_records", "notification_attempted", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("alert_delivery_records", "notification_success", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("alert_delivery_records", "delivery_method_used", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("alert_delivery_records", "updated_at", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("alert_delivery_records", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("legal_notice_acknowledgements", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("security_decoy_connections", "listen_address", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("security_decoy_connections", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._migrate_command_logs_exit_code_nullable()
        self.conn.execute(
            "INSERT OR REPLACE INTO background_monitor_state (key, value) VALUES (?, ?)",
            ("schema_version", str(DATABASE_SCHEMA_VERSION)),
        )
        self.conn.commit()

    def _migrate_command_logs_exit_code_nullable(self) -> None:
        columns = {row["name"]: row for row in self.conn.execute("PRAGMA table_info(command_logs)")}
        exit_code = columns.get("exit_code")
        if not exit_code or not exit_code["notnull"]:
            return
        self.conn.executescript(
            """
            ALTER TABLE command_logs RENAME TO command_logs_old;
            CREATE TABLE command_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                command_id TEXT NOT NULL,
                command_preview TEXT NOT NULL,
                executed_at TEXT NOT NULL,
                stdout TEXT NOT NULL,
                stderr TEXT NOT NULL,
                exit_code INTEGER,
                timed_out INTEGER NOT NULL,
                truncated INTEGER NOT NULL,
                dry_run INTEGER NOT NULL
            );
            INSERT INTO command_logs
            (id, scan_id, command_id, command_preview, executed_at, stdout, stderr, exit_code, timed_out, truncated, dry_run)
            SELECT id, scan_id, command_id, command_preview, executed_at, stdout, stderr, exit_code, timed_out, truncated, dry_run
            FROM command_logs_old;
            DROP TABLE command_logs_old;
            """
        )

    def _ensure_column(self, table: str, column: str, definition: str) -> None:
        columns = {row["name"] for row in self.conn.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def record_scan(self, summary: ScanSummary) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO scans
            (scan_id, started_at, completed_at, findings_count, security_score, notes, new_items_count, score_label)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                summary.scan_id,
                summary.started_at,
                summary.completed_at,
                summary.findings_count,
                -1 if summary.security_score is None else summary.security_score,
                summary.notes,
                summary.new_items_count,
                summary.score_label,
            ),
        )
        self.conn.commit()

    def list_scan_summaries(self, limit: int = 50) -> list[ScanSummary]:
        rows = self.conn.execute(
            "SELECT * FROM scans ORDER BY completed_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            ScanSummary(
                scan_id=str(row["scan_id"]),
                started_at=str(row["started_at"]),
                completed_at=str(row["completed_at"]),
                findings_count=int(row["findings_count"]),
                security_score=None if int(row["security_score"]) < 0 else int(row["security_score"]),
                notes=str(row["notes"]),
                new_items_count=int(row["new_items_count"]),
                score_label=str(row["score_label"] or ""),
            )
            for row in rows
        ]

    def list_scan_summaries_between(self, start_timestamp: str, end_timestamp: str) -> list[ScanSummary]:
        rows = self.conn.execute(
            """
            SELECT * FROM scans
            WHERE completed_at >= ? AND completed_at <= ?
            ORDER BY completed_at ASC
            """,
            (start_timestamp, end_timestamp),
        ).fetchall()
        return [
            ScanSummary(
                scan_id=str(row["scan_id"]),
                started_at=str(row["started_at"]),
                completed_at=str(row["completed_at"]),
                findings_count=int(row["findings_count"]),
                security_score=None if int(row["security_score"]) < 0 else int(row["security_score"]),
                notes=str(row["notes"]),
                new_items_count=int(row["new_items_count"]),
                score_label=str(row["score_label"] or ""),
            )
            for row in rows
        ]

    def record_scan_result(self, scan_result: ScanResult) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO scan_results (scan_id, payload_json) VALUES (?, ?)",
            (scan_result.scan_id, json.dumps(json_safe(scan_result.to_dict()))),
        )
        self.record_nmap_scan_result(scan_result.scan_id, scan_result.artifacts.get("localhost_scan", {}).get("nmap", {}), commit=False)
        self.conn.commit()

    def record_nmap_scan_result(self, scan_id: str, nmap_payload: dict[str, Any], *, commit: bool = True) -> None:
        if not isinstance(nmap_payload, dict) or not nmap_payload:
            return
        ports = nmap_payload.get("ports", [])
        command_used = nmap_payload.get("command_used", "")
        if isinstance(command_used, list):
            command_text = " | ".join(str(item) for item in command_used)
        else:
            command_text = str(command_used or "")
        profile = nmap_payload.get("profile", nmap_payload.get("profiles", ""))
        if isinstance(profile, list):
            profile_text = ", ".join(str(item) for item in profile)
        else:
            profile_text = str(profile or "")
        self.conn.execute(
            """
            INSERT OR REPLACE INTO nmap_scans
            (scan_id, profile, target, timestamp, nmap_path, command_used, warnings_json, errors_json, sudo_required, fallback_used, raw_xml, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                profile_text,
                str(nmap_payload.get("target", "127.0.0.1")),
                str(nmap_payload.get("timestamp", "")),
                str(nmap_payload.get("path", "")),
                command_text,
                json.dumps(json_safe(nmap_payload.get("warnings", []))),
                json.dumps(json_safe(nmap_payload.get("errors", []))),
                int(bool(nmap_payload.get("sudo_required", False))),
                int(bool(nmap_payload.get("fallback_used", False))),
                str(nmap_payload.get("raw_xml", "")),
                json.dumps(json_safe(nmap_payload)),
            ),
        )
        self.conn.execute("DELETE FROM nmap_scan_ports WHERE scan_id = ?", (scan_id,))
        self.conn.executemany(
            """
            INSERT INTO nmap_scan_ports
            (scan_id, host, port, protocol, state, service, product, version, reason, confidence, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    scan_id,
                    str(item.get("host", "")),
                    int(item.get("port", 0) or 0),
                    str(item.get("protocol", "")),
                    str(item.get("state", "")),
                    str(item.get("service", "")),
                    str(item.get("product", "")),
                    str(item.get("version", "")),
                    str(item.get("reason", "")),
                    str(item.get("confidence", "")),
                    json.dumps(json_safe(item)),
                )
                for item in ports
                if isinstance(item, dict)
            ],
        )
        if commit:
            self.conn.commit()

    def record_baseline_drift_snapshot(self, payload: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO baseline_drift_snapshots
            (baseline_id, created_at, trusted, source, note, payload_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(payload.get("snapshot_id", "default")),
                str(payload.get("created_at", utc_now_iso())),
                int(bool(payload.get("trusted", True))),
                str(payload.get("source", "")),
                str(payload.get("note", "")),
                json.dumps(json_safe(payload)),
            ),
        )
        self.conn.commit()

    def latest_baseline_drift_snapshot(self, baseline_id: str = "default") -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT payload_json FROM baseline_drift_snapshots WHERE baseline_id = ? ORDER BY created_at DESC LIMIT 1",
            (baseline_id,),
        ).fetchone()
        if not row:
            return None
        try:
            payload = json.loads(str(row["payload_json"] or "{}"))
        except json.JSONDecodeError:
            return None
        return payload if isinstance(payload, dict) else None

    def record_expected_baseline_drift(self, drift_id: str, *, note: str = "") -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO baseline_drift_expected
            (drift_id, marked_at, note)
            VALUES (?, ?, ?)
            """,
            (drift_id, utc_now_iso(), note),
        )
        self.conn.commit()

    def list_expected_baseline_drift_ids(self) -> list[str]:
        rows = self.conn.execute("SELECT drift_id FROM baseline_drift_expected ORDER BY marked_at DESC").fetchall()
        return [str(row["drift_id"]) for row in rows]

    def latest_scan_result(self) -> ScanResult | None:
        try:
            row = self.conn.execute(
                """
                SELECT scan_results.payload_json
                FROM scan_results
                JOIN scans ON scans.scan_id = scan_results.scan_id
                ORDER BY scans.completed_at DESC LIMIT 1
                """
            ).fetchone()
        except sqlite3.Error as exc:
            LOGGER.exception("Failed to load latest scan result: %s", exc)
            return None
        if not row:
            return None
        try:
            return self._scan_result_from_payload(json.loads(row["payload_json"]))
        except (json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
            LOGGER.exception("Failed to hydrate latest scan result: %s", exc)
            return None

    def get_scan_result(self, scan_id: str) -> ScanResult | None:
        row = self.conn.execute("SELECT payload_json FROM scan_results WHERE scan_id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        try:
            return self._scan_result_from_payload(json.loads(row["payload_json"]))
        except (json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
            LOGGER.exception("Failed to hydrate scan result %s: %s", scan_id, exc)
            return None

    def get_finding_by_id(self, finding_id: str) -> Finding | None:
        row = self.conn.execute("SELECT * FROM findings WHERE id = ? OR finding_id = ? ORDER BY created_at DESC LIMIT 1", (finding_id, finding_id)).fetchone()
        if not row:
            return None
        payload = dict(row)
        payload["remediation_steps"] = json.loads(payload.get("remediation_steps", "[]") or "[]")
        payload["remediation_commands"] = json.loads(payload.get("remediation_commands", "[]") or "[]")
        payload["verification_steps"] = json.loads(payload.get("verification_steps", "[]") or "[]")
        payload["remediation_references"] = json.loads(payload.get("remediation_references", "[]") or "[]")
        payload["redacted"] = bool(payload.get("redacted", 0))
        payload["needs_admin_for_followup"] = bool(payload.get("needs_admin_for_followup", 0))
        payload["requires_admin"] = bool(payload.get("requires_admin", 0))
        payload["reversible"] = bool(payload.get("reversible", 1))
        payload.update(_provenance_from_json(payload.get("provenance_json", "{}")))
        try:
            return Finding(**normalize_finding_payload(payload))
        except Exception:
            return None

    def _scan_result_from_payload(self, payload: dict) -> ScanResult:
        findings: list[Finding] = []
        for item in payload.get("findings", []):
            try:
                if not isinstance(item, dict):
                    raise TypeError("finding payload is not an object")
                findings.append(Finding(**normalize_finding_payload(item)))
            except Exception as exc:
                findings.append(self._finding_parse_error(item, exc))

        return ScanResult(
            scan_id=str(payload.get("scan_id", "unknown-scan")),
            timestamp=str(payload.get("timestamp", utc_timestamp_slug())),
            hostname=str(payload.get("hostname", "")),
            current_user=str(payload.get("current_user", "")),
            findings=findings,
            raw_logs=self._safe_load_items(payload.get("raw_logs", []), RawLogEntry),
            collected_artifacts=self._deserialize_artifacts(payload.get("collected_artifacts", {})),
            baseline_diff=payload.get("baseline_diff", {}),
            errors=self._safe_load_items(payload.get("errors", []), ScanError),
        )

    def _finding_parse_error(self, payload: Any, exc: Exception) -> Finding:
        snippet = str(payload)
        if len(snippet) > 200:
            snippet = snippet[:200]
        return Finding(
            id=f"finding-parse-error-{utc_timestamp_slug()}",
            category="Errors",
            title="Saved Finding Could Not Be Loaded",
            severity="low",
            description="A saved finding payload could not be parsed, but the rest of the scan was loaded.",
            evidence=snippet,
            command_used="stored scan payload hydration",
            remediation_suggestion="Review or re-export the saved scan if you need this finding intact.",
            warning="Editing or deleting database rows without a backup can remove historical evidence.",
            evidence_summary="A legacy or corrupt saved finding was skipped during startup.",
            raw_evidence_ref="storage:finding_parse_error",
            why_this_matters=str(exc),
            false_positive_notes="This usually indicates an older schema version or corrupted stored JSON.",
            recommended_next_steps="Run a fresh scan to regenerate the finding set under the current schema.",
            what_can_go_wrong="Assuming missing historical findings were intentionally cleared can hide a deserialization problem.",
        )

    def _safe_load_items(self, values: Any, cls):
        loaded = []
        if not isinstance(values, list):
            return loaded
        valid_fields = {item.name for item in fields(cls)}
        for value in values:
            if not isinstance(value, dict):
                continue
            filtered = {key: item for key, item in value.items() if key in valid_fields}
            filtered = self._normalize_numeric_payload(cls, filtered)
            try:
                loaded.append(cls(**filtered))
            except Exception:
                continue
        return loaded

    def _normalize_numeric_payload(self, cls, payload: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(payload)
        numeric_fields_by_cls = {
            CommandExecutionResult: {"exit_code"},
            RawLogEntry: {"exit_code"},
            PortSnapshot: {"pid", "port"},
            ProcessSnapshot: {"pid", "ppid"},
            UserSnapshot: {"uid", "gid", "authorized_keys_count", "sudo_rule_count"},
        }
        for field_name in numeric_fields_by_cls.get(cls, set()):
            if field_name in normalized:
                normalized[field_name] = safe_int(normalized[field_name])
        return normalized

    def _deserialize_artifacts(self, artifacts: dict) -> dict:
        mapping = {
            "users": UserSnapshot,
            "history_indicators": HistoryIndicator,
            "permission_snapshots": PermissionSnapshot,
            "file_issues": FileIssueSnapshot,
            "launch_snapshots": LaunchItemSnapshot,
            "command_results": CommandExecutionResult,
            "network_discovery_hosts": NetworkHostSnapshot,
        }
        restored = dict(artifacts)
        for key, cls in mapping.items():
            restored[key] = self._safe_load_items(artifacts.get(key, []), cls)
        ports = artifacts.get("ports", {})
        if isinstance(ports, dict):
            restored["ports"] = {
                "listening": self._safe_load_items(ports.get("listening", []), PortSnapshot),
                "active_connections": self._safe_load_items(ports.get("active_connections", []), PortSnapshot),
                "suspicious_review_needed": self._safe_load_items(ports.get("suspicious_review_needed", []), PortSnapshot),
                "errors": [str(item) for item in ports.get("errors", [])],
            }
        else:
            restored["ports"] = {
                "listening": self._safe_load_items(ports, PortSnapshot),
                "active_connections": [],
                "suspicious_review_needed": self._safe_load_items(ports, PortSnapshot),
                "errors": [str(item) for item in artifacts.get("ports_errors", [])],
            }
        processes = artifacts.get("processes", {})
        if isinstance(processes, dict):
            legacy_processes = artifacts.get("process_snapshots", [])
            restored_all = self._safe_load_items(processes.get("all", []), ProcessSnapshot)
            if not restored_all and isinstance(legacy_processes, list):
                restored_all = self._safe_load_items(legacy_processes, ProcessSnapshot)
            restored["processes"] = {
                "all": restored_all,
                "suspicious": self._safe_load_items(processes.get("suspicious", []), ProcessSnapshot),
                "errors": [str(item) for item in processes.get("errors", [])],
            }
        else:
            restored["processes"] = {
                "all": self._safe_load_items(artifacts.get("process_snapshots", []), ProcessSnapshot),
                "suspicious": self._safe_load_items(processes if isinstance(processes, list) else [], ProcessSnapshot),
                "errors": [],
            }
        restored["process_snapshots"] = list(restored["processes"]["all"])
        network_discovery = artifacts.get("network_discovery", {})
        if isinstance(network_discovery, dict):
            restored["network_discovery"] = {
                "hosts": self._safe_load_items(network_discovery.get("hosts", []), NetworkHostSnapshot),
                "comparison": network_discovery.get("comparison", {}),
                "interface": str(network_discovery.get("interface", "")),
                "subnet": str(network_discovery.get("subnet", "")),
                "gateway": str(network_discovery.get("gateway", "")),
                "gateway_mac": str(network_discovery.get("gateway_mac", "")),
                "scope": str(network_discovery.get("scope", "")),
                "review_needed_count": safe_int(network_discovery.get("review_needed_count")) or 0,
                "debug_logs": [str(item) for item in network_discovery.get("debug_logs", [])],
                "errors": [str(item) for item in network_discovery.get("errors", [])],
            }
        else:
            restored["network_discovery"] = {"hosts": [], "comparison": {}, "interface": "", "subnet": "", "gateway": "", "gateway_mac": "", "scope": "", "review_needed_count": 0, "debug_logs": [], "errors": []}
        return restored

    def record_finding(self, scan_id: str, finding: Finding | dict | Any) -> None:
        payload = normalize_finding_for_db(scan_id, finding)
        self.conn.execute(self.RECORD_FINDING_SQL, payload)
        self.conn.commit()

    def record_command_log(self, scan_id: str, result: CommandExecutionResult) -> int:
        cursor = self.conn.execute(
            """
            INSERT INTO command_logs
            (scan_id, command_id, command_preview, executed_at, stdout, stderr, exit_code, timed_out, truncated, dry_run)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                result.command_id,
                result.command_preview,
                result.executed_at,
                result.stdout,
                result.stderr,
                result.exit_code,
                int(result.timed_out),
                int(result.truncated),
                int(result.dry_run),
            ),
        )
        self.conn.commit()
        return int(cursor.lastrowid)

    def record_user_approval(self, command_id: str, approved_at: str, approval_text: str) -> None:
        self.conn.execute(
            "INSERT INTO user_approvals (command_id, approved_at, approval_text) VALUES (?, ?, ?)",
            (command_id, approved_at, approval_text),
        )
        self.conn.commit()

    def record_remediation_action(
        self,
        *,
        scan_id: str,
        finding_id: str,
        action_type: str,
        command_text: str,
        explanation: str,
        user_approval: bool,
        approval_text: str,
        result_text: str,
        exit_code: int | None,
        created_at: str,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO remediation_actions
            (scan_id, finding_id, action_type, command_text, explanation, user_approval, approval_text, result_text, exit_code, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, finding_id, action_type, command_text, explanation, int(user_approval), approval_text, result_text, exit_code, created_at),
        )
        self.conn.commit()

    def record_snapshots(
        self,
        scan_id: str,
        *,
        ports: list[PortSnapshot],
        users: list[UserSnapshot],
        history_indicators: list[HistoryIndicator],
        permissions: list[PermissionSnapshot],
        files: list[FileIssueSnapshot],
        processes: list[ProcessSnapshot],
        launch_snapshots: list[LaunchItemSnapshot],
        launch_items: set[str],
    ) -> None:
        self._insert_snapshot_rows("port_snapshots", scan_id, [(str(item.key()), item.to_dict()) for item in ports])
        self._insert_snapshot_rows("user_snapshots", scan_id, [(item.key(), item.to_dict()) for item in users])
        self._insert_snapshot_rows("history_indicators", scan_id, [(str(item.key()), item.to_dict()) for item in history_indicators])
        self._insert_snapshot_rows("permission_snapshots", scan_id, [(item.key(), item.to_dict()) for item in permissions])
        self._insert_snapshot_rows("file_snapshots", scan_id, [(item.key(), item.to_dict()) for item in files])
        self._insert_snapshot_rows("process_snapshots", scan_id, [(str(item.key()), item.to_dict()) for item in processes])
        self._insert_snapshot_rows("launch_item_snapshots", scan_id, [(item.key(), item.to_dict()) for item in launch_snapshots])
        self.conn.executemany("INSERT INTO launch_item_snapshots (scan_id, item_key, payload_json) VALUES (?, ?, ?)", [(scan_id, item, None) for item in sorted(launch_items)])
        self.conn.commit()

    def record_network_discovery(self, scan_id: str, payload: dict[str, Any]) -> None:
        payload = json_safe(payload)
        self.conn.execute(
            "INSERT OR REPLACE INTO network_discovery_runs (scan_id, payload_json) VALUES (?, ?)",
            (scan_id, json.dumps(payload)),
        )
        self.conn.execute("DELETE FROM network_discovery_hosts WHERE scan_id = ?", (scan_id,))
        hosts = payload.get("hosts", [])
        self.conn.executemany(
            "INSERT INTO network_discovery_hosts (scan_id, item_key, payload_json) VALUES (?, ?, ?)",
            [(scan_id, str(item.get("ip_address", "")), json.dumps(json_safe(item))) for item in hosts if isinstance(item, dict)],
        )
        self.conn.commit()

    def _insert_snapshot_rows(self, table: str, scan_id: str, rows: list[tuple[str, dict[str, Any]]]) -> None:
        self.conn.executemany(
            f"INSERT INTO {table} (scan_id, item_key, payload_json) VALUES (?, ?, ?)",
            [(scan_id, key, json.dumps(payload)) for key, payload in rows],
        )

    def latest_scan(self) -> dict | None:
        row = self.conn.execute("SELECT * FROM scans ORDER BY completed_at DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def previous_scan_id(self, current_scan_id: str | None = None) -> str | None:
        if current_scan_id:
            row = self.conn.execute(
                "SELECT scan_id FROM scans WHERE scan_id != ? ORDER BY completed_at DESC LIMIT 1",
                (current_scan_id,),
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT scan_id FROM scans ORDER BY completed_at DESC LIMIT 1 OFFSET 1"
            ).fetchone()
        return str(row["scan_id"]) if row else None

    def latest_findings(self, limit: int = 100) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM findings ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        results = []
        for row in rows:
            payload = dict(row)
            payload.update(_provenance_from_json(payload.get("provenance_json", "{}")))
            results.append(payload)
        return results

    def record_cve_radar_cache(
        self,
        payload: dict[str, Any],
        *,
        cache_key: str = "latest",
        source: str = "catalog",
        updated_at: str | None = None,
        expires_at: str = "",
    ) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO cve_radar_cache (cache_key, updated_at, source, expires_at, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                cache_key,
                updated_at or utc_now_iso(),
                source,
                expires_at,
                json.dumps(json_safe(payload)),
            ),
        )
        self.conn.commit()

    def latest_cve_radar_cache(self, cache_key: str = "latest") -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM cve_radar_cache WHERE cache_key = ? ORDER BY updated_at DESC LIMIT 1", (cache_key,)).fetchone()
        if not row:
            return None
        payload = dict(row)
        try:
            payload["payload_json"] = json.loads(payload.get("payload_json", "{}") or "{}")
        except json.JSONDecodeError:
            payload["payload_json"] = {}
        return payload

    def record_cve_radar_inventory(self, payload: dict[str, Any], *, inventory_id: str | None = None, source: str = "local-inventory") -> None:
        collected_at = str(payload.get("collected_at") or utc_now_iso())
        inventory_id = inventory_id or str(payload.get("inventory_id") or collected_at)
        self.conn.execute(
            """
            INSERT OR REPLACE INTO cve_radar_inventory (inventory_id, collected_at, source, payload_json)
            VALUES (?, ?, ?, ?)
            """,
            (inventory_id, collected_at, source, json.dumps(json_safe(payload))),
        )
        self.conn.commit()

    def latest_cve_radar_inventory(self) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM cve_radar_inventory ORDER BY collected_at DESC LIMIT 1").fetchone()
        if not row:
            return None
        payload = dict(row)
        try:
            payload["payload_json"] = json.loads(payload.get("payload_json", "{}") or "{}")
        except json.JSONDecodeError:
            payload["payload_json"] = {}
        return payload

    def record_apple_security_forecast(self, forecast: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO apple_security_forecasts
            (forecast_id, generated_at, level, summary, source_mode, simulated, affected_products, cve_count, kev_count, highest_severity, recommended_action, previous_level, next_check_at, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(forecast.get("forecast_id", "")),
                str(forecast.get("generated_at", utc_now_iso())),
                str(forecast.get("level", "clear")),
                str(forecast.get("summary", "")),
                str(forecast.get("source_mode", "")),
                int(bool(forecast.get("simulated", False))),
                json.dumps(json_safe(forecast.get("affected_products", []))),
                int(forecast.get("cve_count", 0) or 0),
                int(forecast.get("kev_count", 0) or 0),
                str(forecast.get("highest_severity", "info")),
                str(forecast.get("recommended_action", "")),
                str(forecast.get("previous_level", "")),
                str(forecast.get("next_check_at", "")),
                json.dumps(json_safe(forecast), sort_keys=True),
            ),
        )
        self.conn.commit()

    def latest_apple_security_forecast(self) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM apple_security_forecasts ORDER BY generated_at DESC LIMIT 1").fetchone()
        if not row:
            return None
        payload = dict(row)
        try:
            payload["payload_json"] = json.loads(payload.get("payload_json", "{}") or "{}")
        except json.JSONDecodeError:
            payload["payload_json"] = {}
        try:
            payload["affected_products"] = json.loads(payload.get("affected_products", "[]") or "[]")
        except json.JSONDecodeError:
            payload["affected_products"] = []
        payload["simulated"] = bool(payload.get("simulated", 0))
        payload["source_mode"] = str(payload.get("source_mode", ""))
        return payload

    def record_apple_security_forecast_cards(self, cards: list[dict[str, Any]]) -> None:
        for card in cards:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO apple_security_forecast_cards
                (card_id, forecast_id, title, category, forecast_level, simulated, affected_local_product, detected_version, fixed_version, cves, kev_cves, epss_high_cves, applicability, confidence, why_shown, what_to_do, update_path, references_json, status, snooze_until, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(card.get("card_id", "")),
                    str(card.get("forecast_id", "")),
                    str(card.get("title", "")),
                    str(card.get("category", "")),
                    str(card.get("forecast_level", "")),
                    int(bool(card.get("simulated", False))),
                    str(card.get("affected_local_product", "")),
                    str(card.get("detected_version", "")),
                    str(card.get("fixed_version", "")),
                    json.dumps(json_safe(card.get("cves", []))),
                    json.dumps(json_safe(card.get("kev_cves", []))),
                    json.dumps(json_safe(card.get("epss_high_cves", []))),
                    str(card.get("applicability", "")),
                    str(card.get("confidence", "")),
                    str(card.get("why_shown", "")),
                    str(card.get("what_to_do", "")),
                    str(card.get("update_path", "")),
                    json.dumps(json_safe(card.get("references", []))),
                    str(card.get("status", "new")),
                    str(card.get("snooze_until", "")),
                    json.dumps(json_safe(card), sort_keys=True),
                ),
            )
        self.conn.commit()

    def list_apple_security_forecast_cards(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM apple_security_forecast_cards ORDER BY rowid DESC LIMIT ?", (limit,)).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            payload = dict(row)
            try:
                payload["payload_json"] = json.loads(payload.get("payload_json", "{}") or "{}")
            except json.JSONDecodeError:
                payload["payload_json"] = {}
            for key in ["cves", "kev_cves", "epss_high_cves", "references_json"]:
                try:
                    payload[key] = json.loads(payload.get(key, "[]") or "[]")
                except json.JSONDecodeError:
                    payload[key] = []
            payload["simulated"] = bool(payload.get("simulated", 0))
            results.append(payload)
        return results

    def delete_apple_security_forecast(self, forecast_id: str) -> None:
        self.conn.execute("DELETE FROM apple_security_forecast_cards WHERE forecast_id = ?", (forecast_id,))
        self.conn.execute("DELETE FROM apple_security_forecasts WHERE forecast_id = ?", (forecast_id,))
        self.conn.commit()

    def record_apple_security_cve_cache(self, cve_id: str, payload: dict[str, Any], *, source: str) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO apple_security_cve_cache (cve_id, source, updated_at, payload_json)
            VALUES (?, ?, ?, ?)
            """,
            (cve_id, source, utc_now_iso(), json.dumps(json_safe(payload), sort_keys=True)),
        )
        self.conn.commit()

    def latest_apple_security_cve_cache(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM apple_security_cve_cache ORDER BY updated_at DESC").fetchall()
        cached: list[dict[str, Any]] = []
        for row in rows:
            payload = dict(row)
            try:
                payload["payload_json"] = json.loads(payload.get("payload_json", "{}") or "{}")
            except json.JSONDecodeError:
                payload["payload_json"] = {}
            cached.append(payload)
        return cached

    def record_apple_security_review_state(
        self,
        card_id: str,
        *,
        cve_id: str = "",
        status: str = "new",
        snooze_until: str = "",
        snooze_scope: str = "",
        version_marker: str = "",
        notes: str = "",
        payload: dict[str, Any] | None = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO apple_security_review_state
            (card_id, cve_id, status, reviewed_at, snooze_until, snooze_scope, version_marker, notes, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                card_id,
                cve_id,
                status,
                utc_now_iso(),
                snooze_until,
                snooze_scope,
                version_marker,
                notes,
                json.dumps(json_safe(payload or {}), sort_keys=True),
            ),
        )
        self.conn.commit()

    def record_system_recovery_baseline(self, baseline: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO system_recovery_baselines
            (baseline_key, category, path, baseline_bytes, observed_at, payload_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(baseline.get("baseline_key", "")),
                str(baseline.get("category", "")),
                str(baseline.get("path", "")),
                int(baseline.get("baseline_bytes", 0) or 0),
                str(baseline.get("observed_at", utc_now_iso())),
                json.dumps(json_safe(baseline), sort_keys=True),
            ),
        )
        self.conn.commit()

    def list_system_recovery_baselines(self, limit: int = 500) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM system_recovery_baselines ORDER BY observed_at DESC LIMIT ?", (limit,)).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            payload = dict(row)
            try:
                payload["payload_json"] = json.loads(payload.get("payload_json", "{}") or "{}")
            except json.JSONDecodeError:
                payload["payload_json"] = {}
            results.append(payload)
        return results

    def record_system_recovery_snapshot(self, snapshot: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO system_recovery_snapshots
            (snapshot_id, created_at, snapshot_path, assessment_level, payload_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(snapshot.get("snapshot_id", "")),
                str(snapshot.get("created_at", utc_now_iso())),
                str(snapshot.get("snapshot_path", "")),
                str(snapshot.get("assessment_level", "")),
                json.dumps(json_safe(snapshot), sort_keys=True),
            ),
        )
        self.conn.commit()

    def list_system_recovery_snapshots(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM system_recovery_snapshots ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            payload = dict(row)
            try:
                payload["payload_json"] = json.loads(payload.get("payload_json", "{}") or "{}")
            except json.JSONDecodeError:
                payload["payload_json"] = {}
            results.append(payload)
        return results

    def record_system_cleanup_action(self, action: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO system_cleanup_actions
            (action_id, created_at, action_type, category, risk_level, snapshot_id, preview_json, rollback_json, deleted_json, result_text, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(action.get("action_id", "")),
                str(action.get("created_at", utc_now_iso())),
                str(action.get("action_type", "")),
                str(action.get("category", "")),
                str(action.get("risk_level", "")),
                str(action.get("snapshot_id", "")),
                json.dumps(json_safe(action.get("preview_json", {})), sort_keys=True),
                json.dumps(json_safe(action.get("rollback_json", {})), sort_keys=True),
                json.dumps(json_safe(action.get("deleted_json", [])), sort_keys=True),
                str(action.get("result_text", "")),
                json.dumps(json_safe(action), sort_keys=True),
            ),
        )
        self.conn.commit()

    def list_system_cleanup_actions(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM system_cleanup_actions ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            payload = dict(row)
            for key in ["preview_json", "rollback_json", "deleted_json", "payload_json"]:
                try:
                    payload[key] = json.loads(payload.get(key, "{}" if key != "deleted_json" else "[]") or ("[]" if key == "deleted_json" else "{}"))
                except json.JSONDecodeError:
                    payload[key] = [] if key == "deleted_json" else {}
            results.append(payload)
        return results

    def latest_apple_security_review_state(self) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT * FROM apple_security_review_state ORDER BY reviewed_at DESC").fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            payload = dict(row)
            try:
                payload["payload_json"] = json.loads(payload.get("payload_json", "{}") or "{}")
            except json.JSONDecodeError:
                payload["payload_json"] = {}
            results.append(payload)
        return results

    def _cve_radar_alert_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        payload = dict(row)
        raw = str(payload.get("payload_json", "{}") or "{}")
        try:
            details = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            details = {}
        if isinstance(details, dict):
            payload.update(details)
        payload["kev"] = bool(payload.get("kev", 0))
        payload["apple_related"] = bool(payload.get("apple_related", 0))
        return payload

    def record_cve_radar_alerts(self, alerts: list[dict[str, Any]]) -> None:
        existing_rows = {
            str(row["alert_id"]): row
            for row in self.conn.execute("SELECT * FROM cve_radar_alerts").fetchall()
        }
        for alert in alerts:
            alert_id = str(alert.get("alert_id", "")).strip()
            if not alert_id:
                continue
            current = existing_rows.get(alert_id)
            status = str(alert.get("status", "") or "")
            if not status:
                status = str(current["status"]) if current else "new"
            snoozed_until = str(alert.get("snoozed_until", "") or (current["snoozed_until"] if current else ""))
            review_notes = str(alert.get("review_notes", "") or (current["review_notes"] if current else ""))
            self.conn.execute(
                """
                INSERT OR REPLACE INTO cve_radar_alerts
                (alert_id, cve_id, title, severity, confidence, status, source, kev, apple_related, applicability_confidence, published_date, last_modified_date, first_seen, last_seen, snoozed_until, review_notes, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    str(alert.get("cve_id", "")),
                    str(alert.get("title", "")),
                    str(alert.get("severity", "medium")),
                    str(alert.get("confidence", alert.get("applicability_confidence", "low"))),
                    status,
                    str(alert.get("source", "nvd")),
                    int(bool(alert.get("kev", False))),
                    int(bool(alert.get("apple_related", False))),
                    str(alert.get("applicability_confidence", "low")),
                    str(alert.get("published_date", "")),
                    str(alert.get("last_modified_date", "")),
                    str(alert.get("first_seen", utc_now_iso())),
                    str(alert.get("last_seen", utc_now_iso())),
                    snoozed_until,
                    review_notes,
                    json.dumps(json_safe(alert), sort_keys=True),
                ),
            )
        self.conn.commit()

    def list_cve_radar_alerts(self, *, limit: int = 200, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            rows = self.conn.execute(
                "SELECT * FROM cve_radar_alerts WHERE status = ? ORDER BY last_seen DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM cve_radar_alerts ORDER BY last_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._cve_radar_alert_from_row(row) for row in rows]

    def get_cve_radar_alert(self, alert_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM cve_radar_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        return self._cve_radar_alert_from_row(row) if row else None

    def set_cve_radar_alert_status(
        self,
        alert_id: str,
        *,
        status: str,
        notes: str = "",
        snoozed_until: str = "",
        snooze_scope: str = "",
        version_marker: str = "",
        action: str = "review",
        payload: dict[str, Any] | None = None,
    ) -> None:
        row = self.conn.execute("SELECT * FROM cve_radar_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        if not row:
            return
        alert = self._cve_radar_alert_from_row(row)
        if payload:
            alert.update(payload)
        alert["status"] = status
        alert["review_notes"] = notes
        alert["snoozed_until"] = snoozed_until
        alert["last_seen"] = utc_now_iso()
        self.conn.execute(
            """
            UPDATE cve_radar_alerts
            SET status = ?, snoozed_until = ?, review_notes = ?, last_seen = ?, payload_json = ?
            WHERE alert_id = ?
            """,
            (
                status,
                snoozed_until,
                notes,
                alert["last_seen"],
                json.dumps(json_safe(alert), sort_keys=True),
                alert_id,
            ),
        )
        self.conn.execute(
            """
            INSERT INTO cve_radar_reviews
            (alert_id, cve_id, reviewed_at, action, status, notes, snoozed_until, snooze_scope, version_marker, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                str(alert.get("cve_id", "")),
                utc_now_iso(),
                action,
                status,
                notes,
                snoozed_until,
                snooze_scope,
                version_marker,
                json.dumps(json_safe(alert), sort_keys=True),
            ),
        )
        self.conn.commit()

    def list_cve_radar_reviews(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM cve_radar_reviews ORDER BY reviewed_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            payload = dict(row)
            try:
                payload["payload_json"] = json.loads(payload.get("payload_json", "{}") or "{}")
            except json.JSONDecodeError:
                payload["payload_json"] = {}
            results.append(payload)
        return results

    def record_background_monitor_event(self, event: BackgroundMonitorEvent, dedupe_window_seconds: int = 60) -> bool:
        duplicate_group_key = self._background_event_duplicate_group_key(event)
        event.duplicate_group_key = event.duplicate_group_key or duplicate_group_key
        event.duplicate_category = event.duplicate_category or "single"
        event.occurrence_count = max(1, int(getattr(event, "occurrence_count", 1) or 1))
        event.duplicate_count = max(0, int(getattr(event, "duplicate_count", 0) or 0))
        event.first_seen = event.first_seen or event.timestamp
        event.last_seen = event.last_seen or event.timestamp
        row = self.conn.execute(
            """
            SELECT *
            FROM background_monitor_events
            WHERE event_type = ?
              AND process_name = ?
              AND COALESCE(pid, -1) = COALESCE(?, -1)
              AND evidence = ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (event.event_type, event.process_name, event.pid, event.evidence),
        ).fetchone()
        if row and dedupe_window_seconds > 0:
            try:
                event_ts = datetime.fromisoformat(event.timestamp)
                last_ts = datetime.fromisoformat(str(row["timestamp"]))
            except ValueError:
                event_ts = None
                last_ts = None
            if event_ts and last_ts and (event_ts - last_ts).total_seconds() < dedupe_window_seconds:
                self._record_background_event_duplicate(row, event, duplicate_group_key)
                return False
        self.conn.execute(
            """
            INSERT OR REPLACE INTO background_monitor_events
            (event_id, timestamp, event_type, severity, source, process_name, pid, evidence, confidence, recommendation, simulated, notification_sent, notification_error, notification_returncode, notification_decision, notification_reason, cooldown_remaining_seconds, popup_allowed, visible_alert_shown, alert_style, cooldown_suppressed, last_suppression_reason, metadata_json, provenance_json, occurrence_count, duplicate_count, duplicate_group_key, duplicate_category, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.timestamp,
                event.event_type,
                event.severity,
                event.source,
                event.process_name,
                event.pid,
                event.evidence,
                event.confidence,
                event.recommendation,
                int(bool(event.simulated)),
                int(bool(event.notification_sent)),
                event.notification_error,
                event.notification_returncode,
                event.notification_decision,
                event.notification_reason,
                event.cooldown_remaining_seconds,
                int(bool(event.popup_allowed)),
                int(bool(getattr(event, "visible_alert_shown", False))),
                str(getattr(event, "alert_style", "neutral_grey")),
                int(bool(getattr(event, "cooldown_suppressed", False))),
                str(getattr(event, "last_suppression_reason", "")),
                event.metadata_json,
                json.dumps(normalize_event_provenance(event), sort_keys=True),
                event.occurrence_count,
                event.duplicate_count,
                event.duplicate_group_key,
                event.duplicate_category,
                event.first_seen,
                event.last_seen,
            ),
        )
        self.set_background_monitor_state("last_event_timestamp", event.timestamp)
        self.conn.commit()
        return True

    def _background_event_duplicate_group_key(self, event: BackgroundMonitorEvent) -> str:
        parts = [
            str(event.event_type),
            str(event.source),
            str(event.process_name or ""),
            str(event.pid if event.pid is not None else ""),
            str(event.evidence),
        ]
        return "|".join(parts)

    def _record_background_event_duplicate(self, row: sqlite3.Row, event: BackgroundMonitorEvent, duplicate_group_key: str) -> None:
        occurrence_count = max(1, safe_int(row["occurrence_count"]) or 1) + 1
        duplicate_count = max(0, safe_int(row["duplicate_count"]) or 0) + 1
        first_seen = str(row["first_seen"] or row["timestamp"] or event.timestamp)
        last_seen = event.timestamp
        duplicate_category = "duplicate_burst" if duplicate_count < 10 else "high_volume_duplicate"
        metadata = {}
        try:
            metadata = json.loads(str(row["metadata_json"] or "{}"))
        except json.JSONDecodeError:
            metadata = {}
        if not isinstance(metadata, dict):
            metadata = {}
        metadata.update(
            {
                "occurrence_count": occurrence_count,
                "duplicate_count": duplicate_count,
                "duplicate_category": duplicate_category,
                "duplicate_group_key": duplicate_group_key,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "last_duplicate_event_id": event.event_id,
                "last_duplicate_timestamp": event.timestamp,
            }
        )
        event.occurrence_count = occurrence_count
        event.duplicate_count = duplicate_count
        event.duplicate_group_key = duplicate_group_key
        event.duplicate_category = duplicate_category
        event.first_seen = first_seen
        event.last_seen = last_seen
        event.metadata_json = json.dumps(metadata, sort_keys=True)
        self.conn.execute(
            """
            UPDATE background_monitor_events
            SET timestamp = ?,
                occurrence_count = ?,
                duplicate_count = ?,
                duplicate_group_key = ?,
                duplicate_category = ?,
                first_seen = ?,
                last_seen = ?,
                metadata_json = ?
            WHERE event_id = ?
            """,
            (
                event.timestamp,
                occurrence_count,
                duplicate_count,
                duplicate_group_key,
                duplicate_category,
                first_seen,
                last_seen,
                event.metadata_json,
                str(row["event_id"]),
            ),
        )
        self.set_background_monitor_state("last_event_timestamp", event.timestamp)
        self.set_background_monitor_state(f"duplicate_event_count:{event.event_type}", str(duplicate_count))
        self.conn.commit()

    def record_monitor_event(self, event: BackgroundMonitorEvent, dedupe_window_seconds: int = 300) -> bool:
        return self.record_background_monitor_event(event, dedupe_window_seconds=dedupe_window_seconds)

    def _background_event_from_row(self, row: sqlite3.Row) -> BackgroundMonitorEvent:
        provenance: dict[str, Any] = {}
        raw_provenance = str(row["provenance_json"] or "{}")
        if raw_provenance:
            try:
                parsed = json.loads(raw_provenance)
                if isinstance(parsed, dict):
                    provenance = parsed
            except json.JSONDecodeError:
                provenance = {}
        explicit_fields = {
            "first_seen",
            "last_seen",
            "occurrence_count",
            "duplicate_count",
            "duplicate_group_key",
            "duplicate_category",
        }
        return BackgroundMonitorEvent(
            event_id=str(row["event_id"]),
            timestamp=str(row["timestamp"]),
            event_type=str(row["event_type"]),
            severity=str(row["severity"]),
            source=str(row["source"]),
            process_name=str(row["process_name"] or ""),
            pid=safe_int(row["pid"]),
            evidence=str(row["evidence"]),
            confidence=str(row["confidence"]),
            recommendation=str(row["recommendation"]),
            simulated=bool(row["simulated"]),
            notification_sent=bool(row["notification_sent"]),
            notification_error=str(row["notification_error"] or ""),
            notification_returncode=safe_int(row["notification_returncode"]),
            notification_decision=str(row["notification_decision"] or "log_only"),
            notification_reason=str(row["notification_reason"] or ""),
            cooldown_remaining_seconds=safe_int(row["cooldown_remaining_seconds"]) or 0,
            popup_allowed=bool(row["popup_allowed"]),
            visible_alert_shown=bool(row["visible_alert_shown"]),
            alert_style=str(row["alert_style"] or "neutral_grey"),
            cooldown_suppressed=bool(row["cooldown_suppressed"]),
            last_suppression_reason=str(row["last_suppression_reason"] or ""),
            metadata_json=str(row["metadata_json"] or "{}"),
            occurrence_count=max(1, safe_int(row["occurrence_count"]) or 1),
            duplicate_count=max(0, safe_int(row["duplicate_count"]) or 0),
            duplicate_group_key=str(row["duplicate_group_key"] or ""),
            duplicate_category=str(row["duplicate_category"] or "single"),
            first_seen=str(row["first_seen"] or ""),
            last_seen=str(row["last_seen"] or ""),
            **{key: value for key, value in provenance.items() if key in EVENT_PROVENANCE_FIELDS and key not in explicit_fields},
        )

    def update_monitor_event_notification(
        self,
        event_id: str,
        *,
        notification_sent: bool,
        notification_error: str,
        notification_returncode: int | None,
        notification_decision: str = "log_only",
        notification_reason: str = "",
        cooldown_remaining_seconds: int = 0,
        popup_allowed: bool = False,
        visible_alert_shown: bool = False,
        alert_style: str = "neutral_grey",
        cooldown_suppressed: bool = False,
        last_suppression_reason: str = "",
    ) -> None:
        self.conn.execute(
            """
            UPDATE background_monitor_events
            SET notification_sent = ?, notification_error = ?, notification_returncode = ?, notification_decision = ?, notification_reason = ?, cooldown_remaining_seconds = ?, popup_allowed = ?, visible_alert_shown = ?, alert_style = ?, cooldown_suppressed = ?, last_suppression_reason = ?
            WHERE event_id = ?
            """,
            (
                int(bool(notification_sent)),
                notification_error,
                notification_returncode,
                notification_decision,
                notification_reason,
                cooldown_remaining_seconds,
                int(bool(popup_allowed)),
                int(bool(visible_alert_shown)),
                alert_style,
                int(bool(cooldown_suppressed)),
                last_suppression_reason,
                event_id,
            ),
        )
        self.conn.commit()

    def recent_background_monitor_events(self, limit: int = 100, event_type: str | None = None) -> list[BackgroundMonitorEvent]:
        if event_type:
            rows = self.conn.execute(
                """
                SELECT * FROM background_monitor_events
                WHERE event_type = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (event_type, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM background_monitor_events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            self._background_event_from_row(row)
            for row in rows
        ]

    def latest_monitor_events(self, limit: int = 100) -> list[BackgroundMonitorEvent]:
        return self.recent_background_monitor_events(limit=limit)

    def pending_background_monitor_events(self, limit: int = 100) -> list[BackgroundMonitorEvent]:
        rows = self.conn.execute(
            """
            SELECT * FROM background_monitor_events
            WHERE notification_sent = 0
            ORDER BY timestamp ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [self._background_event_from_row(row) for row in rows]

    def background_monitor_events_between(self, start_timestamp: str, end_timestamp: str) -> list[BackgroundMonitorEvent]:
        rows = self.conn.execute(
            """
            SELECT * FROM background_monitor_events
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC
            """,
            (start_timestamp, end_timestamp),
        ).fetchall()
        return [
            self._background_event_from_row(row)
            for row in rows
        ]

    def clear_monitor_events(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS count FROM background_monitor_events").fetchone()
        removed = int(row["count"]) if row and row["count"] is not None else 0
        self.conn.execute("DELETE FROM background_monitor_events")
        self.conn.commit()
        self.conn.execute("VACUUM")
        self.conn.commit()
        self.set_background_monitor_state("last_event_timestamp", "")
        return removed

    def clear_command_logs(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS count FROM command_logs").fetchone()
        removed = int(row["count"]) if row and row["count"] is not None else 0
        self.conn.execute("DELETE FROM command_logs")
        self.conn.commit()
        return removed

    def clear_remediation_actions(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS count FROM remediation_actions").fetchone()
        removed = int(row["count"]) if row and row["count"] is not None else 0
        self.conn.execute("DELETE FROM remediation_actions")
        self.conn.commit()
        return removed

    def count_monitor_events_since(self, since_timestamp: str) -> int:
        rows = self.conn.execute("SELECT timestamp FROM background_monitor_events WHERE timestamp >= ?", (since_timestamp,)).fetchall()
        return len(rows)

    def latest_monitor_event_timestamp(self) -> str:
        row = self.conn.execute("SELECT timestamp FROM background_monitor_events ORDER BY timestamp DESC LIMIT 1").fetchone()
        return str(row["timestamp"]) if row else ""

    def set_background_monitor_state(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO background_monitor_state (key, value) VALUES (?, ?)",
            (key, value),
        )
        self.conn.commit()

    def record_monitor_heartbeat(self, timestamp: str) -> None:
        self.conn.execute(
            "INSERT INTO background_monitor_heartbeats (timestamp, status_json) VALUES (?, ?)",
            (timestamp, "{}"),
        )
        self.conn.commit()
        self.set_background_monitor_state("last_heartbeat", timestamp)

    def latest_monitor_heartbeat(self) -> str:
        row = self.conn.execute("SELECT timestamp FROM background_monitor_heartbeats ORDER BY heartbeat_id DESC LIMIT 1").fetchone()
        return str(row["timestamp"]) if row else self.get_background_monitor_state("last_heartbeat", "")

    def get_background_monitor_state(self, key: str, default: str = "") -> str:
        row = self.conn.execute("SELECT value FROM background_monitor_state WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else default

    def record_event_alert_trace(self, trace: EventAlertTrace | dict[str, Any]) -> None:
        payload = trace.to_dict() if hasattr(trace, "to_dict") else dict(trace)
        self.conn.execute(
            """
            INSERT OR REPLACE INTO event_alert_traces
            (trace_id, event_id, event_type, original_event_type, normalized_event_type, detector_source, created_at, stored_db_path, stored_success, notifier_db_path, notifier_poll_seen, notifier_poll_time, notifier_cursor_before, notifier_cursor_after, notifier_seen, notifier_seen_at, notification_policy_checked, notification_policy_result, notification_policy_reason, severity_before_policy, severity_after_policy, cooldown_checked, cooldown_result, alert_required, alert_suppressed, alert_suppression_reason, alert_queue_enqueued, alert_queue_length_before, alert_queue_length_after, overlay_dispatch_attempted, overlay_dispatch_at, overlay_dispatch_result, overlay_error, visible_alert_id, displayed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(payload.get("trace_id", "")),
                str(payload.get("event_id", "")),
                str(payload.get("event_type", "")),
                str(payload.get("original_event_type", "")),
                str(payload.get("normalized_event_type", "")),
                str(payload.get("detector_source", "")),
                str(payload.get("created_at", utc_now_iso())),
                str(payload.get("stored_db_path", "")),
                int(bool(payload.get("stored_success", False))),
                str(payload.get("notifier_db_path", "")),
                int(bool(payload.get("notifier_poll_seen", False))),
                str(payload.get("notifier_poll_time", "")),
                str(payload.get("notifier_cursor_before", "")),
                str(payload.get("notifier_cursor_after", "")),
                int(bool(payload.get("notifier_seen", False))),
                str(payload.get("notifier_seen_at", "")),
                int(bool(payload.get("notification_policy_checked", False))),
                str(payload.get("notification_policy_result", "")),
                str(payload.get("notification_policy_reason", "")),
                str(payload.get("severity_before_policy", "")),
                str(payload.get("severity_after_policy", "")),
                int(bool(payload.get("cooldown_checked", False))),
                str(payload.get("cooldown_result", "")),
                int(bool(payload.get("alert_required", False))),
                int(bool(payload.get("alert_suppressed", False))),
                str(payload.get("alert_suppression_reason", "")),
                int(bool(payload.get("alert_queue_enqueued", False))),
                int(payload.get("alert_queue_length_before", 0) or 0),
                int(payload.get("alert_queue_length_after", 0) or 0),
                int(bool(payload.get("overlay_dispatch_attempted", False))),
                str(payload.get("overlay_dispatch_at", "")),
                str(payload.get("overlay_dispatch_result", "")),
                str(payload.get("overlay_error", "")),
                str(payload.get("visible_alert_id", "")),
                str(payload.get("displayed_at", "")),
            ),
        )
        self.conn.commit()

    def update_event_alert_trace(self, trace_id: str, **updates: Any) -> None:
        if not updates:
            return
        assignments = ", ".join(f"{key} = ?" for key in updates)
        values = [int(bool(value)) if isinstance(value, bool) else value for value in updates.values()]
        values.append(trace_id)
        self.conn.execute(f"UPDATE event_alert_traces SET {assignments} WHERE trace_id = ?", values)
        self.conn.commit()

    def get_event_alert_trace(self, event_id: str) -> EventAlertTrace | None:
        row = self.conn.execute(
            "SELECT * FROM event_alert_traces WHERE event_id = ? OR trace_id = ? ORDER BY created_at DESC LIMIT 1",
            (event_id, event_id),
        ).fetchone()
        if not row:
            return None
        return EventAlertTrace(
            trace_id=str(row["trace_id"]),
            event_id=str(row["event_id"]),
            event_type=str(row["event_type"]),
            original_event_type=str(row["original_event_type"] or ""),
            normalized_event_type=str(row["normalized_event_type"] or ""),
            detector_source=str(row["detector_source"] or ""),
            created_at=str(row["created_at"]),
            stored_db_path=str(row["stored_db_path"] or ""),
            stored_success=bool(row["stored_success"]),
            notifier_db_path=str(row["notifier_db_path"] or ""),
            notifier_poll_seen=bool(row["notifier_poll_seen"]),
            notifier_poll_time=str(row["notifier_poll_time"] or ""),
            notifier_cursor_before=str(row["notifier_cursor_before"] or ""),
            notifier_cursor_after=str(row["notifier_cursor_after"] or ""),
            notifier_seen=bool(row["notifier_seen"]),
            notifier_seen_at=str(row["notifier_seen_at"] or ""),
            notification_policy_checked=bool(row["notification_policy_checked"]),
            notification_policy_result=str(row["notification_policy_result"] or ""),
            notification_policy_reason=str(row["notification_policy_reason"] or ""),
            severity_before_policy=str(row["severity_before_policy"] or ""),
            severity_after_policy=str(row["severity_after_policy"] or ""),
            cooldown_checked=bool(row["cooldown_checked"]),
            cooldown_result=str(row["cooldown_result"] or ""),
            alert_required=bool(row["alert_required"]),
            alert_suppressed=bool(row["alert_suppressed"]),
            alert_suppression_reason=str(row["alert_suppression_reason"] or ""),
            alert_queue_enqueued=bool(row["alert_queue_enqueued"]),
            alert_queue_length_before=safe_int(row["alert_queue_length_before"]) or 0,
            alert_queue_length_after=safe_int(row["alert_queue_length_after"]) or 0,
            overlay_dispatch_attempted=bool(row["overlay_dispatch_attempted"]),
            overlay_dispatch_at=str(row["overlay_dispatch_at"] or ""),
            overlay_dispatch_result=str(row["overlay_dispatch_result"] or ""),
            overlay_error=str(row["overlay_error"] or ""),
            visible_alert_id=str(row["visible_alert_id"] or ""),
            displayed_at=str(row["displayed_at"] or ""),
        )

    def latest_event_alert_traces(self, limit: int = 25) -> list[EventAlertTrace]:
        rows = self.conn.execute("SELECT event_id FROM event_alert_traces ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        traces: list[EventAlertTrace] = []
        for row in rows:
            trace = self.get_event_alert_trace(str(row["event_id"]))
            if trace is not None:
                traces.append(trace)
        return traces

    def record_notification_capabilities(self, capabilities: NotificationCapabilities | dict[str, Any], *, scope: str = "current") -> None:
        payload = capabilities.to_dict() if hasattr(capabilities, "to_dict") else dict(capabilities)
        self.conn.execute(
            """
            INSERT OR REPLACE INTO notification_capabilities (scope, updated_at, payload_json)
            VALUES (?, ?, ?)
            """,
            (scope, payload.get("last_test_time", utc_now_iso()), json.dumps(payload, sort_keys=True)),
        )
        self.conn.commit()

    def latest_notification_capabilities(self, scope: str = "current") -> NotificationCapabilities | None:
        row = self.conn.execute(
            "SELECT * FROM notification_capabilities WHERE scope = ? ORDER BY updated_at DESC LIMIT 1",
            (scope,),
        ).fetchone()
        if not row:
            return None
        try:
            payload = json.loads(str(row["payload_json"] or "{}"))
        except json.JSONDecodeError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        return NotificationCapabilities(
            overlay_available=bool(payload.get("overlay_available", False)),
            applescript_dialog_available=bool(payload.get("applescript_dialog_available", False)),
            notification_center_available=bool(payload.get("notification_center_available", False)),
            osascript_exists=bool(payload.get("osascript_exists", False)),
            last_test_time=str(payload.get("last_test_time", row["updated_at"] or "")),
            last_test_result=str(payload.get("last_test_result", "")),
        )

    def record_alert_delivery(self, record: AlertDeliveryRecord | dict[str, Any]) -> None:
        payload = record.to_dict() if hasattr(record, "to_dict") else dict(record)
        self.conn.execute(
            """
            INSERT OR REPLACE INTO alert_delivery_records
            (event_id, alert_type, overlay_attempted, overlay_success, dialog_attempted, dialog_success, notification_attempted, notification_success, delivery_method_used, updated_at, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(payload.get("event_id", "")),
                str(payload.get("alert_type", "")),
                int(bool(payload.get("overlay_attempted", False))),
                int(bool(payload.get("overlay_success", False))),
                int(bool(payload.get("dialog_attempted", False))),
                int(bool(payload.get("dialog_success", False))),
                int(bool(payload.get("notification_attempted", False))),
                int(bool(payload.get("notification_success", False))),
                str(payload.get("delivery_method_used", "")),
                str(payload.get("updated_at", utc_now_iso())),
                json.dumps(payload, sort_keys=True),
            ),
        )
        self.conn.commit()

    def latest_alert_delivery_records(self, limit: int = 25) -> list[AlertDeliveryRecord]:
        rows = self.conn.execute("SELECT event_id FROM alert_delivery_records ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
        records: list[AlertDeliveryRecord] = []
        for row in rows:
            record_row = self.conn.execute("SELECT * FROM alert_delivery_records WHERE event_id = ?", (str(row["event_id"]),)).fetchone()
            if not record_row:
                continue
            try:
                payload = json.loads(str(record_row["payload_json"] or "{}"))
            except json.JSONDecodeError:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            records.append(
                AlertDeliveryRecord(
                    event_id=str(record_row["event_id"]),
                    alert_type=str(record_row["alert_type"]),
                    overlay_attempted=bool(record_row["overlay_attempted"]),
                    overlay_success=bool(record_row["overlay_success"]),
                    dialog_attempted=bool(record_row["dialog_attempted"]),
                    dialog_success=bool(record_row["dialog_success"]),
                    notification_attempted=bool(record_row["notification_attempted"]),
                    notification_success=bool(record_row["notification_success"]),
                    delivery_method_used=str(record_row["delivery_method_used"] or ""),
                    updated_at=str(record_row["updated_at"] or ""),
                    payload_json=json.dumps(payload, sort_keys=True),
                )
            )
        return records

    def get_background_monitor_status(self) -> BackgroundMonitorStatus:
        now = datetime.now(timezone.utc)
        last_10_minutes = (now - timedelta(minutes=10)).isoformat()
        return BackgroundMonitorStatus(
            installed=self.get_background_monitor_state("installed", "0") == "1",
            loaded=self.get_background_monitor_state("loaded", "0") == "1",
            running=self.get_background_monitor_state("running", "0") == "1",
            enabled=self.get_background_monitor_state("enabled", "0") == "1",
            plist_path=self.get_background_monitor_state("plist_path", ""),
            label=self.get_background_monitor_state("label", ""),
            log_path=self.get_background_monitor_state("log_path", ""),
            db_path=self.get_background_monitor_state("db_path", str(self.path)),
            process_pid=safe_int(self.get_background_monitor_state("process_pid", "")),
            last_heartbeat=self.latest_monitor_heartbeat(),
            last_event_timestamp=self.get_background_monitor_state("last_event_timestamp", self.latest_monitor_event_timestamp()),
            last_error=self.get_background_monitor_state("last_error", ""),
            notification_status=self.get_background_monitor_state("notification_status", "unknown"),
            current_launchctl_domain=self.get_background_monitor_state("current_launchctl_domain", ""),
            detector_errors=self.get_background_monitor_state("detector_errors", ""),
            events_last_10_minutes=self.count_monitor_events_since(last_10_minutes),
            detector_last_run_timestamp=self.get_background_monitor_state("detector_last_run_timestamp", ""),
            detector_last_run_counts=self.get_background_monitor_state("detector_last_run_counts", ""),
            detector_enabled_camera=self.get_background_monitor_state("detector_enabled_camera", "0") == "1",
            detector_enabled_session=self.get_background_monitor_state("detector_enabled_session", "0") == "1",
            detector_enabled_network=self.get_background_monitor_state("detector_enabled_network", "0") == "1",
            detector_enabled_persistence=self.get_background_monitor_state("detector_enabled_persistence", "0") == "1",
            detector_enabled_sharing=self.get_background_monitor_state("detector_enabled_sharing", "0") == "1",
            detector_enabled_process=self.get_background_monitor_state("detector_enabled_process", "0") == "1",
            detector_enabled_hardware=self.get_background_monitor_state("detector_enabled_hardware", "0") == "1",
            detector_last_zero_reason=self.get_background_monitor_state("detector_last_zero_reason", ""),
            status_text=self.get_background_monitor_state("status_text", ""),
            current_snapshot=self.get_background_monitor_state("current_monitor_snapshot", ""),
        )

    def record_legal_notice_acknowledgement(self, notice_version: str, payload: dict[str, Any] | None = None) -> None:
        acknowledged_at = utc_now_iso()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO legal_notice_acknowledgements
            (notice_version, acknowledged_at, acknowledged, payload_json)
            VALUES (?, ?, ?, ?)
            """,
            (notice_version, acknowledged_at, 1, json.dumps(payload or {}, sort_keys=True)),
        )
        self.conn.commit()

    def legal_notice_acknowledged(self, notice_version: str) -> bool:
        row = self.conn.execute(
            "SELECT acknowledged FROM legal_notice_acknowledgements WHERE notice_version = ?",
            (notice_version,),
        ).fetchone()
        return bool(row and int(row["acknowledged"]) == 1)

    def record_security_decoy_connection(self, payload: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO security_decoy_connections
            (connection_id, timestamp, source_ip, source_port, destination_port, listen_address, protocol_profile, bytes_sent, bytes_received, connection_count, first_seen, last_seen, correlation_id, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(payload.get("connection_id", "")),
                str(payload.get("timestamp", "")),
                str(payload.get("source_ip", "")),
                safe_int(payload.get("source_port")) or 0,
                safe_int(payload.get("destination_port")) or 0,
                str(payload.get("listen_address", "")),
                str(payload.get("protocol_profile", "")),
                safe_int(payload.get("bytes_sent")) or 0,
                safe_int(payload.get("bytes_received")) or 0,
                safe_int(payload.get("connection_count")) or 1,
                str(payload.get("first_seen", "")),
                str(payload.get("last_seen", "")),
                str(payload.get("correlation_id", "")),
                json.dumps(payload.get("payload_json", payload), sort_keys=True),
            ),
        )
        self.conn.commit()

    def list_security_decoy_connections(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM security_decoy_connections ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["payload_json"] = json.loads(item.get("payload_json", "{}") or "{}")
            except json.JSONDecodeError:
                item["payload_json"] = {}
            results.append(item)
        return results

    def security_decoy_summary(self, limit: int = 500) -> dict[str, Any]:
        connections = self.list_security_decoy_connections(limit=limit)
        by_source: dict[str, dict[str, Any]] = {}
        for item in connections:
            source = str(item.get("source_ip", ""))
            if not source:
                continue
            summary = by_source.setdefault(
                source,
                {
                    "source_ip": source,
                    "connection_count": 0,
                    "first_seen": str(item.get("first_seen", "")),
                    "last_seen": str(item.get("last_seen", "")),
                    "protocols": set(),
                    "destination_ports": set(),
                },
            )
            summary["connection_count"] += int(item.get("connection_count") or 1)
            summary["protocols"].add(str(item.get("protocol_profile", "")))
            summary["destination_ports"].add(int(item.get("destination_port") or 0))
            summary["first_seen"] = min(str(summary["first_seen"]), str(item.get("first_seen", ""))) if summary["first_seen"] else str(item.get("first_seen", ""))
            summary["last_seen"] = max(str(summary["last_seen"]), str(item.get("last_seen", ""))) if summary["last_seen"] else str(item.get("last_seen", ""))
        top_sources = []
        for item in by_source.values():
            top_sources.append(
                {
                    "source_ip": item["source_ip"],
                    "connection_count": item["connection_count"],
                    "first_seen": item["first_seen"],
                    "last_seen": item["last_seen"],
                    "protocols": sorted(item["protocols"]),
                    "destination_ports": sorted(port for port in item["destination_ports"] if port),
                }
            )
        top_sources.sort(key=lambda item: int(item.get("connection_count", 0)), reverse=True)
        return {
            "connection_count": sum(int(item.get("connection_count") or 1) for item in connections),
            "unique_sources": len(by_source),
            "top_sources": top_sources[:20],
            "connections": connections,
        }

    def save_investigation_note(self, note: InvestigationNote) -> str:
        note_id = note.note_id or f"note-{uuid4()}"
        created_at = note.created_at or utc_now_iso()
        updated_at = note.updated_at or utc_now_iso()
        existing = self.conn.execute("SELECT note_id FROM investigation_notes WHERE note_id = ?", (note_id,)).fetchone()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO investigation_notes
            (note_id, created_at, updated_at, title, body, tags, linked_finding_id, linked_scan_id, status, priority, investigator_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                note_id,
                created_at,
                updated_at,
                note.title,
                note.body,
                json.dumps(note.tags),
                note.linked_finding_id,
                note.linked_scan_id,
                note.status,
                note.priority,
                note.investigator_name,
            ),
        )
        self._record_investigation_audit(
            action_type="note edited" if existing else "note created",
            entity_type="note",
            entity_id=note_id,
            details=note.title,
        )
        self.conn.commit()
        return note_id

    def list_investigation_notes(
        self,
        *,
        linked_scan_id: str | None = None,
        linked_finding_id: str | None = None,
        limit: int = 500,
    ) -> list[InvestigationNote]:
        clauses = []
        params: list[Any] = []
        if linked_scan_id is not None:
            clauses.append("linked_scan_id = ?")
            params.append(linked_scan_id)
        if linked_finding_id is not None:
            clauses.append("linked_finding_id = ?")
            params.append(linked_finding_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.conn.execute(
            f"SELECT * FROM investigation_notes {where} ORDER BY updated_at DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
        return [
            InvestigationNote(
                note_id=row["note_id"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                title=row["title"],
                body=row["body"],
                tags=json.loads(row["tags"] or "[]"),
                linked_finding_id=row["linked_finding_id"],
                linked_scan_id=row["linked_scan_id"],
                status=row["status"],
                priority=row["priority"],
                investigator_name=row["investigator_name"],
            )
            for row in rows
        ]

    def get_general_investigation_note(self, linked_scan_id: str) -> InvestigationNote:
        for note in self.list_investigation_notes(linked_scan_id=linked_scan_id):
            if note.title == "Investigation Overview" and not note.linked_finding_id:
                return note
        timestamp = utc_now_iso()
        return InvestigationNote(
            note_id=f"note-{uuid4()}",
            created_at=timestamp,
            updated_at=timestamp,
            title="Investigation Overview",
            body="",
            linked_scan_id=linked_scan_id,
        )

    def set_review_status(
        self,
        *,
        item_type: str,
        item_key: str,
        label: str,
        review_state: str,
        linked_scan_id: str,
        linked_finding_id: str = "",
        notes: str = "",
    ) -> None:
        previous = self.conn.execute(
            "SELECT review_state FROM review_checklist WHERE item_type = ? AND item_key = ? AND linked_scan_id = ?",
            (item_type, item_key, linked_scan_id),
        ).fetchone()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO review_checklist
            (item_type, item_key, label, review_state, linked_scan_id, linked_finding_id, updated_at, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (item_type, item_key, label, review_state, linked_scan_id, linked_finding_id, utc_now_iso(), notes),
        )
        self._record_investigation_audit(
            action_type="review status changed",
            entity_type=item_type,
            entity_id=item_key,
            previous_status=str(previous["review_state"]) if previous else "",
            new_status=review_state,
            details=label,
        )
        self.conn.commit()
        if item_type == "finding" and review_state in {"false positive", "resolved"} and linked_finding_id:
            finding = self.get_finding_by_id(linked_finding_id)
            if finding is not None:
                self.record_finding_suppression(finding, review_state=review_state, rationale=notes or label)

    def get_review_statuses(self, linked_scan_id: str) -> dict[tuple[str, str], ReviewChecklistItem]:
        rows = self.conn.execute(
            "SELECT * FROM review_checklist WHERE linked_scan_id = ? ORDER BY updated_at DESC",
            (linked_scan_id,),
        ).fetchall()
        return {
            (row["item_type"], row["item_key"]): ReviewChecklistItem(
                item_type=row["item_type"],
                item_key=row["item_key"],
                label=row["label"],
                review_state=row["review_state"],
                linked_scan_id=row["linked_scan_id"],
                linked_finding_id=row["linked_finding_id"],
                updated_at=row["updated_at"],
                notes=row["notes"],
            )
            for row in rows
        }

    def record_finding_suppression(self, finding: Finding, *, review_state: str, rationale: str = "") -> None:
        fingerprint = self._finding_fingerprint(finding)
        timestamp = utc_now_iso()
        existing = self.conn.execute(
            "SELECT matched_count, first_seen_at FROM finding_suppression_rules WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        matched_count = int(existing["matched_count"]) + 1 if existing else 1
        first_seen_at = str(existing["first_seen_at"]) if existing else timestamp
        self.conn.execute(
            """
            INSERT OR REPLACE INTO finding_suppression_rules
            (fingerprint, title, category, severity, review_state, rationale, active, matched_count, first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fingerprint,
                finding.title,
                finding.category,
                finding.severity,
                review_state,
                rationale,
                1,
                matched_count,
                first_seen_at,
                timestamp,
            ),
        )
        self._record_investigation_audit(
            action_type="finding suppression learned",
            entity_type="finding",
            entity_id=fingerprint,
            previous_status=review_state,
            new_status="active",
            details=f"{finding.category}: {finding.title}",
        )
        self.conn.commit()

    def list_finding_suppressions(self, limit: int = 500) -> list[FindingSuppressionRule]:
        rows = self.conn.execute(
            "SELECT * FROM finding_suppression_rules ORDER BY last_seen_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            FindingSuppressionRule(
                fingerprint=str(row["fingerprint"]),
                title=str(row["title"]),
                category=str(row["category"]),
                severity=str(row["severity"]),
                review_state=str(row["review_state"]),
                rationale=str(row["rationale"]),
                active=bool(row["active"]),
                matched_count=int(row["matched_count"]),
                first_seen_at=str(row["first_seen_at"]),
                last_seen_at=str(row["last_seen_at"]),
            )
            for row in rows
        ]

    def find_suppression_rule(self, finding: Finding | dict[str, Any]) -> FindingSuppressionRule | None:
        fingerprint = self._finding_fingerprint(finding)
        row = self.conn.execute("SELECT * FROM finding_suppression_rules WHERE fingerprint = ?", (fingerprint,)).fetchone()
        if not row:
            return None
        return FindingSuppressionRule(
            fingerprint=str(row["fingerprint"]),
            title=str(row["title"]),
            category=str(row["category"]),
            severity=str(row["severity"]),
            review_state=str(row["review_state"]),
            rationale=str(row["rationale"]),
            active=bool(row["active"]),
            matched_count=int(row["matched_count"]),
            first_seen_at=str(row["first_seen_at"]),
            last_seen_at=str(row["last_seen_at"]),
        )

    def _finding_fingerprint(self, finding: Finding | dict[str, Any]) -> str:
        if hasattr(finding, "to_dict"):
            payload = finding.to_dict()
        elif isinstance(finding, dict):
            payload = dict(finding)
        else:
            payload = dict(getattr(finding, "__dict__", {}))
        evidence = str(payload.get("evidence_summary") or payload.get("evidence") or payload.get("recommendation") or "")
        basis = {
            "category": str(payload.get("category", "")),
            "title": str(payload.get("title", "")),
            "severity": str(payload.get("severity", "")),
            "command": str(payload.get("command_used") or payload.get("command_or_source") or ""),
            "evidence": evidence[:240],
        }
        return hashlib.sha256(json.dumps(basis, sort_keys=True).encode("utf-8")).hexdigest()

    def investigation_progress(self, linked_scan_id: str, total_findings: int) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT review_state, COUNT(*) AS count FROM review_checklist WHERE linked_scan_id = ? AND item_type = 'finding' GROUP BY review_state",
            (linked_scan_id,),
        ).fetchall()
        counts = {str(row["review_state"]): int(row["count"]) for row in rows}
        reviewed = counts.get("reviewed", 0)
        follow_up = counts.get("needs follow-up", 0)
        confirmed = counts.get("confirmed concern", 0)
        false_positives = counts.get("false positive", 0)
        completed = reviewed + follow_up + confirmed + false_positives
        unreviewed = max(total_findings - completed, 0)
        return {
            "total_findings": total_findings,
            "reviewed_count": reviewed,
            "unreviewed_count": unreviewed,
            "follow_up_count": follow_up,
            "confirmed_concerns": confirmed,
            "false_positives": false_positives,
            "progress_percentage": int((completed / total_findings) * 100) if total_findings else 0,
        }

    def list_investigation_audit_trail(self, limit: int = 500) -> list[InvestigationAuditEntry]:
        rows = self.conn.execute(
            "SELECT * FROM investigation_audit_trail ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            InvestigationAuditEntry(
                audit_id=row["audit_id"],
                timestamp=row["timestamp"],
                action_type=row["action_type"],
                entity_type=row["entity_type"],
                entity_id=row["entity_id"],
                previous_status=row["previous_status"],
                new_status=row["new_status"],
                details=row["details"],
            )
            for row in rows
        ]

    def investigation_audit_trail_between(self, start_timestamp: str, end_timestamp: str) -> list[InvestigationAuditEntry]:
        rows = self.conn.execute(
            """
            SELECT * FROM investigation_audit_trail
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC
            """,
            (start_timestamp, end_timestamp),
        ).fetchall()
        return [
            InvestigationAuditEntry(
                audit_id=row["audit_id"],
                timestamp=row["timestamp"],
                action_type=row["action_type"],
                entity_type=row["entity_type"],
                entity_id=row["entity_id"],
                previous_status=row["previous_status"],
                new_status=row["new_status"],
                details=row["details"],
            )
            for row in rows
        ]

    def _record_investigation_audit(
        self,
        *,
        action_type: str,
        entity_type: str,
        entity_id: str,
        previous_status: str = "",
        new_status: str = "",
        details: str = "",
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO investigation_audit_trail
            (timestamp, action_type, entity_type, entity_id, previous_status, new_status, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (utc_now_iso(), action_type, entity_type, entity_id, previous_status, new_status, details),
        )

    def get_scan_bundle(self, scan_id: str) -> dict:
        return {
            "ports": self._load_snapshots(scan_id, "port_snapshots", PortSnapshot),
            "users": self._load_snapshots(scan_id, "user_snapshots", UserSnapshot),
            "history": self._load_snapshots(scan_id, "history_indicators", HistoryIndicator),
            "permissions": self._load_snapshots(scan_id, "permission_snapshots", PermissionSnapshot),
            "files": self._load_snapshots(scan_id, "file_snapshots", FileIssueSnapshot),
            "processes": self._load_snapshots(scan_id, "process_snapshots", ProcessSnapshot),
            "launch_snapshots": self._load_snapshots(scan_id, "launch_item_snapshots", LaunchItemSnapshot, ignore_null_payload=True),
            "launch_items": set(
                row["item_key"]
                for row in self.conn.execute("SELECT item_key FROM launch_item_snapshots WHERE scan_id = ?", (scan_id,))
            ),
            "network_discovery": self._load_network_discovery(scan_id),
        }

    def _load_network_discovery(self, scan_id: str) -> dict[str, Any]:
        row = self.conn.execute("SELECT payload_json FROM network_discovery_runs WHERE scan_id = ?", (scan_id,)).fetchone()
        if not row:
            return {"hosts": [], "devices": [], "comparison": {}, "interface": "", "subnet": "", "gateway": "", "gateway_ip": "", "gateway_mac": "", "scope": "", "review_needed_count": 0, "debug_logs": [], "errors": []}
        try:
            payload = json.loads(row["payload_json"])
        except json.JSONDecodeError:
            return {"hosts": [], "devices": [], "comparison": {}, "interface": "", "subnet": "", "gateway": "", "gateway_ip": "", "gateway_mac": "", "scope": "", "review_needed_count": 0, "debug_logs": [], "errors": []}
        if not isinstance(payload, dict):
            return {"hosts": [], "devices": [], "comparison": {}, "interface": "", "subnet": "", "gateway": "", "gateway_ip": "", "gateway_mac": "", "scope": "", "review_needed_count": 0, "debug_logs": [], "errors": []}
        payload["hosts"] = self._safe_load_items(payload.get("hosts", payload.get("devices", [])), NetworkHostSnapshot)
        payload["devices"] = payload["hosts"]
        return payload

    def latest_network_discovery(self) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT payload_json FROM network_discovery_runs ORDER BY rowid DESC LIMIT 1").fetchone()
        if not row:
            return None
        try:
            payload = json.loads(row["payload_json"])
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        payload["hosts"] = self._safe_load_items(payload.get("hosts", payload.get("devices", [])), NetworkHostSnapshot)
        payload["devices"] = payload["hosts"]
        return payload

    def previous_network_discovery(self) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT payload_json FROM network_discovery_runs ORDER BY rowid DESC LIMIT 1 OFFSET 1").fetchone()
        if not row:
            return None
        try:
            payload = json.loads(row["payload_json"])
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        payload["hosts"] = self._safe_load_items(payload.get("hosts", payload.get("devices", [])), NetworkHostSnapshot)
        payload["devices"] = payload["hosts"]
        return payload

    def _load_snapshots(self, scan_id: str, table: str, cls, ignore_null_payload: bool = False):
        rows = self.conn.execute(f"SELECT payload_json FROM {table} WHERE scan_id = ?", (scan_id,)).fetchall()
        loaded = []
        for row in rows:
            if row["payload_json"] is None:
                if ignore_null_payload:
                    continue
                else:
                    continue
            try:
                payload = json.loads(row["payload_json"])
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            payload = self._normalize_numeric_payload(cls, payload)
            try:
                loaded.append(cls(**payload))
            except Exception:
                continue
        return loaded

    def compare_to_previous_scan(self, current_scan_id: str) -> BaselineComparison:
        from mac_audit_agent.analyzers import compare_snapshots

        previous_scan_id = self.previous_scan_id(current_scan_id)
        if previous_scan_id is None:
            return BaselineComparison()
        previous = self.get_scan_bundle(previous_scan_id)
        current = self.get_scan_bundle(current_scan_id)
        return compare_snapshots(
            previous_ports=previous["ports"],
            current_ports=current["ports"],
            previous_users=previous["users"],
            current_users=current["users"],
            previous_permissions=previous["permissions"],
            current_permissions=current["permissions"],
            previous_history=previous["history"],
            current_history=current["history"],
            previous_files=previous["files"],
            current_files=current["files"],
            previous_launch_items=previous["launch_items"],
            current_launch_items=current["launch_items"],
            previous_processes=previous["processes"],
            current_processes=current["processes"],
            previous_launch_snapshots=previous["launch_snapshots"],
            current_launch_snapshots=current["launch_snapshots"],
        )

    def write_scan_logs(self, scan_id: str, payload: dict) -> None:
        scan_dir = self.logs_dir / scan_id
        scan_dir.mkdir(parents=True, exist_ok=True)
        ports = payload.get("ports", {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []})
        processes = payload.get("processes", {"all": [], "suspicious": [], "errors": []})
        self._write_jsonl(scan_dir / "findings.jsonl", [item.to_dict() for item in payload["findings"]])
        self._write_jsonl(scan_dir / "command_outputs.jsonl", [item.to_dict() for item in payload["command_results"]])
        self._write_jsonl(scan_dir / "ports.jsonl", [item.to_dict() for item in ports.get("listening", [])])
        self._write_jsonl(scan_dir / "ports_active_connections.jsonl", [item.to_dict() for item in ports.get("active_connections", [])])
        self._write_jsonl(scan_dir / "ports_review_needed.jsonl", [item.to_dict() for item in ports.get("suspicious_review_needed", [])])
        self._write_jsonl(scan_dir / "ports_errors.jsonl", [{"error": item} for item in ports.get("errors", [])])
        self._write_jsonl(scan_dir / "users.jsonl", [item.to_dict() for item in payload["users"]])
        self._write_jsonl(scan_dir / "history_indicators.jsonl", [item.to_dict() for item in payload["history_indicators"]])
        self._write_jsonl(scan_dir / "permissions.jsonl", [item.to_dict() for item in payload["permission_snapshots"]])
        self._write_jsonl(scan_dir / "files.jsonl", [item.to_dict() for item in payload["file_issues"]])
        self._write_jsonl(scan_dir / "processes.jsonl", [item.to_dict() for item in processes.get("all", [])])
        self._write_jsonl(scan_dir / "processes_suspicious.jsonl", [item.to_dict() for item in processes.get("suspicious", [])])
        self._write_jsonl(scan_dir / "processes_errors.jsonl", [{"error": item} for item in processes.get("errors", [])])
        self._write_jsonl(scan_dir / "launch_items.jsonl", [item.to_dict() for item in payload["launch_snapshots"]])
        self._write_jsonl(scan_dir / "baseline_comparison.jsonl", [payload["comparison"].to_dict()])
        if "raw_logs" in payload:
            self._write_jsonl(scan_dir / "raw_logs.jsonl", [item.to_dict() for item in payload["raw_logs"]])
        if "remediation_actions" in payload:
            self._write_jsonl(scan_dir / "remediation_actions.jsonl", payload["remediation_actions"])

    def _write_jsonl(self, path: Path, rows: list[dict]) -> None:
        with path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")

    def prune_old_logs(self) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.log_retention_days)
        for child in self.logs_dir.iterdir():
            try:
                modified = datetime.fromtimestamp(child.stat().st_mtime, tz=timezone.utc)
            except OSError:
                continue
            if modified < cutoff:
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)

    def export_snapshot(self) -> dict:
        return {
            "scans": [dict(row) for row in self.conn.execute("SELECT * FROM scans ORDER BY completed_at DESC")],
            "findings": [dict(row) for row in self.conn.execute("SELECT * FROM findings ORDER BY created_at DESC")],
            "cve_radar_cache": [dict(row) for row in self.conn.execute("SELECT * FROM cve_radar_cache ORDER BY updated_at DESC")],
            "cve_radar_alerts": [self._cve_radar_alert_from_row(row) for row in self.conn.execute("SELECT * FROM cve_radar_alerts ORDER BY last_seen DESC")],
            "cve_radar_reviews": [item for item in self.list_cve_radar_reviews(limit=5000)],
            "cve_radar_inventory": [dict(row) for row in self.conn.execute("SELECT * FROM cve_radar_inventory ORDER BY collected_at DESC")],
            "apple_security_forecasts": [dict(row) for row in self.conn.execute("SELECT * FROM apple_security_forecasts ORDER BY generated_at DESC")],
            "apple_security_forecast_cards": [dict(row) for row in self.conn.execute("SELECT * FROM apple_security_forecast_cards ORDER BY forecast_id DESC, card_id ASC")],
            "apple_security_cve_cache": [dict(row) for row in self.conn.execute("SELECT * FROM apple_security_cve_cache ORDER BY updated_at DESC")],
            "apple_security_review_state": [dict(row) for row in self.conn.execute("SELECT * FROM apple_security_review_state ORDER BY reviewed_at DESC")],
            "system_recovery_baselines": [dict(row) for row in self.conn.execute("SELECT * FROM system_recovery_baselines ORDER BY observed_at DESC")],
            "system_recovery_snapshots": [dict(row) for row in self.conn.execute("SELECT * FROM system_recovery_snapshots ORDER BY created_at DESC")],
            "system_cleanup_actions": [dict(row) for row in self.conn.execute("SELECT * FROM system_cleanup_actions ORDER BY created_at DESC")],
            "command_logs": [dict(row) for row in self.conn.execute("SELECT * FROM command_logs ORDER BY executed_at DESC")],
            "user_approvals": [dict(row) for row in self.conn.execute("SELECT * FROM user_approvals ORDER BY approved_at DESC")],
            "remediation_actions": [dict(row) for row in self.conn.execute("SELECT * FROM remediation_actions ORDER BY created_at DESC")],
            "background_monitor_events": [item.to_dict() for item in self.recent_background_monitor_events(limit=1000)],
            "background_monitor_state": [dict(row) for row in self.conn.execute("SELECT * FROM background_monitor_state ORDER BY key ASC")],
            "investigation_notes": [item.to_dict() for item in self.list_investigation_notes(limit=5000)],
            "review_checklist": [dict(row) for row in self.conn.execute("SELECT * FROM review_checklist ORDER BY updated_at DESC")],
            "investigation_audit_trail": [item.to_dict() for item in self.list_investigation_audit_trail(limit=5000)],
        }

    def write_json_export(self, output_path: Path) -> None:
        output_path.write_text(json.dumps(self.export_snapshot(), indent=2), encoding="utf-8")
