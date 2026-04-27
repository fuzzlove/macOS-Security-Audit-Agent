from __future__ import annotations

import ipaddress
import json
import logging
import shutil
import sqlite3
from dataclasses import fields, is_dataclass, asdict
from datetime import date, datetime, time as datetime_time, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from mac_audit_agent.models import (
    BaselineComparison,
    BackgroundMonitorEvent,
    BackgroundMonitorStatus,
    CommandExecutionResult,
    FileIssueSnapshot,
    Finding,
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

LOGGER = logging.getLogger(__name__)
FINDING_FIELD_NAMES = {item.name for item in fields(Finding)}


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
    }


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
        :created_at
    )
    """

    def __init__(self, path: Path, logs_dir: Path | None = None, log_retention_days: int = 30) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.logs_dir = logs_dir or (Path.home() / ".mac_audit_agent" / "logs")
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.log_retention_days = log_retention_days
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

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
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS background_monitor_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS background_monitor_heartbeats (
                heartbeat_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                status_json TEXT NOT NULL DEFAULT '{}'
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
        self._ensure_column("network_discovery_runs", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("network_discovery_hosts", "payload_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column("background_monitor_events", "simulated", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("background_monitor_events", "notification_sent", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("background_monitor_events", "notification_error", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("background_monitor_events", "notification_returncode", "INTEGER")
        self._ensure_column("background_monitor_events", "notification_decision", "TEXT NOT NULL DEFAULT 'log_only'")
        self._ensure_column("background_monitor_events", "notification_reason", "TEXT NOT NULL DEFAULT ''")
        self._ensure_column("background_monitor_events", "cooldown_remaining_seconds", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("background_monitor_events", "popup_allowed", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("background_monitor_events", "metadata_json", "TEXT NOT NULL DEFAULT '{}'")
        self._migrate_command_logs_exit_code_nullable()
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

    def record_scan_result(self, scan_result: ScanResult) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO scan_results (scan_id, payload_json) VALUES (?, ?)",
            (scan_result.scan_id, json.dumps(json_safe(scan_result.to_dict()))),
        )
        self.conn.commit()

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
        return [dict(row) for row in rows]

    def record_background_monitor_event(self, event: BackgroundMonitorEvent, dedupe_window_seconds: int = 60) -> bool:
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
        if row:
            try:
                event_ts = datetime.fromisoformat(event.timestamp)
                last_ts = datetime.fromisoformat(str(row["timestamp"]))
            except ValueError:
                event_ts = None
                last_ts = None
            if event_ts and last_ts and (event_ts - last_ts).total_seconds() < dedupe_window_seconds:
                return False
        if row and not dedupe_window_seconds:
            return False
        self.conn.execute(
            """
            INSERT OR REPLACE INTO background_monitor_events
            (event_id, timestamp, event_type, severity, source, process_name, pid, evidence, confidence, recommendation, simulated, notification_sent, notification_error, notification_returncode, notification_decision, notification_reason, cooldown_remaining_seconds, popup_allowed, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                event.metadata_json,
            ),
        )
        self.set_background_monitor_state("last_event_timestamp", event.timestamp)
        self.conn.commit()
        return True

    def record_monitor_event(self, event: BackgroundMonitorEvent, dedupe_window_seconds: int = 300) -> bool:
        return self.record_background_monitor_event(event, dedupe_window_seconds=dedupe_window_seconds)

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
    ) -> None:
        self.conn.execute(
            """
            UPDATE background_monitor_events
            SET notification_sent = ?, notification_error = ?, notification_returncode = ?, notification_decision = ?, notification_reason = ?, cooldown_remaining_seconds = ?, popup_allowed = ?
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
            BackgroundMonitorEvent(
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
                metadata_json=str(row["metadata_json"] or "{}"),
            )
            for row in rows
        ]

    def latest_monitor_events(self, limit: int = 100) -> list[BackgroundMonitorEvent]:
        return self.recent_background_monitor_events(limit=limit)

    def clear_monitor_events(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS count FROM background_monitor_events").fetchone()
        removed = int(row["count"]) if row and row["count"] is not None else 0
        self.conn.execute("DELETE FROM background_monitor_events")
        self.conn.commit()
        self.conn.execute("VACUUM")
        self.conn.commit()
        self.set_background_monitor_state("last_event_timestamp", "")
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
            detector_enabled_sharing=self.get_background_monitor_state("detector_enabled_sharing", "0") == "1",
            detector_enabled_process=self.get_background_monitor_state("detector_enabled_process", "0") == "1",
            detector_last_zero_reason=self.get_background_monitor_state("detector_last_zero_reason", ""),
            status_text=self.get_background_monitor_state("status_text", ""),
            current_snapshot=self.get_background_monitor_state("current_monitor_snapshot", ""),
        )

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
