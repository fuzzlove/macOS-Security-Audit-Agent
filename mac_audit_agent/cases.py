from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from mac_audit_agent.evidence_graph import EvidenceGraphBuilder
from mac_audit_agent.models import ScanResult, utc_now_iso
from mac_audit_agent.security_timeline import SecurityTimelineBuilder
from mac_audit_agent.storage import AuditDatabase, json_safe


CaseStatus = Literal["open", "investigating", "resolved", "archived"]


@dataclass
class CaseRecord:
    case_id: str
    title: str
    description: str = ""
    status: CaseStatus = "open"
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    severity: str = "medium"
    notes: list[dict[str, Any]] = field(default_factory=list)
    linked_findings: list[str] = field(default_factory=list)
    linked_events: list[str] = field(default_factory=list)
    linked_snapshots: list[str] = field(default_factory=list)
    linked_reports: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CaseManager:
    def __init__(self, db: AuditDatabase) -> None:
        self.db = db
        self._init_schema()

    def create_case(self, *, title: str, description: str = "", severity: str = "medium", status: CaseStatus = "open") -> CaseRecord:
        timestamp = utc_now_iso()
        case = CaseRecord(
            case_id=f"case-{uuid4()}",
            title=title.strip() or "Untitled Case",
            description=description.strip(),
            severity=severity,
            status=status,
            created_at=timestamp,
            updated_at=timestamp,
        )
        self.save_case(case)
        return case

    def save_case(self, case: CaseRecord) -> None:
        payload = case.to_dict()
        self.db.conn.execute(
            """
            INSERT OR REPLACE INTO cases
            (case_id, title, description, status, created_at, updated_at, severity, notes_json, linked_findings_json, linked_events_json, linked_snapshots_json, linked_reports_json, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case.case_id,
                case.title,
                case.description,
                case.status,
                case.created_at,
                case.updated_at,
                case.severity,
                json.dumps(json_safe(case.notes), sort_keys=True),
                json.dumps(json_safe(case.linked_findings), sort_keys=True),
                json.dumps(json_safe(case.linked_events), sort_keys=True),
                json.dumps(json_safe(case.linked_snapshots), sort_keys=True),
                json.dumps(json_safe(case.linked_reports), sort_keys=True),
                json.dumps(json_safe(payload), sort_keys=True),
            ),
        )
        self.db.conn.commit()

    def get_case(self, case_id: str) -> CaseRecord | None:
        row = self.db.conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        return self._case_from_row(row) if row else None

    def list_cases(self, *, include_archived: bool = True, limit: int = 500) -> list[CaseRecord]:
        if include_archived:
            rows = self.db.conn.execute("SELECT * FROM cases ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
        else:
            rows = self.db.conn.execute("SELECT * FROM cases WHERE status != 'archived' ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._case_from_row(row) for row in rows]

    def link_finding(self, case_id: str, finding_id: str) -> CaseRecord:
        return self._append_link(case_id, "linked_findings", finding_id)

    def link_event(self, case_id: str, event_id: str) -> CaseRecord:
        return self._append_link(case_id, "linked_events", event_id)

    def link_snapshot(self, case_id: str, snapshot_path_or_id: str) -> CaseRecord:
        return self._append_link(case_id, "linked_snapshots", snapshot_path_or_id)

    def link_report(self, case_id: str, report_path: str) -> CaseRecord:
        return self._append_link(case_id, "linked_reports", report_path)

    def add_note(self, case_id: str, note: str, *, author: str = "") -> CaseRecord:
        case = self._required_case(case_id)
        timestamp = utc_now_iso()
        case.notes.append({"timestamp": timestamp, "author": author, "note": note})
        case.updated_at = timestamp
        self.save_case(case)
        return case

    def archive_case(self, case_id: str) -> CaseRecord:
        case = self._required_case(case_id)
        case.status = "archived"
        case.updated_at = utc_now_iso()
        self.save_case(case)
        return case

    def export_case_package(
        self,
        case_id: str,
        output_path: Path,
        *,
        scan_result: ScanResult | None = None,
        timeline: dict[str, Any] | None = None,
        findings: list[dict[str, Any]] | None = None,
        evidence_snapshots: list[dict[str, Any]] | None = None,
        reports: list[str] | None = None,
    ) -> Path:
        case = self._required_case(case_id)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        timeline = timeline or (SecurityTimelineBuilder(self.db).build_from_db(scan_result) if scan_result is not None else SecurityTimelineBuilder(self.db).build_from_db(None))
        graph = EvidenceGraphBuilder().build_from_scan_result(scan_result).to_dict() if scan_result is not None else {}
        findings = findings if findings is not None else self._linked_findings(case, scan_result)
        evidence_snapshots = evidence_snapshots if evidence_snapshots is not None else self._linked_snapshots(case, scan_result)
        reports = reports if reports is not None else list(case.linked_reports)
        manifest: dict[str, Any] = {
            "generated_at": utc_now_iso(),
            "case_id": case.case_id,
            "hash_algorithm": "sha256",
            "files": [],
            "missing_linked_files": [],
        }
        with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            self._write_json(archive, manifest, "case.json", case.to_dict())
            self._write_json(archive, manifest, "notes.json", case.notes)
            self._write_json(archive, manifest, "timeline.json", timeline)
            self._write_json(archive, manifest, "findings.json", findings)
            self._write_json(archive, manifest, "evidence_snapshots.json", evidence_snapshots)
            self._write_json(archive, manifest, "evidence_graph.json", graph)
            self._write_json(archive, manifest, "reports.json", reports)
            for value in case.linked_snapshots:
                self._add_linked_file(archive, manifest, value, "snapshots")
            for value in reports:
                self._add_linked_file(archive, manifest, value, "reports")
            self._write_json(archive, manifest, "manifest.json", manifest)
        return output_path

    def _init_schema(self) -> None:
        self.db.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'medium',
                notes_json TEXT NOT NULL DEFAULT '[]',
                linked_findings_json TEXT NOT NULL DEFAULT '[]',
                linked_events_json TEXT NOT NULL DEFAULT '[]',
                linked_snapshots_json TEXT NOT NULL DEFAULT '[]',
                linked_reports_json TEXT NOT NULL DEFAULT '[]',
                payload_json TEXT NOT NULL DEFAULT '{}'
            );
            """
        )
        self.db.conn.commit()

    def _case_from_row(self, row) -> CaseRecord:
        return CaseRecord(
            case_id=str(row["case_id"]),
            title=str(row["title"]),
            description=str(row["description"] or ""),
            status=str(row["status"] or "open"),  # type: ignore[arg-type]
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            severity=str(row["severity"] or "medium"),
            notes=self._json_list(row["notes_json"]),
            linked_findings=[str(item) for item in self._json_list(row["linked_findings_json"])],
            linked_events=[str(item) for item in self._json_list(row["linked_events_json"])],
            linked_snapshots=[str(item) for item in self._json_list(row["linked_snapshots_json"])],
            linked_reports=[str(item) for item in self._json_list(row["linked_reports_json"])],
        )

    def _required_case(self, case_id: str) -> CaseRecord:
        case = self.get_case(case_id)
        if case is None:
            raise KeyError(f"Unknown case: {case_id}")
        return case

    def _append_link(self, case_id: str, field_name: str, value: str) -> CaseRecord:
        case = self._required_case(case_id)
        links = getattr(case, field_name)
        if value and value not in links:
            links.append(value)
            case.updated_at = utc_now_iso()
            self.save_case(case)
        return case

    def _linked_findings(self, case: CaseRecord, scan_result: ScanResult | None) -> list[dict[str, Any]]:
        if scan_result is None:
            return []
        linked = set(case.linked_findings)
        findings = [finding.to_dict() if hasattr(finding, "to_dict") else dict(finding) for finding in scan_result.findings]
        return [finding for finding in findings if not linked or str(finding.get("id", "")) in linked]

    def _linked_snapshots(self, case: CaseRecord, scan_result: ScanResult | None) -> list[dict[str, Any]]:
        snapshots = []
        if scan_result is not None:
            snapshots.extend(scan_result.collected_artifacts.get("packet_captures", []))
            snapshots.extend(scan_result.collected_artifacts.get("system_recovery_snapshots", []))
        linked = set(case.linked_snapshots)
        if not linked:
            return [json_safe(item) for item in snapshots if isinstance(item, dict)]
        return [
            json_safe(item)
            for item in snapshots
            if isinstance(item, dict)
            and any(str(item.get(key, "")) in linked for key in ("snapshot_id", "capture_id", "snapshot_path", "pcap_path"))
        ]

    def _write_json(self, archive: zipfile.ZipFile, manifest: dict[str, Any], name: str, payload: Any) -> None:
        content = json.dumps(json_safe(payload), indent=2, sort_keys=True).encode("utf-8")
        archive.writestr(name, content)
        manifest["files"].append({"path": name, "sha256": hashlib.sha256(content).hexdigest(), "size_bytes": len(content)})

    def _add_linked_file(self, archive: zipfile.ZipFile, manifest: dict[str, Any], value: str, folder: str) -> None:
        path = Path(value).expanduser()
        if not path.is_file():
            manifest["missing_linked_files"].append(value)
            return
        content = path.read_bytes()
        archive_name = f"{folder}/{path.name}"
        archive.writestr(archive_name, content)
        manifest["files"].append({"path": archive_name, "source_path": str(path), "sha256": hashlib.sha256(content).hexdigest(), "size_bytes": len(content)})

    def _json_list(self, raw: Any) -> list[Any]:
        try:
            parsed = json.loads(str(raw or "[]"))
        except json.JSONDecodeError:
            return []
        return parsed if isinstance(parsed, list) else []
