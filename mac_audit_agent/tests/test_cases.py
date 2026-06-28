from __future__ import annotations

import json
import zipfile
from pathlib import Path

from mac_audit_agent.cases import CaseManager
from mac_audit_agent.models import Finding, ScanResult
from mac_audit_agent.storage import AuditDatabase


def _db(tmp_path: Path) -> AuditDatabase:
    return AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")


def _scan_result() -> ScanResult:
    finding = Finding(
        id="finding-1",
        category="Persistence",
        title="New LaunchDaemon",
        severity="high",
        description="A LaunchDaemon was added.",
        evidence="/Library/LaunchDaemons/com.test.plist",
        command_used="launchctl print",
        remediation_suggestion="Verify the LaunchDaemon.",
        warning="Review before removal.",
    )
    return ScanResult(
        scan_id="scan-1",
        timestamp="2026-06-27T12:00:00+00:00",
        hostname="mac.local",
        current_user="m",
        findings=[finding],
        collected_artifacts={
            "ports": {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []},
            "processes": {"all": [], "suspicious": [], "errors": []},
            "localhost_scan": {},
            "packet_captures": [{"capture_id": "capture-1", "status": "completed", "pcap_path": ""}],
        },
    )


def test_create_case(tmp_path: Path) -> None:
    db = _db(tmp_path)
    try:
        manager = CaseManager(db)
        case = manager.create_case(title="Suspicious persistence", description="Review LaunchDaemon.", severity="high")

        loaded = manager.get_case(case.case_id)
        assert loaded is not None
        assert loaded.title == "Suspicious persistence"
        assert loaded.status == "open"
        assert loaded.severity == "high"
    finally:
        db.close()


def test_link_finding(tmp_path: Path) -> None:
    db = _db(tmp_path)
    try:
        manager = CaseManager(db)
        case = manager.create_case(title="Case")
        updated = manager.link_finding(case.case_id, "finding-1")

        assert updated.linked_findings == ["finding-1"]
        assert manager.get_case(case.case_id).linked_findings == ["finding-1"]  # type: ignore[union-attr]
    finally:
        db.close()


def test_add_note(tmp_path: Path) -> None:
    db = _db(tmp_path)
    try:
        manager = CaseManager(db)
        case = manager.create_case(title="Case")
        updated = manager.add_note(case.case_id, "Analyst reviewed launch item.", author="m")

        assert updated.notes[0]["author"] == "m"
        assert "launch item" in updated.notes[0]["note"]
    finally:
        db.close()


def test_export_package(tmp_path: Path) -> None:
    db = _db(tmp_path)
    try:
        manager = CaseManager(db)
        case = manager.create_case(title="Case")
        manager.link_finding(case.case_id, "finding-1")
        manager.link_event(case.case_id, "event-1")
        manager.add_note(case.case_id, "Package this case.", author="m")
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps({"scan_id": "scan-1"}), encoding="utf-8")
        manager.link_report(case.case_id, str(report_path))

        output = manager.export_case_package(case.case_id, tmp_path / "case.zip", scan_result=_scan_result())

        assert output.exists()
        with zipfile.ZipFile(output, "r") as archive:
            names = set(archive.namelist())
            assert {"case.json", "notes.json", "timeline.json", "findings.json", "evidence_snapshots.json", "reports.json", "manifest.json"} <= names
            assert "reports/report.json" in names
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
            findings = json.loads(archive.read("findings.json").decode("utf-8"))
        assert manifest["case_id"] == case.case_id
        assert manifest["hash_algorithm"] == "sha256"
        assert findings[0]["id"] == "finding-1"
    finally:
        db.close()
