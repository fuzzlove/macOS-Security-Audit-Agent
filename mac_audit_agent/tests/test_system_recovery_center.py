import zipfile
from pathlib import Path

from PySide6.QtWidgets import QApplication

from mac_audit_agent.config import AuditConfig
from mac_audit_agent.models import ProcessSnapshot
from mac_audit_agent.recovery_center import SystemRecoveryCenter
from mac_audit_agent.ui.main_window import MainWindow
from mac_audit_agent.ui.system_recovery_panel import RecoveryEvidenceWarningDialog
from mac_audit_agent.storage import AuditDatabase


def _make_large_cache(root: Path) -> Path:
    cache_dir = root / "Library" / "Caches" / "TestCache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "big.bin").write_bytes(b"0" * (6 * 1024 * 1024))
    return cache_dir


def test_system_recovery_tab_exists_and_can_be_opened(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("mac_audit_agent.config.Path.home", lambda: tmp_path)
    monkeypatch.setattr("mac_audit_agent.recovery_center.Path.home", lambda: tmp_path)
    window = MainWindow(tmp_path / "audit.sqlite")
    assert window.sidebar.item(7).text() == "System Recovery"
    window.show_system_recovery_page()
    assert window.sidebar.currentRow() == 7
    assert window.pages.currentIndex() == 7
    assert window.system_recovery_panel.title_label.text() == "System Recovery"
    assert window.system_recovery_panel.recovery_state_label.text()
    window.close()
    app.processEvents()


def test_recovery_warning_dialog_defaults_to_snapshot() -> None:
    app = QApplication.instance() or QApplication([])
    dialog = RecoveryEvidenceWarningDialog()
    assert dialog.windowTitle() == "Potential Evidence Preservation Risk"
    assert dialog.cancel_button.text() == "Cancel"
    assert dialog.snapshot_button.text() == "Create Evidence Snapshot First"
    assert dialog.continue_button.text() == "Continue Cleanup"
    assert dialog.snapshot_button.isDefault()
    dialog.close()
    app.processEvents()


def test_recovery_preview_snapshot_cleanup_and_preservation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.config.Path.home", lambda: tmp_path)
    monkeypatch.setattr("mac_audit_agent.recovery_center.Path.home", lambda: tmp_path)
    monkeypatch.setattr("mac_audit_agent.recovery_center.tempfile.gettempdir", lambda: str(tmp_path / "tmp"))
    config = AuditConfig()
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    center = SystemRecoveryCenter(db, config)

    cache_dir = _make_large_cache(tmp_path)
    protected_report = tmp_path / "Library" / "Application Support" / "MacAuditAgent" / "reports"
    protected_report.mkdir(parents=True, exist_ok=True)
    (protected_report / "report.html").write_text("keep", encoding="utf-8")
    protected_snapshot_dir = tmp_path / "Library" / "Application Support" / "MacAuditAgent" / "snapshots"
    protected_snapshot_dir.mkdir(parents=True, exist_ok=True)
    (protected_snapshot_dir / "keep.zip").write_text("keep", encoding="utf-8")
    protected_logs = tmp_path / "Library" / "Logs" / "MacAuditAgent"
    protected_logs.mkdir(parents=True, exist_ok=True)
    (protected_logs / "log.txt").write_text("keep", encoding="utf-8")

    preview = center.build_cleanup_preview()
    assert preview.total_recoverable_bytes > 0
    assert preview.recovery_score <= 100
    assert preview.candidates

    (cache_dir / "growth.bin").write_bytes(b"1" * (55 * 1024 * 1024))
    grown_preview = center.build_cleanup_preview()
    assert grown_preview.total_recoverable_bytes > preview.total_recoverable_bytes
    assert grown_preview.opportunities > 0
    assert grown_preview.growth_summary

    snapshot = center.create_evidence_snapshot(assessment=center.incident_awareness_check(), preview=grown_preview, reason="test")
    snapshot_path = Path(snapshot["snapshot_path"])
    assert snapshot_path.exists()
    with zipfile.ZipFile(snapshot_path, "r") as archive:
        assert "metadata.json" in archive.namelist()
        assert "database_export.json" in archive.namelist()

    result = center.run_cleanup([str(cache_dir)], preview=grown_preview, assessment=center.incident_awareness_check())
    assert result["deleted"]
    assert not cache_dir.exists()
    assert protected_report.exists()
    assert protected_snapshot_dir.exists()
    assert protected_logs.exists()
    assert db.path.exists()

    actions = db.list_system_cleanup_actions(limit=10)
    assert actions
    action = actions[0]
    assert action.get("rollback_json")
    assert action.get("deleted_json")
    assert action.get("result_text")


def test_recovery_center_treats_system_apple_cache_as_protected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.config.Path.home", lambda: tmp_path)
    monkeypatch.setattr("mac_audit_agent.recovery_center.Path.home", lambda: tmp_path)
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    center = SystemRecoveryCenter(db, AuditConfig())
    protected = Path("/Library/Caches/com.apple.amsengagement.classicdatavault")

    assert center._is_protected(protected)
    assert center._scan_candidate({"category": "review", "kind": "user-selected log folder", "path": protected}) == []


def test_snapshot_only_action_is_logged(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.config.Path.home", lambda: tmp_path)
    monkeypatch.setattr("mac_audit_agent.recovery_center.Path.home", lambda: tmp_path)
    config = AuditConfig()
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    center = SystemRecoveryCenter(db, config)
    preview = center.build_cleanup_preview()
    result = center.run_cleanup([], create_snapshot_first=True, preview=preview, assessment=center.incident_awareness_check())
    assert result["action_type"] == "snapshot_only"
    actions = db.list_system_cleanup_actions(limit=10)
    assert actions
    assert actions[0].get("action_type") == "snapshot_only"


def test_incident_awareness_accepts_process_snapshots(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.config.Path.home", lambda: tmp_path)
    monkeypatch.setattr("mac_audit_agent.recovery_center.Path.home", lambda: tmp_path)
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    center = SystemRecoveryCenter(db, AuditConfig())
    assessment = center.incident_awareness_check(
        current_payload={
            "processes": {
                "all": [
                    ProcessSnapshot(
                        pid=1,
                        ppid=0,
                        user="m",
                        command_path="/Applications/Test.app/Contents/MacOS/Test",
                        process_name="Test",
                        signed_status="signed",
                        trust_level="review",
                        trust_score=55,
                        trust_summary="test",
                        reasons=["nonstandard_process_path"],
                    )
                ]
            }
        }
    )
    assert assessment.level in {"caution", "investigate_first", "incident_response_recommended"}
