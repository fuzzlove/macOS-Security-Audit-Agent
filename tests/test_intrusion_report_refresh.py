from __future__ import annotations

import os
from pathlib import Path

import pytest

from mac_audit_agent.intrusion_correlation import IntrusionCorrelationEngine
from mac_audit_agent.intrusion_report_refresh import IntrusionReportRefreshCoordinator
from mac_audit_agent.secure_io import PersistenceResult
from mac_audit_agent.storage import AuditDatabase


def test_build_report_is_pure_and_does_not_create_ai_summary(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MSAA_REPORT_DIR", str(tmp_path / "generated"))
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    report = IntrusionCorrelationEngine(db).build_report()
    assert report.ai_summary and report.ai_summary_path == ""
    assert report.ai_summary_persistence["attempted"] is False
    assert not (tmp_path / "generated/ai_summary.json").exists()


def test_one_generation_builds_and_persists_once_for_both_consumers(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MSAA_REPORT_DIR", str(tmp_path / "generated"))
    engine = IntrusionCorrelationEngine(AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs"))
    coordinator = IntrusionReportRefreshCoordinator(engine)
    first = coordinator.get(); second = coordinator.get()
    assert first is second and first.report is second.report
    assert coordinator.build_count == 1 and coordinator.persistence_attempt_count == 1
    assert first.persistence.succeeded


def test_permission_failure_is_fail_soft_and_cached_once(tmp_path: Path, monkeypatch, caplog) -> None:
    monkeypatch.setenv("MSAA_REPORT_DIR", str(tmp_path / "generated"))
    engine = IntrusionCorrelationEngine(AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs"))
    attempts = 0
    def denied(_summary):
        nonlocal attempts; attempts += 1; raise PermissionError("injected without sensitive content")
    monkeypatch.setattr(engine, "persist_ai_summary", denied)
    coordinator = IntrusionReportRefreshCoordinator(engine)
    first = coordinator.get(); second = coordinator.get()
    assert first.report.ai_summary and second.report is first.report
    assert first.persistence.error_code == "REPORT_PERMISSION_DENIED"
    assert attempts == 1 and coordinator.build_count == 1
    assert sum("persistence permission failure" in item.message for item in caplog.records) == 1


def test_failed_legacy_migration_never_blocks_report(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MSAA_REPORT_DIR", str(tmp_path / "generated"))
    engine = IntrusionCorrelationEngine(AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs"))
    monkeypatch.setattr(engine, "migrate_legacy_ai_summary", lambda: (_ for _ in ()).throw(PermissionError("denied")))
    snapshot = IntrusionReportRefreshCoordinator(engine).get()
    assert snapshot.report.ai_summary and snapshot.persistence.succeeded
    assert snapshot.migration and snapshot.migration.status == "migration_failed"
    assert snapshot.report.ai_summary_persistence["legacy_migration"]["status"] == "migration_failed"


def test_unexpected_report_engine_defect_is_not_mislabeled_as_persistence(tmp_path: Path) -> None:
    engine = IntrusionCorrelationEngine(AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs"))
    engine.build_report = lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("engine defect"))
    with pytest.raises(RuntimeError, match="engine defect"):
        IntrusionReportRefreshCoordinator(engine).get()


def test_explicit_export_uses_selected_path_securely(tmp_path: Path) -> None:
    directory = tmp_path / "selected"; directory.mkdir(mode=0o700)
    engine = IntrusionCorrelationEngine(AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs"))
    path = engine.write_ai_summary({"selected": True}, directory / "chosen.json")
    assert path == directory / "chosen.json" and oct(path.stat().st_mode & 0o777) == "0o600"


def test_gui_refresh_methods_render_same_snapshot_when_persistence_fails(tmp_path: Path, monkeypatch) -> None:
    from mac_audit_agent.ui.main_window import MainWindow

    monkeypatch.setenv("MSAA_REPORT_DIR", str(tmp_path / "generated"))
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs"); engine = IntrusionCorrelationEngine(db)
    monkeypatch.setattr(engine, "persist_ai_summary", lambda _summary: PersistenceResult(True, False, tmp_path / "denied/ai_summary.json", "REPORT_PERMISSION_DENIED", "denied"))

    class Panel:
        def __init__(self): self.reports = []; self.statuses = []
        def set_report(self, report): self.reports.append(report)
        def set_persistence_status(self, message): self.statuses.append(message)
    class Status:
        def __init__(self): self.messages = []
        def showMessage(self, message, _timeout): self.messages.append(message)
    class Harness:
        refresh_intrusion_detection = MainWindow.refresh_intrusion_detection
        refresh_flight_recorder = MainWindow.refresh_flight_recorder
        _apply_intrusion_persistence_status = MainWindow._apply_intrusion_persistence_status
        def __init__(self):
            self.db=db; self.current_scan_result=None; self.current_payload={}; self.intrusion_correlation_engine=engine
            self.intrusion_report_refresh=IntrusionReportRefreshCoordinator(engine); self.intrusion_detection_panel=Panel(); self.flight_recorder_panel=Panel()
            self._last_intrusion_persistence_warning_generation=""; self._status=Status()
        def statusBar(self): return self._status
    window = Harness(); window.refresh_intrusion_detection(); window.refresh_flight_recorder()
    assert window.intrusion_detection_panel.reports[0] is window.flight_recorder_panel.reports[0]
    assert window.intrusion_detection_panel.reports[0].ai_summary
    assert window.intrusion_report_refresh.build_count == 1 and window.intrusion_report_refresh.persistence_attempt_count == 1
    assert len(window._status.messages) == 1 and "could not be saved" in window._status.messages[0]
    assert "REPORT_PERMISSION_DENIED" not in window.intrusion_detection_panel.reports[0].summary


def test_later_success_clears_persistence_warning(tmp_path: Path, monkeypatch) -> None:
    from mac_audit_agent.ui.main_window import MainWindow
    monkeypatch.setenv("MSAA_REPORT_DIR", str(tmp_path / "generated"))
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs"); engine = IntrusionCorrelationEngine(db)
    outcomes = iter((PersistenceResult(True, False, tmp_path / "x", "REPORT_PERMISSION_DENIED", "denied"), PersistenceResult(True, True, tmp_path / "ok.json", None, None)))
    monkeypatch.setattr(engine, "persist_ai_summary", lambda _summary: next(outcomes))
    class Panel:
        def __init__(self): self.status=""
        def set_report(self, _report): pass
        def set_persistence_status(self, message): self.status=message
    class Harness:
        _apply_intrusion_persistence_status=MainWindow._apply_intrusion_persistence_status
        def __init__(self): self.intrusion_detection_panel=Panel(); self.flight_recorder_panel=Panel(); self._last_intrusion_persistence_warning_generation=""; self.messages=[]
        def statusBar(self): return self
        def showMessage(self, message, _timeout): self.messages.append(message)
    coordinator=IntrusionReportRefreshCoordinator(engine); window=Harness()
    window._apply_intrusion_persistence_status(coordinator.get())
    window._apply_intrusion_persistence_status(coordinator.get(force=True))
    assert window.intrusion_detection_panel.status == "" and window.flight_recorder_panel.status == ""
    assert window.messages[-1] == "Intrusion analysis and AI summary persistence completed."


def test_production_qt_styles_do_not_request_windows_fonts() -> None:
    root = Path(__file__).parents[1] / "mac_audit_agent"
    python_text = "\n".join(path.read_text(encoding="utf-8") for path in root.rglob("*.py"))
    assert "Segoe UI" not in python_text
    main_source = (root / "ui/main_window.py").read_text(encoding="utf-8")
    assert "QFontDatabase.systemFont" in main_source
    assert "SystemFont.FixedFont" in main_source
