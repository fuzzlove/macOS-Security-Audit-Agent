import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mac_audit_agent.models import ScanSummary
from mac_audit_agent.ui.main_window import MainWindow


def make_summary() -> ScanSummary:
    return ScanSummary(
        scan_id="scan-1",
        started_at="2026-04-26T00:00:00Z",
        completed_at="2026-04-26T00:01:00Z",
        findings_count=1,
        security_score=90,
        notes="test",
    )


def test_auto_save_note(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    window.current_scan_summary = make_summary()
    window.investigation_note_title.setText("Autosave")
    window.investigation_notes_editor.setPlainText("Saved automatically.")
    window._autosave_investigation_notes()
    notes = window.db.list_investigation_notes(linked_scan_id="scan-1")
    assert len(notes) == 1
    assert notes[0].title == "Autosave"
    window.close()
    app.processEvents()


def test_mark_finding_review_states(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    window.current_scan_summary = make_summary()
    window.current_selected_finding = {"id": "finding-1", "title": "Listener"}
    window._set_selected_finding_review_state("reviewed")
    window._set_selected_finding_review_state("false positive")
    window._set_selected_finding_review_state("confirmed concern")
    statuses = window.db.get_review_statuses("scan-1")
    assert statuses[("finding", "finding-1")].review_state == "confirmed concern"
    window.close()
    app.processEvents()
