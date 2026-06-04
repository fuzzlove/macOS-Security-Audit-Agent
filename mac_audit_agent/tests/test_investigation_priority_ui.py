from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mac_audit_agent.models import Finding, ScanResult
from mac_audit_agent.ui.main_window import MainWindow


def _scan_result() -> ScanResult:
    return ScanResult(
        scan_id="scan-ui-1",
        timestamp="2026-06-01T12:00:00+00:00",
        hostname="mac.local",
        current_user="m",
        findings=[
            Finding(
                id="f-1",
                category="Persistence",
                title="LaunchDaemon Added",
                severity="high",  # type: ignore[arg-type]
                description="LaunchDaemon Added",
                evidence="/Library/LaunchDaemons/com.example.plist",
                command_used="/Library/LaunchDaemons/com.example.plist",
                remediation_suggestion="Inspect the plist.",
                warning="",
                confidence="high",  # type: ignore[arg-type]
                evidence_summary="New LaunchDaemon.",
                recommended_next_steps="Inspect the plist.",
            )
        ],
        collected_artifacts={"processes": {"all": [], "suspicious": [], "errors": []}, "file_issues": [], "network_discovery": {"review_needed_count": 0, "devices": [], "comparison": {}, "debug_logs": [], "errors": []}},
        baseline_diff={},
        raw_logs=[],
        errors=[],
    )


def test_investigation_priorities_tab_exists_and_renders_rows(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    tabs = [window.results_tabs.tabText(index) for index in range(window.results_tabs.count())]
    assert "Investigation Priorities" in tabs
    assert window.investigation_priority_panel.title_label.text() == "Investigation Priorities"
    assert "No findings to prioritize" in window.investigation_priority_panel.details_view.toPlainText()

    window.current_scan_result = _scan_result()
    window.refresh_investigation_priorities()
    assert window.investigation_priority_panel.top_3_table.rowCount() == 1
    assert window.investigation_priority_panel.full_queue_table.rowCount() == 1
    assert "LaunchDaemon Added" in window.investigation_priority_panel.details_view.toPlainText()

    window.close()
    app.processEvents()

