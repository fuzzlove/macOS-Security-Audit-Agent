from __future__ import annotations

import os
import json
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QApplication, QPushButton

from mac_audit_agent.models import BackgroundMonitorEvent, CommandExecutionResult
from mac_audit_agent.ui.main_window import GuidedLongActionDialog, LongActionWorker, MainWindow


def test_clean_install_disabled_visible_buttons_explain_why(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    missing = [
        button.text()
        for button in window.findChildren(QPushButton)
        if button.isVisible() and not button.isEnabled() and not button.toolTip().strip()
    ]

    assert missing == []
    window.close()
    app.processEvents()


def test_selection_only_finding_actions_hidden_until_selection(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    assert not window.selected_finding_hint_label.isHidden()
    assert window.review_actions_frame.isHidden()
    assert window.remediation_actions_frame.isHidden()

    window.close()
    app.processEvents()


def test_clean_install_results_tab_shows_empty_state_not_blank_tables(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    assert not window.results_empty_state.isHidden()
    assert window.results_tabs.isHidden()

    window.close()
    app.processEvents()


def test_command_preview_explains_collection_vs_remediation_scope(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    preview_text = window._default_command_preview_text()
    assert "audit and evidence-collection command previews only" in preview_text
    assert "not list every possible remediation command" in preview_text

    side_panel_text = window.selected_command_panel.toPlainText() + "\n" + window.remediation_panel.toPlainText()
    assert "Select a finding" in side_panel_text or "No remediation item selected" in side_panel_text

    window.close()
    app.processEvents()


def test_dashboard_keeps_advanced_actions_out_of_primary_header(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    assert window.dashboard_primary_actions in window.dashboard_header_widgets
    assert window.dashboard_report_actions in window.dashboard_header_widgets
    assert window.dashboard_advanced_note in window.dashboard_header_widgets
    assert window.vulnerability_review_button not in window.dashboard_header_widgets
    assert window.full_localhost_scan_button not in window.dashboard_header_widgets
    assert window.network_discovery_button not in window.dashboard_header_widgets

    window.close()
    app.processEvents()


def test_production_ui_hides_demo_test_and_synthetic_controls(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    banned = ("demo", "simulate", "synthetic", "test alert", "test event", "generate test", "test notification", "test high priority", "test bottom", "test critical", "test idle", "mock", "placeholder")

    visible_buttons = [
        button.text()
        for button in window.findChildren(QPushButton)
        if button.isVisible() and any(term in button.text().lower() for term in banned)
    ]
    visible_actions = [
        action.text()
        for action in window.findChildren(QAction)
        if action.isVisible() and action is not window.developer_mode_action and any(term in action.text().lower() for term in banned)
    ]

    assert visible_buttons == []
    assert visible_actions == []
    window.close()
    app.processEvents()


def test_developer_mode_reveals_synthetic_controls_only_when_enabled(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    assert all(button.isHidden() for button in window.background_monitor_panel.developer_only_buttons())
    assert all(not action.isVisible() for action in window.developer_monitor_actions)

    window.developer_mode_action.setChecked(True)

    assert all(not button.isHidden() for button in window.background_monitor_panel.developer_only_buttons())
    assert all(action.isVisible() for action in window.developer_monitor_actions)

    window.close()
    app.processEvents()


def test_reliability_refresh_updates_configuration_drift_from_monitor_snapshot(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    window.db.set_background_monitor_state(
        "current_monitor_snapshot",
        json.dumps({"remote_login_enabled": False, "screen_sharing_enabled": False, "launch_agents": ["baseline.plist"]}, sort_keys=True),
    )
    window._current_configuration_drift_payload()
    window.db.set_background_monitor_state(
        "current_monitor_snapshot",
        json.dumps({"remote_login_enabled": True, "screen_sharing_enabled": False, "launch_agents": ["baseline.plist"]}, sort_keys=True),
    )

    payload = window._current_configuration_drift_payload()

    assert any(change.get("setting") == "Remote Login / SSH" for change in payload.get("changes", []))
    window.close()
    app.processEvents()


def test_main_window_reliability_page_exposes_required_dashboards_and_actions(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    tab_names = [window.reliability_panel.tabs.tabText(index) for index in range(window.reliability_panel.tabs.count())]

    assert "Alert Pipeline Health" in tab_names
    assert "Monitoring Coverage" in tab_names
    assert "Release Readiness" in tab_names
    assert "Trust Timeline" in tab_names
    assert "Configuration Drift" in tab_names
    assert "Incident Mode" in tab_names
    assert window.export_sarif_button.text() == "Export SARIF"
    assert window.reliability_panel.incident_snapshot_button.text() == "Create Evidence Snapshot"
    assert window.reliability_panel.incident_timeline_button.text() == "Open Timeline"
    assert window.reliability_panel.incident_export_button.text() == "Export Case Package"
    assert window.reliability_panel.incident_note_button.text() == "Add Investigation Note"
    assert window.reliability_panel.incident_priority_button.text() == "Review High Priority Events"
    assert window.reliability_panel.alert_table.rowCount() >= 8
    assert window.reliability_panel.coverage_table.columnCount() == 9
    assert window.reliability_panel.release_table.columnCount() == 4

    window.close()
    app.processEvents()


def test_incident_mode_actions_record_note_and_case_package_activity(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    window.incident_mode_manager.set_enabled(True)
    monkeypatch.setattr(window, "show_investigation_notes_page", lambda: None)
    monkeypatch.setattr(window, "export_html", lambda: tmp_path / "case.html")

    window.open_incident_note_panel()
    window.export_incident_case_package()
    status = window.incident_mode_manager.status()

    assert status["notes_panel_opened"] is True
    assert status["investigation_note_count"] == 1
    assert status["case_package_count"] == 1
    assert status["last_case_package"]["path"] == str(tmp_path / "case.html")
    window.close()
    app.processEvents()


def test_findings_without_detailed_remediation_get_category_guidance(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    finding = {
        "id": "finding-1",
        "category": "Network",
        "title": "Unexpected Listener",
        "severity": "high",
        "evidence": "port 4444 listening",
    }

    text = window._render_remediation_details(finding)

    assert "Identify the owning process" in text
    assert "Log Handling:" in text
    assert "Monitor Events and Scan Command Logs" in text
    assert "Verification:" in text
    window.close()
    app.processEvents()


def test_logs_page_filters_and_clears_selected_category(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    window.db.record_background_monitor_event(
        BackgroundMonitorEvent(
            event_id="event-1",
            timestamp="2026-06-06T00:00:00+00:00",
            event_type="remote_login_enabled",
            severity="high",
            source="test",
            evidence="ssh enabled",
            confidence="high",
        )
    )
    window.db.record_command_log(
        "scan-1",
        CommandExecutionResult(
            command_id="network.test",
            command_preview="netstat -an",
            executed_at="2026-06-06T00:00:01+00:00",
            stdout="ok",
            stderr="",
            exit_code=0,
            timed_out=False,
            truncated=False,
            dry_run=False,
        ),
    )
    window.db.record_remediation_action(
        scan_id="scan-1",
        finding_id="finding-1",
        action_type="copy",
        command_text="launchctl print system/test",
        explanation="copied",
        user_approval=True,
        approval_text="COPY",
        result_text="copied",
        exit_code=None,
        created_at="2026-06-06T00:00:02+00:00",
    )
    (window.db.logs_dir / "app.log").write_text("2026-06-06T00:00:03+00:00 app log\n", encoding="utf-8")

    window.refresh_logs_page()
    assert window.logs_panel.table.rowCount() >= 4
    monkeypatch.setattr(window, "_confirm_clear_logs_category", lambda category: True)

    window.clear_logs_category("scan_command_logs")
    snapshot = window.db.export_snapshot()

    assert snapshot["command_logs"] == []
    assert snapshot["remediation_actions"]
    assert window.db.recent_background_monitor_events(limit=10)
    window.close()
    app.processEvents()


def test_guided_long_action_dialog_walks_through_background_phases() -> None:
    app = QApplication.instance() or QApplication([])
    dialog = GuidedLongActionDialog("Scan Running", ["Preparing scan.", "Collecting evidence.", "Preparing results."])

    assert "Preparing scan" in dialog.status_label.text()
    dialog._advance_phase()
    assert "Collecting evidence" in dialog.status_label.text()
    dialog._update_progress({"message": "Comparing against baseline.", "completed": 2, "total": 3})

    assert "Comparing against baseline" in dialog.status_label.text()
    assert dialog.progress_bar.maximum() == 3
    assert dialog.progress_bar.value() == 2
    dialog.close()
    app.processEvents()


def test_long_action_worker_reports_progress_and_result() -> None:
    observed: list[dict] = []
    completed: list[object] = []

    def action(progress):
        progress({"message": "working", "completed": 1, "total": 2})
        return {"done": True}

    worker = LongActionWorker(action)
    worker.progress.connect(lambda payload: observed.append(dict(payload)))
    worker.completed.connect(lambda result: completed.append(result))

    worker.run()

    assert observed == [{"message": "working", "completed": 1, "total": 2}]
    assert completed == [{"done": True}]
