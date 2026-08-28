from __future__ import annotations

import os
import json
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QAction
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QPushButton, QDialog, QMessageBox, QTabWidget, QWidget

from mac_audit_agent.models import BackgroundMonitorEvent, CommandExecutionResult
from mac_audit_agent.ui.operational_health_panel import OperationalHealthPanel
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

    assert window.details_panel.isHidden()
    assert window.selected_finding_hint_label.isHidden()
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

    assert window.details_panel.isHidden()

    window.close()
    app.processEvents()


def test_command_preview_catalog_is_filterable_and_copy_actions_follow_selection(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    page = window._build_preview_page()

    assert window.command_preview_table.rowCount() == len(window.registry)
    assert window.command_preview_copy_button.isEnabled()
    window.command_preview_search.setText("DNS")
    assert 0 < window.command_preview_table.rowCount() < len(window.registry)
    assert "Showing" in window.command_preview_summary.text()
    assert "Recent Scan Activity" == page.findChild(QTabWidget, "auditCommandPreviewDetailsTabs").tabText(1)

    window.close()
    app.processEvents()


def test_framework_coverage_starts_with_complete_beginner_sheet(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    page = window._build_framework_coverage_page()
    tabs = page.findChild(QTabWidget, "frameworkCoverageTabs")

    assert tabs is not None
    assert tabs.tabText(0) == "Coverage Sheet — Start Here"
    assert window.framework_beginner_table.rowCount() == 12
    assert "Recommended next step" in window.framework_beginner_detail.toPlainText()

    window.framework_beginner_status.setCurrentIndex(3)
    assert window.framework_beginner_table.rowCount() == 1
    assert window.framework_beginner_table.item(0, 0).text() == "Governance, policy, workforce, and suppliers"

    window.framework_beginner_status.setCurrentIndex(0)
    window.framework_beginner_search.setText("suspected RCE")
    assert window.framework_beginner_table.rowCount() == 1
    assert window.framework_beginner_table.item(0, 0).text() == "Host IDS and exploitation evidence"

    window.close()
    app.processEvents()


def test_operational_posture_cards_have_responsive_action_affordance(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    container = window._build_dashboard_operations_command_center()

    assert len(window.dashboard_operational_cards) == 14
    for card in window.dashboard_operational_cards.values():
        assert card["widget"].property("interactiveCard") is True
        assert card["widget"].minimumHeight() >= 150
        assert card["state"].wordWrap()
        assert card["state"].property("textRole") == "operationalState"
        assert "Open" in card["action"].text()
    assert container.findChildren(QWidget)

    window.close()
    app.processEvents()


def test_context_column_releases_space_and_reveals_only_applicable_sections(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")

    window._set_context_panel_state(visible=True, remediation=False)
    assert not window.details_panel.isHidden()
    assert not window.details_heading.isHidden()
    assert window.remediation_heading.isHidden()
    assert window.remediation_panel.isHidden()

    window._set_context_panel_state(visible=True, remediation=True)
    assert not window.details_panel.isHidden()
    assert not window.remediation_heading.isHidden()
    assert not window.remediation_panel.isHidden()

    window._set_context_panel_state(visible=False)
    assert window.details_panel.isHidden()
    assert window.main_splitter.sizes()[1] == 0

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


def _integrity_health_payload(status: str) -> dict:
    health_status = "broken" if status == "modified" else "healthy" if status == "verified" else "degraded"
    return {
        "overall_status": health_status,
        "health_score": 80,
        "checks": [
            {
                "component": "Source Integrity",
                "status": health_status,
                "summary": status,
                "evidence": "test",
                "next_step": "review",
            }
        ],
        "details": {"source_integrity": {"overall_status": status}},
    }


def test_integrity_action_buttons_are_state_aware() -> None:
    app = QApplication.instance() or QApplication([])
    panel = OperationalHealthPanel()
    panel.show()

    panel.set_report(_integrity_health_payload("stale"))
    assert panel.resolve_mismatch_button.text() == "Resolve Mismatch"
    assert not panel.resolve_mismatch_button.isHidden()
    assert not panel.create_manifest_button.isHidden()
    assert panel.preserve_evidence_snapshot_button.isHidden()

    panel.set_report(_integrity_health_payload("modified"))
    assert panel.view_mismatch_details_button.text() == "View Mismatches"
    assert not panel.view_mismatch_details_button.isHidden()
    assert panel.preserve_evidence_snapshot_button.text() == "Preserve Evidence Snapshot"
    assert not panel.preserve_evidence_snapshot_button.isHidden()
    assert panel.resolve_mismatch_button.isHidden()
    assert panel.create_manifest_button.isHidden()

    panel.set_report(_integrity_health_payload("unknown"))
    assert panel.create_manifest_button.text() == "Create Trusted Manifest"
    assert not panel.create_manifest_button.isHidden()
    assert not panel.resolve_mismatch_button.isHidden()

    panel.set_report(_integrity_health_payload("verified"))
    assert panel.verify_integrity_button.text() == "Verify Now"
    assert not panel.verify_integrity_button.isHidden()
    assert panel.export_integrity_report_button.text() == "Export Integrity Report"
    assert not panel.export_integrity_report_button.isHidden()
    assert panel.view_mismatch_details_button.isHidden()
    assert panel.resolve_mismatch_button.isHidden()
    assert panel.create_manifest_button.isHidden()
    assert panel.preserve_evidence_snapshot_button.isHidden()

    panel.close()
    app.processEvents()


def test_operational_health_panel_explains_degraded_safe_issue() -> None:
    app = QApplication.instance() or QApplication([])
    panel = OperationalHealthPanel()
    panel.show()

    panel.set_report(
        {
            "overall_status": "degraded",
            "display_status": "Degraded (User LaunchAgent Missing)",
            "health_score": 76,
            "generated_at": "2026-07-02T00:00:00+00:00",
            "checks": [
                {
                    "component": "User LaunchAgent",
                    "status": "degraded",
                    "summary": "User notifier is not installed.",
                    "evidence": "plist missing",
                    "next_step": "Install the user notifier.",
                }
            ],
            "issues": [
                {
                    "issue_id": "user_launchagent_degraded",
                    "component": "User LaunchAgent",
                    "severity": "degraded",
                    "category": "missing_component",
                    "title": "User LaunchAgent Missing",
                    "description": "User notifier is not installed.",
                    "impact": "Alerts may be unavailable.",
                    "evidence": ["plist missing"],
                    "suggested_fix": ["Repair Notifier"],
                    "auto_fixable": True,
                    "requires_admin": False,
                    "risk_of_tampering": False,
                }
            ],
            "root_cause_ranking": [{"rank": 1, "issue_id": "user_launchagent_degraded", "severity": "degraded"}],
            "primary_cause": {
                "title": "User LaunchAgent Missing",
                "component": "User LaunchAgent",
                "description": "User notifier is not installed.",
                "evidence": ["plist missing"],
                "suggested_fix": ["Repair Notifier"],
            },
            "components": [
                {
                    "component": "User Notifier",
                    "status": "degraded",
                    "status_label": "Missing",
                    "reason": "User notifier is not installed.",
                    "last_check_timestamp": "2026-07-02T00:00:00+00:00",
                    "fix_label": "Repair Notifier",
                    "auto_fixable": True,
                }
            ],
        }
    )

    assert "User LaunchAgent Missing" in panel.summary_label.text()
    assert "Why this is happening" in panel.why_label.text()
    assert not panel.repair_button.isHidden()
    assert panel.component_table.rowCount() == 1
    component_payload=panel.component_table.item(0,0).data(Qt.UserRole)
    assert component_payload["component"]=="User Notifier"
    assert component_payload["status"]=="degraded"
    assert panel.component_table.contextMenuPolicy()==Qt.CustomContextMenu
    assert panel.issue_table.rowCount() == 1
    assert panel.security_banner.isHidden()
    assert not panel.copy_action_button.isHidden()
    panel.copy_action_button.click()
    assert QApplication.clipboard().text() == "Repair Notifier"
    assert panel.copy_action_button.text() == "Copied"

    panel.close()
    app.processEvents()


def test_operational_health_panel_security_degraded_mode_blocks_repair() -> None:
    app = QApplication.instance() or QApplication([])
    panel = OperationalHealthPanel()
    panel.show()

    payload = _integrity_health_payload("modified")
    payload["security_degraded_mode"] = True
    payload["display_status"] = "SECURITY DEGRADED MODE"
    payload["issues"] = [
        {
            "issue_id": "source_integrity_critical",
            "component": "Source Integrity",
            "severity": "critical",
            "category": "integrity_mismatch",
            "title": "Integrity Verification Mismatch",
            "description": "Possible program modification or tampering detected.",
            "impact": "CRITICAL",
            "evidence": ["changed=1"],
            "suggested_fix": ["View Integrity Report", "Export Evidence Snapshot", "Reinstall From Trusted Source"],
            "auto_fixable": False,
            "requires_admin": False,
            "risk_of_tampering": True,
        }
    ]
    payload["primary_cause"] = payload["issues"][0]
    panel.set_report(payload)

    assert "SECURITY DEGRADED MODE" in panel.security_banner.text()
    assert panel.repair_button.isHidden()
    assert not panel.view_mismatch_details_button.isHidden()
    assert not panel.preserve_evidence_snapshot_button.isHidden()

    panel.close()
    app.processEvents()


class _FakeIntegrityResult:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def to_dict(self) -> dict:
        return dict(self._payload)


def _integrity_payload() -> dict:
    return {
        "overall_status": "stale",
        "health_impact": "degraded",
        "manifest_path": "/tmp/msaa_integrity_manifest.json",
        "source_type": "source_tree",
        "trust_state": "trusted",
        "manifest_app_version": "0.9.4",
        "current_app_version": "0.9.5",
        "manifest_build_id": "old-build",
        "current_build_id": "new-build",
        "manifest_git_commit": "abc",
        "current_git_commit": "def",
        "current_install_mode": "source_tree",
        "exact_mismatch_reason": "Manifest version 0.9.4 differs from current app version 0.9.5.",
        "matched_count": 10,
        "mismatched_count": 0,
        "missing_count": 0,
        "extra_count": 0,
        "cached_result": False,
        "cache_valid": True,
        "cache_invalidated_reason": "bypassed",
        "verification_result_id": "verify-1",
        "verified_at": "2026-07-01T00:00:00+00:00",
        "mismatch_details": [{"field": "app_version", "message": "Manifest version 0.9.4 differs from current app version 0.9.5."}],
        "recommended_actions": ["Create new trusted manifest after verifying update."],
    }


def test_view_integrity_mismatch_details_includes_exact_fields(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    monkeypatch.setattr("mac_audit_agent.ui.main_window.verify_current_install_integrity", lambda *args, **kwargs: _FakeIntegrityResult(_integrity_payload()))
    captured: dict[str, str] = {}

    class FakeMessageBox:
        Warning = 1
        Information = 2
        Ok = 0

        def __init__(self, *args, **kwargs) -> None:
            pass

        def setIcon(self, value) -> None:
            pass

        def setWindowTitle(self, value) -> None:
            captured["title"] = value

        def setText(self, value) -> None:
            captured["text"] = value

        def setDetailedText(self, value) -> None:
            captured["details"] = value

        def addButton(self, *args, **kwargs) -> None:
            pass

        def exec(self) -> int:
            return 0

        @staticmethod
        def information(*args, **kwargs) -> None:
            return None

        @staticmethod
        def warning(*args, **kwargs) -> None:
            return None

    monkeypatch.setattr("mac_audit_agent.ui.main_window.QMessageBox", FakeMessageBox)

    window.view_integrity_mismatch_details()
    details = captured["details"]

    assert "manifest app_version: 0.9.4" in details
    assert "current app_version: 0.9.5" in details
    assert "manifest build_id: old-build" in details
    assert "current build_id: new-build" in details
    assert "source_type: source_tree" in details
    assert "install_mode: source_tree" in details
    window.close()
    app.processEvents()


def test_export_integrity_report_writes_json(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    output = tmp_path / "integrity-report.json"
    monkeypatch.setattr("mac_audit_agent.ui.main_window.verify_current_install_integrity", lambda *args, **kwargs: _FakeIntegrityResult(_integrity_payload()))
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QFileDialog.getSaveFileName", lambda *args, **kwargs: (str(output), "JSON Files (*.json)"))
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QMessageBox.information", lambda *args, **kwargs: None)
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QMessageBox.warning", lambda *args, **kwargs: None)

    window.export_integrity_report()
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert payload["overall_status"] == "stale"
    assert payload["exact_mismatch_reason"]
    assert window.db.get_background_monitor_state("last_integrity_report_export_path", "") == str(output)
    window.close()
    app.processEvents()


def test_create_trusted_manifest_requires_checkbox_and_typed_confirmation(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    root = tmp_path / "app"
    root.mkdir()
    create_calls: list[object] = []

    class Selection:
        manifest_path = root / "msaa_integrity_manifest.json"
        expected_source_type = "source_tree"

    class FakeManifest:
        file_entries = [object()]

    monkeypatch.setattr(window, "_application_integrity_root", lambda: root)
    monkeypatch.setattr(window, "verify_application_integrity", lambda: None)
    monkeypatch.setattr("mac_audit_agent.ui.main_window.select_integrity_manifest", lambda root: Selection())
    monkeypatch.setattr("mac_audit_agent.ui.main_window.verify_current_install_integrity", lambda *args, **kwargs: _FakeIntegrityResult(_integrity_payload()))
    monkeypatch.setattr("mac_audit_agent.ui.main_window.create_integrity_manifest", lambda *args, **kwargs: create_calls.append(kwargs) or FakeManifest())
    monkeypatch.setattr("mac_audit_agent.ui.main_window.write_integrity_manifest", lambda *args, **kwargs: Selection.manifest_path.write_text("trusted", encoding="utf-8"))
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QMessageBox.question", lambda *args, **kwargs: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QMessageBox.warning", lambda *args, **kwargs: None)
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QMessageBox.information", lambda *args, **kwargs: None)

    monkeypatch.setattr("mac_audit_agent.ui.main_window.QDialog.exec", lambda self: QDialog.Accepted)

    window.create_trusted_integrity_manifest()

    assert create_calls == []
    assert not Selection.manifest_path.exists()

    monkeypatch.setattr("mac_audit_agent.ui.main_window.QCheckBox.isChecked", lambda self: True)
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QInputDialog.getText", lambda *args, **kwargs: ("TRUST CURRENT BUILD", True))

    window.create_trusted_integrity_manifest()

    assert create_calls == []
    assert not Selection.manifest_path.exists()

    monkeypatch.setattr("mac_audit_agent.ui.main_window.QInputDialog.getText", lambda *args, **kwargs: ("TRUST CURRENT FILES", True))

    window.create_trusted_integrity_manifest()

    assert len(create_calls) == 1
    assert Selection.manifest_path.exists()
    window.close()
    app.processEvents()


def test_integrity_ui_actions_do_not_auto_trust(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    output = tmp_path / "integrity-report.json"
    create_calls: list[object] = []

    monkeypatch.setattr("mac_audit_agent.ui.main_window.verify_current_install_integrity", lambda *args, **kwargs: _FakeIntegrityResult(_integrity_payload()))
    monkeypatch.setattr("mac_audit_agent.ui.main_window.create_integrity_manifest", lambda *args, **kwargs: create_calls.append(kwargs) or object())
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QFileDialog.getSaveFileName", lambda *args, **kwargs: (str(output), "JSON Files (*.json)"))
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QMessageBox.information", lambda *args, **kwargs: None)
    monkeypatch.setattr("mac_audit_agent.ui.main_window.QMessageBox.warning", lambda *args, **kwargs: None)

    class FakeMessageBox:
        Warning = 1
        Information = 2
        Ok = 0

        def __init__(self, *args, **kwargs) -> None:
            pass

        def setIcon(self, value) -> None:
            pass

        def setWindowTitle(self, value) -> None:
            pass

        def setText(self, value) -> None:
            pass

        def setDetailedText(self, value) -> None:
            pass

        def addButton(self, *args, **kwargs) -> None:
            pass

        def exec(self) -> int:
            return 0

        @staticmethod
        def information(*args, **kwargs) -> None:
            return None

        @staticmethod
        def warning(*args, **kwargs) -> None:
            return None

    monkeypatch.setattr("mac_audit_agent.ui.main_window.QMessageBox", FakeMessageBox)

    window.verify_application_integrity()
    window.view_integrity_mismatch_details()
    window.export_integrity_report()

    assert create_calls == []
    assert output.exists()
    window.close()
    app.processEvents()
