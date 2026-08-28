from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from mac_audit_agent.quality.functional_registry import build_registry
from mac_audit_agent.ui.findings_filter import (
    FindingFilter,
    apply_severity_filter,
    get_active_filter_summary,
    normalize_severity,
    validate_dashboard_severity_counts_match_findings,
)
from mac_audit_agent.ui.main_window import MainWindow
from mac_audit_agent.ui.navigation_intents import create_findings_severity_intent


def _findings() -> list[dict[str, str]]:
    return [
        {"severity": "info", "category": "General", "title": "Info item", "evidence": "context"},
        {"severity": "low", "category": "General", "title": "Low item", "evidence": "minor"},
        {"severity": "medium", "category": "General", "title": "Medium item", "evidence": "review"},
        {"severity": "high", "category": "General", "title": "High item", "evidence": "urgent"},
        {"severity": "critical", "category": "General", "title": "Critical item", "evidence": "immediate"},
    ]


def test_severity_navigation_normalization_and_filtering() -> None:
    assert normalize_severity("Info") == "info"
    assert normalize_severity("Informational") == "info"
    assert normalize_severity("Severe") == "critical"
    assert normalize_severity("Critical") == "critical"
    assert [item["title"] for item in apply_severity_filter(_findings(), "high")] == ["High item"]
    assert apply_severity_filter(_findings(), "none-present") == _findings()
    assert apply_severity_filter(_findings(), "severe")[0]["title"] == "Critical item"
    assert "No High severity findings" in get_active_filter_summary(FindingFilter(severity="high"), match_count=0)


def test_dashboard_severity_counts_match_findings_data() -> None:
    counts = {"info": 1, "low": 1, "medium": 1, "high": 1, "critical": 1}
    result = validate_dashboard_severity_counts_match_findings(counts, _findings())
    assert result["status"] == "pass"
    stale = validate_dashboard_severity_counts_match_findings({**counts, "high": 9}, _findings())
    assert stale["status"] == "warn"
    assert stale["mismatches"]["high"]["dashboard"] == 9


def test_navigation_intent_preserves_scan_id_and_route() -> None:
    intent = create_findings_severity_intent("Severe", scan_id="scan-123")
    assert intent.target_view == "findings"
    assert intent.filter_type == "severity"
    assert intent.filter_value == "critical"
    assert intent.scan_id == "scan-123"
    assert intent.to_route() == {"view": "findings", "params": {"severity": "critical", "scan_id": "scan-123"}}
    assert intent.to_internal_url() == "msaa://findings?severity=critical&scan_id=scan-123"


def test_dashboard_severity_cards_click_to_filtered_findings(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    window.current_scan_active = True
    window.current_payload = {
        "findings": _findings(),
        "dashboard": {
            "suspicious_ports": 0,
            "users_admin_changes": 0,
            "history_indicators": 0,
            "suspicious_directories": 0,
            "new_since_last_scan": 0,
        },
    }
    window._set_results_available(True)
    window._refresh_dashboard()

    high_card = window.severity_card_widgets[3]
    assert high_card.accessibleName() == "View High severity findings"
    assert "Opens the Findings view filtered" in high_card.accessibleDescription()
    QTest.mouseClick(high_card, Qt.LeftButton)
    app.processEvents()

    assert window.sidebar.currentItem().text() == "Results"
    assert window.results_tabs.tabText(window.results_tabs.currentIndex()) == "Findings"
    assert window.active_findings_filter.severity == "high"
    assert not window.findings_filter_banner.isHidden()
    assert "Showing High severity findings from latest scan." in window.findings_filter_label.text()
    assert window.findings_table.rowCount() == 1
    assert window.findings_table.item(0, 2).text() == "High item"

    window.clear_findings_filter_button.click()
    assert window.findings_table.rowCount() == 5
    assert not window.findings_filter_banner.isVisible()
    window.close()
    app.processEvents()


def test_dashboard_severity_keyboard_activation_and_zero_count(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    window.current_scan_active = True
    window.current_payload = {
        "findings": [{"severity": "medium", "category": "General", "title": "Medium item", "evidence": "review"}],
        "dashboard": {
            "suspicious_ports": 0,
            "users_admin_changes": 0,
            "history_indicators": 0,
            "suspicious_directories": 0,
            "new_since_last_scan": 0,
        },
    }
    window._set_results_available(True)
    window._refresh_dashboard()

    critical_card = window.severity_card_widgets[4]
    critical_card.setFocus()
    QTest.keyClick(critical_card, Qt.Key_Return)
    app.processEvents()

    assert window.active_findings_filter.severity == "critical"
    assert window.findings_table.rowCount() == 0
    assert "No Critical severity findings were found in the latest scan." in window.findings_filter_label.text()
    window.back_to_dashboard_button.click()
    assert window.sidebar.currentItem().text() == "Dashboard"
    window.close()
    app.processEvents()


def test_dashboard_severity_navigation_no_scan_does_not_crash(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    window.navigate_to_findings_by_severity("informational")
    assert window.sidebar.currentItem().text() == "Results"
    assert "No scan results are available yet. Run a scan first." in window.findings_filter_label.text()
    window.close()
    app.processEvents()


def test_dashboard_severity_navigation_pre_uat_registered() -> None:
    assert "ui.dashboard_severity_navigation" in {check.check_id for check in build_registry()}


def test_results_pin_critical_findings_across_filters_until_completed_scan_clears_them(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    window._populate_pinned_critical_results(_findings(), authoritative=True, scan_id="scan-critical")
    window._populate_findings([item for item in _findings() if item["severity"] == "low"])

    assert window.critical_results_table.rowCount() == 1
    assert window.critical_results_table.item(0, 1).text() == "Critical item"
    assert "1 requires attention" in window.critical_results_heading.text()
    assert window.open_critical_results_button.isEnabled()

    window._populate_pinned_critical_results([], authoritative=True, scan_id="scan-resolved")
    assert "none in the active completed scan" in window.critical_results_heading.text()
    assert not window.open_critical_results_button.isEnabled()
    window.close()
    app.processEvents()
