import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel, QHBoxLayout, QPushButton, QDialog

from mac_audit_agent.ui.main_window import MainWindow
from mac_audit_agent.ui import main_window as main_window_module
from mac_audit_agent.ui.cve_radar_panel import CveRadarCardWidget, CveRadarDetailsDialog, CveRadarPanel, CveRadarUpdateGuidanceDialog
from mac_audit_agent.cve_radar import AppleSecurityForecast
from mac_audit_agent.apple_exposure_guidance import build_apple_exposure_update_guide


def test_apple_security_forecast_shows_not_checked_on_startup(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    assert window.cve_radar_panel.status_label.text() == "Assessment not checked yet"
    assert "Apple Exposure Assessment has not been checked yet." in window.cve_radar_panel.reason_label.text()
    window.close()
    app.processEvents()


def test_forecast_panel_does_not_expose_demo_controls(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    assert not hasattr(window.cve_radar_panel, "demo_button")
    assert not hasattr(window.cve_radar_panel, "safari_demo_button")
    assert not hasattr(window.cve_radar_panel, "clear_demo_button")
    assert not hasattr(window, "generate_demo_apple_security_forecast")
    assert not hasattr(window, "generate_safari_webkit_demo_apple_security_forecast")
    window.close()
    app.processEvents()


def test_simulated_forecast_cache_is_not_rendered_after_restart(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    db_path = tmp_path / "audit.sqlite"
    window = MainWindow(db_path)
    window.db.record_apple_security_forecast(
        {
            "forecast_id": "demo-old",
            "generated_at": "2026-06-01T00:00:00+00:00",
            "level": "urgent",
            "summary": "",
            "affected_products": [],
            "cve_count": 1,
            "kev_count": 1,
            "highest_severity": "critical",
            "recommended_action": "",
            "previous_level": "watch",
            "next_check_at": "",
            "payload_json": {"simulated": True, "source_mode": "demo", "cards": [{"title": "Demo", "simulated": True}]},
        }
    )
    window.close()
    app.processEvents()

    restarted = MainWindow(db_path)
    assert restarted.cve_radar_panel.status_label.text() == "Assessment not checked yet"
    assert restarted.cve_radar_panel.current_card() is None
    restarted.close()
    app.processEvents()


def test_forecast_tab_exists_and_dashboard_is_compact(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    sidebar_items = [window.sidebar.item(index).text() for index in range(window.sidebar.count())]
    assert "Apple Exposure Assessment" in sidebar_items
    assert window.cve_radar_panel.parentWidget() is not None
    assert window.cve_radar_panel.window() is window
    assert window.dashboard_forecast_frame.isVisible() is False or window.dashboard_forecast_frame.objectName() == "dashboardForecastSummary"
    assert window.dashboard_forecast_level_label.text().startswith("Level:")
    assert window.dashboard_forecast_cards_label.text().startswith("Cards:")
    assert window.open_forecast_button.text() == "Open Apple Exposure Assessment"
    assert window.open_forecast_button.objectName() == "openAppleExposureAssessmentButton"
    assert window.open_forecast_button.isVisible()
    assert window.open_forecast_button.isEnabled()
    assert window.open_forecast_button.toolTip() == "Open the Apple Exposure Assessment view to review Mac-relevant Apple security update exposure."
    window.close()
    app.processEvents()


def test_forecast_button_opens_apple_exposure_assessment(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    apple_row = [window.sidebar.item(index).text() for index in range(window.sidebar.count())].index("Apple Exposure Assessment")
    window.open_forecast_button.click()
    assert window.sidebar.currentRow() == apple_row
    assert window.pages.currentIndex() == apple_row
    window.close()
    app.processEvents()


def test_navigation_helper_opens_apple_exposure_assessment(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    apple_row = [window.sidebar.item(index).text() for index in range(window.sidebar.count())].index("Apple Exposure Assessment")
    assert window.navigate_to_view("apple_exposure_assessment") is True
    assert window.sidebar.currentRow() == apple_row
    assert window.pages.currentIndex() == apple_row
    window.close()
    app.processEvents()


def test_missing_apple_exposure_view_fails_gracefully(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    messages: list[str] = []
    monkeypatch.setattr(main_window_module.QMessageBox, "warning", lambda _parent, _title, message: messages.append(message))
    for index in range(window.sidebar.count()):
        if window.sidebar.item(index).text() == "Apple Exposure Assessment":
            window.sidebar.takeItem(index)
            break
    assert window.navigate_to_view("apple_exposure_assessment") is False
    assert messages == ["Apple Exposure Assessment view is unavailable."]
    window.close()
    app.processEvents()


def test_forecast_button_does_not_refresh_automatically(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    refresh_calls: list[str] = []
    monkeypatch.setattr(window, "refresh_apple_security_forecast", lambda *args, **kwargs: refresh_calls.append("refresh"))
    window.open_forecast_button.click()
    assert refresh_calls == []
    window.close()
    app.processEvents()


def test_apple_exposure_empty_state_displays_after_navigation(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    window.open_forecast_button.click()
    assert window.cve_radar_panel.status_label.text() == "Assessment not checked yet"
    assert window.cve_radar_panel.reason_label.text() == "Apple Exposure Assessment has not been checked yet."
    window.close()
    app.processEvents()


def test_forecast_buttons_have_widths_labels_and_tooltips() -> None:
    app = QApplication.instance() or QApplication([])
    panel = CveRadarPanel()
    buttons = {
        "update": panel.update_button,
        "diagnostics": panel.diagnostics_button,
        "export": panel.export_button,
        "details": panel.details_button,
        "review": panel.review_button,
        "snooze": panel.snooze_button,
        "guidance": panel.guidance_button,
    }
    for button in buttons.values():
        assert button.text().strip()
        assert button.toolTip().strip()
        assert button.minimumWidth() >= 110
        assert "background: #" in button.styleSheet()
        assert "rgba(" not in button.styleSheet()
        assert "min-height: 34px" in button.styleSheet()
    assert buttons["update"].text() == "Update Assessment"
    assert buttons["diagnostics"].text() == "Diagnostics"
    assert buttons["export"].text() == "Export Assessment"
    assert buttons["details"].text() == "View Details"
    assert buttons["review"].text() == "Reviewed"
    assert buttons["snooze"].text() == "Snooze"
    assert buttons["guidance"].text() == "Update Guidance"
    panel.close()
    app.processEvents()


def test_forecast_selected_action_buttons_are_inside_panel() -> None:
    app = QApplication.instance() or QApplication([])
    panel = CveRadarPanel()
    action_buttons = [
        panel.details_button,
        panel.review_button,
        panel.snooze_button,
        panel.guidance_button,
    ]

    assert panel.selected_action_frame.parentWidget() is panel
    for button in action_buttons:
        assert button.parentWidget() is panel.selected_action_frame
        assert button.window() is panel.window()

    panel.close()
    app.processEvents()


def test_forecast_card_action_area_renders_all_actions() -> None:
    app = QApplication.instance() or QApplication([])
    card = {
        "title": "Safari/WebKit Security Update",
        "forecast_level": "elevated",
        "source": "apple",
        "applicability_confidence": "high",
        "recommended_action": "Review Software Update.",
        "update_guidance": "System Settings > General > Software Update",
        "references": ["https://support.apple.com/"],
    }
    widget = CveRadarCardWidget(card)
    buttons = {button.text() for button in widget.findChildren(QPushButton)}
    assert {"Details", "Reviewed", "Snooze", "Update Guidance"}.issubset(buttons)
    action_rows = widget.findChildren(QHBoxLayout)
    assert len(action_rows) >= 2
    assert all(row.count() <= 2 for row in action_rows[-2:])
    for button in widget.findChildren(QPushButton):
        assert button.toolTip().strip()
        assert button.minimumWidth() >= 110
    widget.close()
    app.processEvents()


def test_forecast_card_shows_planning_and_false_positive_language() -> None:
    app = QApplication.instance() or QApplication([])
    card = {
        "title": "Safari/WebKit Security Update",
        "forecast_level": "elevated",
        "source": "apple",
        "applicability_confidence": "high",
        "forecast_phrase": "Check Software Update today",
        "planning_guidance": "Check Software Update today or during the next normal maintenance window.",
        "false_positive_review": {
            "result": "Low false-positive risk",
            "reason": "Apple release evidence and local version checks point to this Mac.",
            "checks": {"private_data_inspected": False},
        },
        "recommended_action": "Check Software Update.",
        "update_guidance": "System Settings > General > Software Update",
    }
    widget = CveRadarCardWidget(card)
    text = " ".join(label.text() for label in widget.findChildren(QLabel))
    assert "Check Software Update today" in text
    assert "Low false-positive risk" in text
    assert "Apple release evidence" in text
    widget.close()
    app.processEvents()


def test_forecast_update_handles_dict_cards(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    forecast = AppleSecurityForecast(
        forecast_id="forecast-1",
        generated_at="2026-06-01T00:00:00Z",
        level="elevated",
        cards=[
            {
                "card_id": "card-1",
                "title": "Safari/WebKit Security Update",
                "forecast_level": "elevated",
                "source": "apple",
                "affected_local_product": "Safari",
                "detected_version": "17.0",
                "fixed_version": "17.1",
                "cves": ["CVE-2026-0001"],
            }
        ],
    )
    window.cve_radar_engine.db.record_apple_security_forecast(forecast.to_dict())
    window.cve_radar_engine.db.record_apple_security_forecast_cards([forecast.cards[0]])
    payload = window.cve_radar_engine.load_cached_state()
    assert payload["display_cards"]
    window.close()
    app.processEvents()


def test_update_guidance_builder_macos_card_is_nonblank() -> None:
    guide = build_apple_exposure_update_guide(
        {
            "card_id": "macos-1",
            "title": "macOS Security Update Available",
            "affected_local_product": "macOS",
            "detected_version": "14.4",
            "fixed_version": "14.5",
            "forecast_level": "elevated",
            "applicability_confidence": "high",
            "recommended_action": "Install macOS update.",
            "references": ["https://support.apple.com/en-us/100100"],
        },
        {"macos_version": "14.4"},
        {"generated_at": "2026-06-01T00:00:00Z"},
    )
    text = guide.to_text()
    assert guide.title == "macOS Security Update Guidance"
    assert "Open System Settings" in text
    assert "Verification Steps" in text
    assert "https://support.apple.com/en-us/100100" in text


def test_update_guidance_builder_safari_xcode_kev_review_and_missing_data() -> None:
    safari = build_apple_exposure_update_guide({"title": "Safari WebKit Update", "affected_local_product": "Safari/WebKit", "forecast_level": "urgent"})
    assert safari.title == "Safari / WebKit Security Update Guidance"
    assert "Restart Safari" in safari.to_text()

    xcode = build_apple_exposure_update_guide({"title": "Xcode Command Line Tools", "affected_local_product": "Xcode", "forecast_level": "watch"})
    assert xcode.title == "Xcode / Command Line Tools Update Guidance"
    assert "App Store" in xcode.to_text()

    kev = build_apple_exposure_update_guide({"title": "Known exploited WebKit", "affected_local_product": "macOS", "kev": True, "forecast_level": "critical"})
    assert kev.title == "Known Exploited Apple Vulnerability Guidance"
    assert "does not prove this Mac is compromised" in kev.to_text()

    review = build_apple_exposure_update_guide({"title": "Review Needed", "applicability": "review_needed"})
    assert review.title == "Apple Security Advisory Review Needed"
    assert "Mark Reviewed or Snooze" in review.to_text()

    missing = build_apple_exposure_update_guide({"title": "Incomplete Apple advisory"})
    assert missing.to_text().strip()
    assert "Recommended/fixed version could not be determined automatically" in missing.to_text()
    assert missing.fallback_used is True


def test_update_guidance_builder_no_selection_empty_state() -> None:
    guide = build_apple_exposure_update_guide(None)
    text = guide.to_text()
    assert guide.title == "Apple Security Update Guidance"
    assert "No Apple Exposure item is selected" in text
    assert "Refresh Apple Exposure Assessment" in text
    assert "Open Software Update" in text
    assert "Evidence Preservation" in text
    assert text.strip()


def test_update_guidance_button_opens_nonblank_selected_and_empty_state(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    panel = CveRadarPanel()
    captured: list[str] = []

    def fake_init(self, body, **kwargs):
        captured.append(body)
        QDialog.__init__(self, kwargs.get("parent"))

    monkeypatch.setattr(CveRadarUpdateGuidanceDialog, "__init__", fake_init)
    monkeypatch.setattr(CveRadarUpdateGuidanceDialog, "exec", lambda self: 0)

    panel.open_update_guidance()
    assert "No Apple Exposure item is selected" in captured[-1]

    panel.set_radar_data(
        {
            "generated_at": "2026-06-01T00:00:00Z",
            "display_cards": [
                {
                    "card_id": "card-1",
                    "title": "Safari/WebKit Security Update",
                    "affected_local_product": "Safari/WebKit",
                    "forecast_level": "urgent",
                    "recommended_action": "Install available updates.",
                    "references": ["https://support.apple.com/en-us/100100"],
                }
            ],
        }
    )
    panel.open_update_guidance()
    assert "Safari / WebKit Security Update Guidance" in captured[-1]
    assert "Recommended Actions" in captured[-1]
    assert "Verification Steps" in captured[-1]
    assert "References" in captured[-1]
    assert not panel.toolbar_guidance_button.isHidden()
    assert panel.toolbar_guidance_button.isEnabled()
    assert panel.toolbar_guidance_button.text() == "Update Guidance"
    panel.close()
    app.processEvents()
