import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel, QHBoxLayout, QPushButton

from mac_audit_agent.ui.main_window import MainWindow
from mac_audit_agent.ui.cve_radar_panel import CveRadarCardWidget, CveRadarPanel
from mac_audit_agent.cve_radar import AppleSecurityForecast


def test_apple_security_forecast_shows_not_checked_on_startup(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    assert window.cve_radar_panel.status_label.text() == "Assessment not checked yet"
    assert "No Apple Exposure Assessment has been checked yet." in window.cve_radar_panel.reason_label.text()
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
    assert "Apple Exposure Assessment" not in sidebar_items
    assert window.cve_radar_panel.parentWidget() is not None
    assert window.cve_radar_panel.window() is window
    assert window.dashboard_forecast_frame.isVisible() is False or window.dashboard_forecast_frame.objectName() == "dashboardForecastSummary"
    assert window.dashboard_forecast_level_label.text().startswith("Level:")
    assert window.dashboard_forecast_cards_label.text().startswith("Cards:")
    assert window.open_forecast_button.text() == "Show Assessment"
    assert window.open_forecast_button.toolTip()
    window.close()
    app.processEvents()


def test_forecast_button_keeps_user_on_dashboard(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    window.open_forecast_button.click()
    assert window.sidebar.currentRow() == 0
    assert window.pages.currentIndex() == 0
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
    assert buttons["guidance"].text() == "Update Guide"
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
    assert {"Details", "Reviewed", "Snooze", "Update Guide"}.issubset(buttons)
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
