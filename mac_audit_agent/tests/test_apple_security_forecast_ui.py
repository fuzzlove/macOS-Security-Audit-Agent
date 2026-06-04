import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QPushButton

from mac_audit_agent.ui.main_window import MainWindow
from mac_audit_agent.ui.cve_radar_panel import CveRadarCardWidget, CveRadarPanel
from mac_audit_agent.cve_radar import AppleSecurityForecast


def test_apple_security_forecast_shows_not_checked_on_startup(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    assert window.cve_radar_panel.status_label.text() == "Forecast not checked yet"
    assert "No Apple Security Forecast has been checked yet." in window.cve_radar_panel.reason_label.text()
    window.close()
    app.processEvents()


def test_demo_forecast_renders_two_cards_and_is_marked_simulated(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    window.generate_demo_apple_security_forecast()
    assert window.cve_radar_panel.status_label.text() == "Urgent"
    assert window.cve_radar_panel.cards.count() == 2
    assert window.cve_radar_panel.current_card() is not None
    assert window.cve_radar_panel.current_card().get("simulated") is True
    forecast = window.db.latest_apple_security_forecast()
    assert forecast is not None
    assert forecast.get("simulated") is True
    assert forecast.get("source_mode") == "demo"
    window.close()
    app.processEvents()


def test_apple_security_forecast_loads_from_sqlite_after_restart(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    db_path = tmp_path / "audit.sqlite"
    window = MainWindow(db_path)
    window.generate_demo_apple_security_forecast()
    window.close()
    app.processEvents()

    restarted = MainWindow(db_path)
    assert restarted.cve_radar_panel.status_label.text() == "Urgent"
    assert restarted.cve_radar_panel.cards.count() == 2
    assert restarted.cve_radar_panel.current_card() is not None
    assert restarted.cve_radar_panel.current_card().get("simulated") is True
    restarted.close()
    app.processEvents()


def test_forecast_tab_exists_and_dashboard_is_compact(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    assert window.sidebar.item(1).text() == "Apple Security Forecast"
    assert window.pages.count() >= 7
    assert window.dashboard_forecast_frame.isVisible() is False or window.dashboard_forecast_frame.objectName() == "dashboardForecastSummary"
    assert window.dashboard_forecast_level_label.text().startswith("Level:")
    assert window.dashboard_forecast_cards_label.text().startswith("Cards:")
    assert window.open_forecast_button.text() == "Open Forecast"
    assert window.open_forecast_button.toolTip()
    window.close()
    app.processEvents()


def test_open_forecast_button_switches_to_forecast_tab(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    window.open_forecast_button.click()
    assert window.sidebar.currentRow() == 1
    assert window.pages.currentIndex() == 1
    window.close()
    app.processEvents()


def test_forecast_buttons_have_widths_labels_and_tooltips() -> None:
    app = QApplication.instance() or QApplication([])
    panel = CveRadarPanel()
    buttons = {
        "update": panel.update_button,
        "diagnostics": panel.diagnostics_button,
        "demo": panel.demo_button,
        "safari_demo": panel.safari_demo_button,
        "clear_demo": panel.clear_demo_button,
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
    assert buttons["update"].text() == "Update Forecast"
    assert buttons["diagnostics"].text() == "Diagnostics"
    assert buttons["demo"].text() == "Generate Demo"
    assert buttons["safari_demo"].text() == "Safari/WebKit Demo"
    assert buttons["clear_demo"].text() == "Clear Demo"
    assert buttons["export"].text() == "Export Forecast"
    assert buttons["details"].text() == "View Details"
    assert buttons["review"].text() == "Reviewed"
    assert buttons["snooze"].text() == "Snooze"
    assert buttons["guidance"].text() == "Update Guide"
    panel.close()
    app.processEvents()


def test_safari_webkit_demo_forecast_renders_single_simulated_card(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow(tmp_path / "audit.sqlite")
    window.generate_safari_webkit_demo_apple_security_forecast()
    assert window.cve_radar_panel.status_label.text() == "Elevated"
    assert window.cve_radar_panel.cards.count() == 1
    assert window.cve_radar_panel.current_card() is not None
    assert window.cve_radar_panel.current_card().get("simulated") is True
    assert window.cve_radar_panel.current_card().get("category") == "Safari/WebKit"
    forecast = window.db.latest_apple_security_forecast()
    assert forecast is not None
    assert forecast.get("simulated") is True
    assert forecast.get("source_mode") == "demo-safari-webkit"
    window.close()
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
    for button in widget.findChildren(QPushButton):
        assert button.toolTip().strip()
        assert button.minimumWidth() >= 110
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
