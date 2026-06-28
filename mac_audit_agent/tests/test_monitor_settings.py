from __future__ import annotations

import json

from PySide6.QtWidgets import QApplication

from mac_audit_agent.models import BackgroundMonitorEvent
from mac_audit_agent.monitor_settings import load_settings, reset_defaults, save_settings, settings_diagnostics
from mac_audit_agent.notification_manager import NotificationManager
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.ui.background_monitor_panel import BackgroundMonitorPanel

from mac_audit_agent.tests.test_background_monitor import FakeLaunchAgent


def _event(event_type: str, severity: str = "high") -> BackgroundMonitorEvent:
    return BackgroundMonitorEvent(
        event_id=f"{event_type}-1",
        timestamp="2026-06-27T12:00:00+00:00",
        event_type=event_type,
        severity=severity,
        source="test",
        evidence=f"{event_type} evidence",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
        rule_id=event_type,
        trigger_rule_id=event_type,
        rule_name=event_type,
        trigger_rule_name=event_type,
    )


def test_monitor_settings_load_save_and_reset_defaults(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.alerting.notify_min_severity = "critical"
    settings.event_categories.usb = False
    settings.notification.enable_alert_sounds = True
    saved = save_settings(db, settings)

    payload = json.loads(db.get_background_monitor_state("monitor_settings_json", "{}"))
    assert saved.alerting.notify_min_severity == "critical"
    assert payload["alerting"]["notify_min_severity"] == "critical"
    assert db.get_background_monitor_state("notify_min_severity", "") == "critical"
    assert db.get_background_monitor_state("enable_alert_sounds", "") == "1"
    assert load_settings(db).event_categories.usb is False

    reset = reset_defaults(db)
    assert reset.alerting.notify_min_severity == "info"
    assert load_settings(db).event_categories.usb is True


def test_corrupt_monitor_settings_recover_safely(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.set_background_monitor_state("monitor_settings_json", "{bad json")
    settings = load_settings(db)

    assert settings.alerting.notify_min_severity == "info"
    assert "corrupt settings recovered" in db.get_background_monitor_state("monitor_settings_last_error", "")


def test_critical_severity_threshold_filters_lower_runtime_alerts(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.alerting.notify_min_severity = "critical"
    settings.notification.cooldown_seconds = 0
    save_settings(db, settings)
    manager = NotificationManager(db)

    high = _event("launchagent_added", "high")
    critical = _event("launchdaemon_added", "critical")

    assert manager.should_notify(high) is False
    assert high.notification_reason == "below_min_severity"
    assert manager.should_notify(critical) is True


def test_category_setting_updates_notifier_preferences(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.event_categories.usb = False
    save_settings(db, settings)
    manager = NotificationManager(db)

    assert manager.preference_for("usb_device_connected")["enabled"] is False
    assert manager.should_notify(_event("usb_device_connected", "critical")) is False


def test_critical_overlay_setting_updates_runtime_visible_alert_policy(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.notification.critical_overlay = False
    settings.notification.cooldown_seconds = 0
    save_settings(db, settings)
    manager = NotificationManager(db)

    decision = manager.should_show_visible_alert(_event("launchdaemon_added", "critical"))

    assert db.get_background_monitor_state("critical_overlay_enabled", "") == "0"
    assert manager.settings()["critical_overlay_enabled"] is False
    assert decision.show is False
    assert decision.reason == "critical overlay disabled"


def test_persistent_alert_setting_updates_runtime_visible_alert_policy(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.notification.persistent_alerts = False
    settings.notification.cooldown_seconds = 0
    save_settings(db, settings)
    manager = NotificationManager(db)

    decision = manager.should_show_visible_alert(_event("launchdaemon_added", "critical"))

    assert db.get_background_monitor_state("persistent_alerts", "") == "0"
    assert manager.settings()["persistent_alerts"] is False
    assert decision.show is True
    assert decision.persistent is False


def test_monitor_settings_diagnostics_reports_mismatch(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.installation.monitor_mode = "system"
    settings.installation.system_launch_daemon = True
    diagnostic = settings_diagnostics(
        db,
        settings,
        runtime_values={"notify_min_severity": settings.alerting.notify_min_severity, "cooldown_seconds_per_category": settings.notification.cooldown_seconds},
        installed_values={"system_launch_daemon_installed": False},
    )

    assert diagnostic["status"] == "mismatch"
    assert "system_launch_daemon_installation" in diagnostic["mismatches"]


def test_monitor_settings_ui_runtime_and_notifier_agree(tmp_path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    monkeypatch.setattr(panel, "refresh", lambda: None)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.warning", lambda *args, **kwargs: None)

    panel.notify_min_severity_combo.setCurrentIndex(panel.notify_min_severity_combo.findData("critical"))
    panel.category_checkboxes["usb"].setChecked(False)
    panel.cooldown_seconds_input.setText("42")
    panel.apply_monitor_settings_from_ui()

    loaded = load_settings(db)
    manager = NotificationManager(db)
    assert loaded.alerting.notify_min_severity == "critical"
    assert loaded.event_categories.usb is False
    assert db.get_background_monitor_state("notify_min_severity", "") == "critical"
    assert db.get_background_monitor_state("cooldown_seconds_per_category", "") == "42"
    assert manager.settings()["notify_min_severity"] == "critical"
    assert manager.preference_for("usb_device_connected")["enabled"] is False
    assert "current_settings_json" in panel.settings_diagnostics_panel.toPlainText()
    assert app is not None
