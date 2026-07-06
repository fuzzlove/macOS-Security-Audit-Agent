from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtWidgets import QApplication, QLabel

from mac_audit_agent.models import BackgroundMonitorEvent
from mac_audit_agent.alert_styles import ALERT_SEVERITY_STYLES, validate_alert_styles
from mac_audit_agent.monitor import BackgroundMonitorService
from mac_audit_agent.hardware_monitor import HardwareMonitorSnapshot
from mac_audit_agent.monitor_settings import load_settings, migrate_settings, reset_defaults, save_settings, settings_diagnostics
from mac_audit_agent.security_overlay import SEVERITY_STYLES
from mac_audit_agent.launch_agent import build_launch_agent_plist
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
    assert settings.event_categories.admin_persistence_monitoring_enabled is True
    assert settings.event_categories.network_activity_monitoring_enabled is True
    assert settings.event_categories.usb_monitoring_enabled is True
    assert settings.event_categories.bluetooth_monitoring_enabled is True
    assert settings.local_edr.persistent_local_edr_enabled is True
    assert settings.local_edr.persistent_local_edr_alerts_enabled is True
    assert settings.local_edr.persistent_local_edr_local_only is True
    assert settings.event_categories.usb_unknown_device_alerts_enabled is True
    assert settings.event_categories.bluetooth_unknown_device_alerts_enabled is True
    assert settings.event_categories.network_suspicious_connection_alerts_enabled is True
    assert settings.event_categories.network_localhost_visibility_alerts_enabled is True
    settings.alerting.notify_min_severity = "critical"
    settings.event_categories.usb = False
    settings.event_categories.admin_persistence_monitoring_enabled = False
    settings.event_categories.network_activity_monitoring_enabled = False
    settings.event_categories.usb_monitoring_enabled = False
    settings.event_categories.bluetooth_monitoring_enabled = False
    settings.local_edr.persistent_local_edr_enabled = False
    settings.local_edr.persistent_local_edr_alerts_enabled = False
    settings.notification.enable_alert_sounds = True
    settings.installation.monitor_mode = "system"
    settings.installation.system_launch_daemon = True
    settings.installation.run_at_load = False
    settings.installation.keep_alive = False
    settings.installation.auto_restart = False
    settings.installation.db_path = str(tmp_path / "selected.sqlite")
    settings.installation.log_path = str(tmp_path / "selected.log")
    saved = save_settings(db, settings)

    payload = json.loads(db.get_background_monitor_state("monitor_settings_json", "{}"))
    assert saved.alerting.notify_min_severity == "critical"
    assert saved.settings_version == 1
    assert saved.updated_at
    assert payload["settings_version"] == 1
    assert payload["updated_at"] == saved.updated_at
    assert payload["alerting"]["notify_min_severity"] == "critical"
    assert db.get_background_monitor_state("notify_min_severity", "") == "critical"
    assert db.get_background_monitor_state("enable_alert_sounds", "") == "1"
    assert db.get_background_monitor_state("admin_persistence_monitoring_enabled", "") == "0"
    assert db.get_background_monitor_state("network_activity_monitoring_enabled", "") == "0"
    assert db.get_background_monitor_state("usb_monitoring_enabled", "") == "0"
    assert db.get_background_monitor_state("bluetooth_monitoring_enabled", "") == "0"
    assert db.get_background_monitor_state("persistent_local_edr_enabled", "") == "0"
    assert db.get_background_monitor_state("persistent_local_edr_alerts_enabled", "") == "0"
    assert db.get_background_monitor_state("monitor_mode", "") == "system"
    assert db.get_background_monitor_state("installation_run_at_load", "") == "0"
    assert db.get_background_monitor_state("installation_keep_alive", "") == "0"
    assert db.get_background_monitor_state("installation_auto_restart", "") == "0"
    assert db.get_background_monitor_state("db_path", "") == str(tmp_path / "selected.sqlite")
    assert db.get_background_monitor_state("log_path", "") == str(tmp_path / "selected.log")
    assert load_settings(db).event_categories.usb is False
    assert load_settings(db).event_categories.admin_persistence_monitoring_enabled is False
    assert load_settings(db).event_categories.network_activity_monitoring_enabled is False
    assert load_settings(db).event_categories.usb_monitoring_enabled is False
    assert load_settings(db).event_categories.bluetooth_monitoring_enabled is False
    assert load_settings(db).local_edr.persistent_local_edr_enabled is False
    assert load_settings(db).local_edr.persistent_local_edr_alerts_enabled is False
    assert load_settings(db).installation.run_at_load is False
    assert load_settings(db).installation.keep_alive is False
    assert load_settings(db).installation.auto_restart is False

    reset = reset_defaults(db)
    assert reset.alerting.notify_min_severity == "info"
    assert load_settings(db).event_categories.usb is True
    assert load_settings(db).event_categories.admin_persistence_monitoring_enabled is True
    assert load_settings(db).event_categories.network_activity_monitoring_enabled is True
    assert load_settings(db).event_categories.usb_monitoring_enabled is True
    assert load_settings(db).event_categories.bluetooth_monitoring_enabled is True
    assert load_settings(db).local_edr.persistent_local_edr_enabled is True


def test_parent_disabled_preserves_child_settings_but_suppresses_preferences(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.event_categories.usb_monitoring_enabled = False
    settings.event_categories.usb_new_device_alerts_enabled = True
    settings.event_categories.usb_unknown_device_alerts_enabled = True
    settings.event_categories.bluetooth_monitoring_enabled = False
    settings.event_categories.bluetooth_inventory_alerts_enabled = True
    settings.event_categories.bluetooth_unknown_device_alerts_enabled = True
    settings.event_categories.network_activity_monitoring_enabled = False
    settings.event_categories.network_vpn_alerts_enabled = True
    settings.event_categories.network_suspicious_connection_alerts_enabled = True
    settings.event_categories.network_localhost_visibility_alerts_enabled = True
    settings.event_categories.admin_persistence_monitoring_enabled = False
    settings.event_categories.launchagent_monitoring_enabled = True
    saved = save_settings(db, settings)

    loaded = load_settings(db)
    manager = NotificationManager(db)

    assert loaded.event_categories.usb_new_device_alerts_enabled is True
    assert loaded.event_categories.usb_unknown_device_alerts_enabled is True
    assert loaded.event_categories.bluetooth_inventory_alerts_enabled is True
    assert loaded.event_categories.bluetooth_unknown_device_alerts_enabled is True
    assert loaded.event_categories.network_vpn_alerts_enabled is True
    assert loaded.event_categories.network_suspicious_connection_alerts_enabled is True
    assert loaded.event_categories.network_localhost_visibility_alerts_enabled is True
    assert loaded.event_categories.launchagent_monitoring_enabled is True
    assert saved.event_categories.usb_monitoring_enabled is False
    assert manager.preference_for("new_usb_device_detected")["enabled"] is False
    assert manager.preference_for("bluetooth_inventory_changed")["enabled"] is False
    assert manager.preference_for("vpn_connected")["enabled"] is False
    assert manager.preference_for("launchagent_added")["enabled"] is False


def test_persistent_local_edr_disabled_suppresses_monitor_alerts(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.local_edr.persistent_local_edr_enabled = False
    save_settings(db, settings)
    manager = NotificationManager(db)

    decision = manager.should_show_visible_alert(_event("launchagent_added", "high"))

    assert manager.settings()["persistent_local_edr_enabled"] is False
    assert decision.show is False
    assert decision.reason == "persistent_local_edr_disabled"


def test_bottom_right_overlay_styles_are_solid_and_high_contrast() -> None:
    assert validate_alert_styles() == []
    assert SEVERITY_STYLES["info_grey"]["opacity"] == 1.0
    assert SEVERITY_STYLES["neutral_grey"]["opacity"] == 1.0
    assert SEVERITY_STYLES["medium_blue"]["opacity"] == 1.0
    assert SEVERITY_STYLES["high_orange"]["opacity"] == 1.0
    assert SEVERITY_STYLES["critical_red"]["opacity"] == 1.0
    assert ALERT_SEVERITY_STYLES["critical"].background != ALERT_SEVERITY_STYLES["high"].background
    assert ALERT_SEVERITY_STYLES["medium"].background != ALERT_SEVERITY_STYLES["info"].background
    for style in ALERT_SEVERITY_STYLES.values():
        payload = style.to_dict()
        assert payload["background"].startswith("#")
        assert payload["badge_background"].startswith("#")
        assert "rgba" not in json.dumps(payload).lower()
        assert "transparent" not in json.dumps(payload).lower()


def test_security_overlay_source_does_not_use_transparent_alert_card_styles() -> None:
    source = (Path(__file__).resolve().parents[1] / "security_overlay.py").read_text(encoding="utf-8").lower()
    assert "rgba(" not in source
    assert "background-color: transparent" not in source
    assert "background: transparent" not in source
    assert "setwindowopacity(1.0)" in source
    assert "setwindowopacity(0." not in source


def test_child_monitor_setting_disables_specific_alert_preference(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.event_categories.usb_monitoring_enabled = True
    settings.event_categories.usb_storage_alerts_enabled = False
    settings.event_categories.usb_unknown_device_alerts_enabled = False
    settings.event_categories.network_activity_monitoring_enabled = True
    settings.event_categories.network_vpn_alerts_enabled = False
    settings.event_categories.network_suspicious_connection_alerts_enabled = False
    settings.event_categories.network_localhost_visibility_alerts_enabled = False
    settings.event_categories.bluetooth_monitoring_enabled = True
    settings.event_categories.bluetooth_unknown_device_alerts_enabled = False
    save_settings(db, settings)
    manager = NotificationManager(db)

    assert manager.preference_for("usb_storage_device_connected")["enabled"] is False
    assert manager.preference_for("usb_unknown_class_connected")["enabled"] is False
    assert manager.preference_for("usb_unknown_class_connected")["suppression_reason"] == "usb_unknown_device_alerts_disabled"
    assert manager.preference_for("vpn_connected")["enabled"] is False
    assert manager.preference_for("suspicious_network_connection_detected")["enabled"] is False
    assert manager.preference_for("suspicious_network_connection_detected")["suppression_reason"] == "network_suspicious_connection_alerts_disabled"
    assert manager.preference_for("hidden_localhost_port_detected")["enabled"] is False
    assert manager.preference_for("hidden_localhost_port_detected")["suppression_reason"] == "network_localhost_visibility_alerts_disabled"
    assert manager.preference_for("unknown_bluetooth_device_detected")["enabled"] is False
    assert manager.preference_for("unknown_bluetooth_device_detected")["suppression_reason"] == "bluetooth_unknown_device_alerts_disabled"
    assert manager.preference_for("usb_hid_device_connected")["enabled"] is True


def test_corrupt_monitor_settings_recover_safely(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.set_background_monitor_state("monitor_settings_json", "{bad json")
    settings = load_settings(db)

    assert settings.alerting.notify_min_severity == "info"
    assert "corrupt settings recovered" in db.get_background_monitor_state("monitor_settings_last_error", "")


def test_migrate_settings_adds_missing_monitoring_keys(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.set_background_monitor_state("monitor_settings_json", json.dumps({"schema_version": 1, "event_categories": {"usb_monitoring_enabled": False}}))

    migrated = migrate_settings(db)
    payload = json.loads(db.get_background_monitor_state("monitor_settings_json", "{}"))

    assert migrated.event_categories.usb_monitoring_enabled is False
    assert migrated.event_categories.bluetooth_monitoring_enabled is True
    assert migrated.event_categories.network_activity_monitoring_enabled is True
    assert migrated.event_categories.usb_unknown_device_alerts_enabled is True
    assert migrated.event_categories.bluetooth_unknown_device_alerts_enabled is True
    assert migrated.event_categories.network_suspicious_connection_alerts_enabled is True
    assert migrated.event_categories.network_localhost_visibility_alerts_enabled is True
    assert migrated.event_categories.admin_persistence_monitoring_enabled is True
    assert "bluetooth_monitoring_enabled" in payload["event_categories"]
    assert "network_activity_monitoring_enabled" in payload["event_categories"]
    assert "usb_unknown_device_alerts_enabled" in payload["event_categories"]
    assert "bluetooth_unknown_device_alerts_enabled" in payload["event_categories"]
    assert "network_suspicious_connection_alerts_enabled" in payload["event_categories"]
    assert "network_localhost_visibility_alerts_enabled" in payload["event_categories"]
    assert "admin_persistence_monitoring_enabled" in payload["event_categories"]


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


def test_launch_agent_plist_uses_installation_settings(tmp_path) -> None:
    payload = build_launch_agent_plist(
        db_path=tmp_path / "custom.sqlite",
        run_at_load=False,
        keep_alive=True,
        auto_restart=False,
        stdout_path=tmp_path / "custom.log",
        stderr_path=tmp_path / "custom.err.log",
    )

    assert payload["RunAtLoad"] is False
    assert payload["KeepAlive"] is False
    assert payload["EnvironmentVariables"]["MAC_AUDIT_AGENT_DB_PATH"] == str(tmp_path / "custom.sqlite")
    assert payload["StandardOutPath"] == str(tmp_path / "custom.log")
    assert payload["StandardErrorPath"] == str(tmp_path / "custom.err.log")


def test_category_setting_updates_notifier_preferences(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.event_categories.usb = False
    save_settings(db, settings)
    manager = NotificationManager(db)

    assert manager.preference_for("usb_device_connected")["enabled"] is False
    assert manager.should_notify(_event("usb_device_connected", "critical")) is False


def test_admin_and_network_monitoring_disabled_suppress_visible_alerts_with_reason(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.event_categories.admin_persistence_monitoring_enabled = False
    settings.event_categories.network_activity_monitoring_enabled = False
    save_settings(db, settings)
    manager = NotificationManager(db)

    admin_decision = manager.evaluate_notification_decision(_event("launchagent_added", "critical"))
    network_decision = manager.evaluate_notification_decision(_event("new_network_connection_detected", "high"))

    assert admin_decision["visible_alert_shown"] is False
    assert admin_decision["alert_suppressed_reason"] == "admin_persistence_monitoring_disabled"
    assert network_decision["visible_alert_shown"] is False
    assert network_decision["alert_suppressed_reason"] == "network_activity_monitoring_disabled"
    assert manager.should_show_visible_alert(_event("launchdaemon_added", "critical"), force=True).show is False
    assert manager.evaluate_notification_decision(_event("launchdaemon_added", "critical"), force=True)["alert_suppressed_reason"] == "admin_persistence_monitoring_disabled"


def test_usb_and_bluetooth_monitoring_disabled_suppress_visible_alerts_with_reason(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.event_categories.usb_monitoring_enabled = False
    settings.event_categories.bluetooth_monitoring_enabled = False
    save_settings(db, settings)
    manager = NotificationManager(db)

    usb_decision = manager.evaluate_notification_decision(_event("new_usb_device_detected", "high"))
    bluetooth_decision = manager.evaluate_notification_decision(_event("bluetooth_device_connected", "medium"))

    assert usb_decision["visible_alert_shown"] is False
    assert usb_decision["alert_suppressed_reason"] == "usb_monitoring_disabled"
    assert bluetooth_decision["visible_alert_shown"] is False
    assert bluetooth_decision["alert_suppressed_reason"] == "bluetooth_monitoring_disabled"
    assert db.get_background_monitor_state("last_suppressed_usb_alert_reason", "") == "usb_monitoring_disabled"
    assert db.get_background_monitor_state("last_suppressed_bluetooth_alert_reason", "") == "bluetooth_monitoring_disabled"


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
    settings.settings_version = 7
    diagnostic = settings_diagnostics(
        db,
        settings,
        runtime_values={
            "notify_min_severity": settings.alerting.notify_min_severity,
            "cooldown_seconds_per_category": settings.notification.cooldown_seconds,
            "settings_version": "6",
        },
        installed_values={"system_launch_daemon_installed": False, "settings_version_installed": "5"},
    )

    assert diagnostic["status"] == "partially_applied"
    assert diagnostic["settings_reconciliation"]["status"] == "partially_applied"
    assert "system_launch_daemon_installation" in diagnostic["mismatches"]
    assert "runtime_settings_version" in diagnostic["mismatches"]
    assert "installed_settings_version" in diagnostic["mismatches"]
    assert any(item["component"] == "System Daemon Runtime" for item in diagnostic["detailed_mismatches"])


def test_monitor_settings_ui_runtime_and_notifier_agree(tmp_path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    monkeypatch.setattr(panel, "refresh", lambda: None)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.warning", lambda *args, **kwargs: None)

    panel.notify_min_severity_combo.setCurrentIndex(panel.notify_min_severity_combo.findData("critical"))
    panel.notification_mode_combo.setCurrentIndex(panel.notification_mode_combo.findData("overlay"))
    panel.persistent_local_edr_checkbox.setChecked(False)
    panel.category_checkboxes["usb"].setChecked(False)
    panel.category_checkboxes["bluetooth"].setChecked(False)
    assert "usb_unknown_device_alerts_enabled" in panel.child_category_checkboxes
    assert "bluetooth_unknown_device_alerts_enabled" in panel.child_category_checkboxes
    assert "network_suspicious_connection_alerts_enabled" in panel.child_category_checkboxes
    assert "network_localhost_visibility_alerts_enabled" in panel.child_category_checkboxes
    panel.child_category_checkboxes["usb_new_device_alerts_enabled"].setChecked(True)
    panel.child_category_checkboxes["network_vpn_alerts_enabled"].setChecked(False)
    panel.show_admin_persistence_alerts_checkbox.setChecked(False)
    panel.show_network_change_alerts_checkbox.setChecked(False)
    panel.cooldown_seconds_input.setText("42")
    panel.install_monitor_mode_combo.setCurrentIndex(panel.install_monitor_mode_combo.findData("system"))
    panel.install_run_at_load_checkbox.setChecked(False)
    panel.install_keep_alive_checkbox.setChecked(False)
    panel.install_auto_restart_checkbox.setChecked(False)
    panel.install_db_path_input.setText(str(tmp_path / "ui.sqlite"))
    panel.install_log_path_input.setText(str(tmp_path / "ui.log"))
    panel.apply_monitor_settings_from_ui()

    loaded = load_settings(db)
    manager = NotificationManager(db)
    assert loaded.alerting.notify_min_severity == "critical"
    assert loaded.notification.notification_mode == "overlay"
    assert loaded.notification.bottom_right_alerts is True
    assert loaded.local_edr.persistent_local_edr_enabled is False
    assert panel.child_category_checkboxes["network_vpn_alerts_enabled"].isEnabled() is False
    assert "Persistent Local EDR Monitor is turned off" in panel.child_category_checkboxes["network_vpn_alerts_enabled"].toolTip()
    assert loaded.event_categories.usb is False
    assert loaded.event_categories.usb_monitoring_enabled is False
    assert loaded.event_categories.bluetooth_monitoring_enabled is False
    assert loaded.event_categories.usb_new_device_alerts_enabled is True
    assert loaded.event_categories.network_vpn_alerts_enabled is False
    assert panel.child_category_checkboxes["usb_new_device_alerts_enabled"].isEnabled() is False
    assert "parent monitoring category is off" in panel.child_category_checkboxes["usb_new_device_alerts_enabled"].toolTip()
    assert loaded.installation.monitor_mode == "system"
    assert loaded.installation.run_at_load is False
    assert loaded.installation.keep_alive is False
    assert loaded.installation.auto_restart is False
    assert loaded.installation.db_path == str(tmp_path / "ui.sqlite")
    assert loaded.installation.log_path == str(tmp_path / "ui.log")
    assert loaded.event_categories.admin_persistence_monitoring_enabled is False
    assert loaded.event_categories.network_activity_monitoring_enabled is False
    assert panel.category_checkboxes["admin"].isEnabled() is False
    assert panel.category_checkboxes["persistence"].isEnabled() is False
    assert panel.category_checkboxes["network"].isEnabled() is False
    assert db.get_background_monitor_state("notify_min_severity", "") == "critical"
    assert db.get_background_monitor_state("cooldown_seconds_per_category", "") == "42"
    assert db.get_background_monitor_state("notification_mode", "") == "overlay"
    assert db.get_background_monitor_state("monitor_mode", "") == "system"
    assert db.get_background_monitor_state("installation_run_at_load", "") == "0"
    assert db.get_background_monitor_state("installation_keep_alive", "") == "0"
    assert db.get_background_monitor_state("installation_auto_restart", "") == "0"
    assert db.get_background_monitor_state("admin_persistence_monitoring_enabled", "") == "0"
    assert db.get_background_monitor_state("network_activity_monitoring_enabled", "") == "0"
    assert db.get_background_monitor_state("usb_monitoring_enabled", "") == "0"
    assert db.get_background_monitor_state("bluetooth_monitoring_enabled", "") == "0"
    assert manager.settings()["notify_min_severity"] == "critical"
    assert manager.settings()["notification_mode"] == "overlay"
    assert manager.settings()["admin_persistence_monitoring_enabled"] is False
    assert manager.settings()["network_activity_monitoring_enabled"] is False
    assert manager.preference_for("usb_device_connected")["enabled"] is False
    assert "current_settings_json" in panel.settings_diagnostics_panel.toPlainText()
    assert app is not None


def test_physical_session_settings_labels_are_clear(tmp_path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    monkeypatch.setattr(panel, "refresh", lambda: None)
    labels = {label.text() for label in panel.findChildren(QLabel)}

    assert "Physical Monitoring Settings" in labels
    assert "Physical Device Monitoring" in labels
    assert "Physical Session Monitoring" in labels
    assert "Physical Device Alert Details" in labels
    assert "Other Monitor Alert Details" in labels
    assert "Monitor USB Devices" in labels
    assert "Monitor Bluetooth Devices" in labels
    assert "Monitor lid open/close" in labels
    assert "Monitor screen lock/unlock" in labels
    assert "Monitor idle resume" in labels
    assert "Monitor input activity after idle" in labels
    assert not any("Physical/Session" in label for label in labels)
    assert not any("USB/Bluetooth" in label for label in labels)
    assert ("Blue" + "ooth") not in labels
    assert app is not None


def test_disabled_monitoring_stops_detector_loops(tmp_path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", record_startup=False)
    settings = load_settings(service.db)
    settings.event_categories.admin_persistence_monitoring_enabled = False
    settings.event_categories.network_activity_monitoring_enabled = False
    save_settings(service.db, settings)
    monkeypatch.setattr(service.network_monitor, "collect_snapshot", lambda: (_ for _ in ()).throw(AssertionError("network detector should not collect")))
    monkeypatch.setattr(service.persistence_monitor, "collect_snapshot", lambda: (_ for _ in ()).throw(AssertionError("persistence detector should not collect")))

    assert service._run_network_detector() == []
    assert service._run_persistence_detector() == []
    assert service.db.get_background_monitor_state("detector_enabled_network", "") == "0"
    assert service.db.get_background_monitor_state("detector_enabled_persistence", "") == "0"
    assert service.db.get_background_monitor_state("detector_disabled_reason:network_state_detector", "") == "Network activity monitoring disabled by settings."
    assert service.db.get_background_monitor_state("detector_disabled_reason:persistence_detector", "") == "Admin/Persistence monitoring disabled by settings."


def test_persistent_local_edr_disabled_skips_daemon_detector_loop(tmp_path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", record_startup=False)
    settings = load_settings(service.db)
    settings.local_edr.persistent_local_edr_enabled = False
    save_settings(service.db, settings)
    calls: list[str] = []
    monkeypatch.setattr(service, "_run_network_detector", lambda: calls.append("network") or [])
    monkeypatch.setattr(service, "_run_hardware_detector", lambda: calls.append("hardware") or [])

    events = service.run_once()

    assert events == []
    assert calls == []
    assert service.db.get_background_monitor_state("runtime_persistent_local_edr_enabled", "") == "0"
    assert service.db.get_background_monitor_state("persistent_local_edr_status", "") == "Disabled by settings"
    assert service.db.get_background_monitor_state("detector_enabled_network", "") == "0"


def test_usb_and_bluetooth_disabled_stop_hardware_collection(tmp_path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", record_startup=False)
    settings = load_settings(service.db)
    settings.event_categories.usb_monitoring_enabled = False
    settings.event_categories.bluetooth_monitoring_enabled = False
    save_settings(service.db, settings)
    monkeypatch.setattr(service.hardware_monitor, "collect_snapshot", lambda **_kwargs: (_ for _ in ()).throw(AssertionError("hardware detector should not collect")))

    assert service._run_hardware_detector() == []
    assert service.db.get_background_monitor_state("detector_enabled_hardware", "") == "0"
    assert service.db.get_background_monitor_state("detector_enabled_usb", "") == "0"
    assert service.db.get_background_monitor_state("detector_enabled_bluetooth", "") == "0"
    assert service.db.get_background_monitor_state("physical_device_last_usb_skip_reason", "") == "USB monitoring disabled by settings."
    assert service.db.get_background_monitor_state("physical_device_last_bluetooth_skip_reason", "") == "Bluetooth monitoring disabled by settings."


def test_usb_disabled_discards_queued_usb_observer_events(tmp_path) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", record_startup=False)
    service.usb_observer.events.put(_event("usb_device_connected", "high"))
    settings = load_settings(service.db)
    settings.event_categories.usb_monitoring_enabled = False
    save_settings(service.db, settings)

    service._update_runtime_state()

    assert service.usb_observer.drain() == []
    assert service.db.get_background_monitor_state("usb_observer_enabled", "") == "0"
    assert service.db.get_background_monitor_state("usb_observer_discarded_events", "") == "1"


def test_usb_and_bluetooth_enabled_run_hardware_collection(tmp_path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", record_startup=False)
    calls: list[dict[str, bool]] = []

    def collect_snapshot(**kwargs):
        calls.append(kwargs)
        return HardwareMonitorSnapshot(usb_devices=[], bluetooth_devices=[], nearby_bluetooth_devices=[])

    monkeypatch.setattr(service.hardware_monitor, "collect_snapshot", collect_snapshot)
    monkeypatch.setattr(service.usb_observer, "drain", lambda: [])

    assert service._run_hardware_detector() == []
    assert calls == [{"include_usb": True, "include_bluetooth": True}]
    assert service.db.get_background_monitor_state("detector_enabled_hardware", "") == "1"
    assert service.db.get_background_monitor_state("detector_enabled_usb", "") == "1"
    assert service.db.get_background_monitor_state("detector_enabled_bluetooth", "") == "1"


def test_monitor_settings_apply_syncs_usb_bluetooth_to_active_daemon_db(tmp_path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    ui_db = AuditDatabase(tmp_path / "ui.sqlite", tmp_path / "ui-logs")
    daemon_db = AuditDatabase(tmp_path / "daemon.sqlite", tmp_path / "daemon-logs")
    ui_settings = load_settings(ui_db)
    ui_settings.installation.monitor_mode = "system"
    ui_settings.installation.system_launch_daemon = True
    save_settings(ui_db, ui_settings)
    panel = BackgroundMonitorPanel(ui_db, FakeLaunchAgent(installed=True, running=False))
    monkeypatch.setattr(panel, "refresh", lambda: None)
    monkeypatch.setattr(panel, "_active_monitor_db", lambda: daemon_db)
    panel._notification_service_cache = None
    panel._notification_service_db_path = ""
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.warning", lambda *args, **kwargs: None)

    panel.category_checkboxes["usb"].setChecked(False)
    panel.category_checkboxes["bluetooth"].setChecked(False)
    panel.apply_monitor_settings_from_ui()

    assert load_settings(ui_db).event_categories.usb_monitoring_enabled is False
    assert load_settings(ui_db).event_categories.bluetooth_monitoring_enabled is False
    assert load_settings(daemon_db).event_categories.usb_monitoring_enabled is False
    assert load_settings(daemon_db).event_categories.bluetooth_monitoring_enabled is False
    assert load_settings(daemon_db).settings_version == load_settings(ui_db).settings_version
    assert daemon_db.get_background_monitor_state("usb_monitoring_enabled", "") == "0"
    assert daemon_db.get_background_monitor_state("bluetooth_monitoring_enabled", "") == "0"
    assert daemon_db.get_background_monitor_state("settings_synced_from_ui_db_path", "") == str(ui_db.path)
    assert app is not None
    assert "usb" in panel.category_checkboxes
    assert "bluetooth" in panel.category_checkboxes
    assert hasattr(panel, "show_network_change_alerts_checkbox")
    assert hasattr(panel, "show_admin_persistence_alerts_checkbox")
    assert panel.category_checkboxes["usb"].isEnabled()
    assert panel.category_checkboxes["bluetooth"].isEnabled()
