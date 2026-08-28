from __future__ import annotations

import json

from mac_audit_agent.monitor_settings import load_settings, settings_diagnostics
from mac_audit_agent.settings.settings_reconciliation import reconcile_settings
from mac_audit_agent.settings.settings_sync import repair_settings_sync
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.user_notifier_installer import UserNotifierStatus
from mac_audit_agent.user_notifier_status import status_to_runtime_values


def test_settings_reconciliation_detects_runtime_manifest_and_notifier_stale(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.settings_version = 65

    result = reconcile_settings(
        settings,
        runtime_values={"settings_version": "39", "daemon_settings_version": "39", "notifier_settings_version": "39"},
        installed_values={"settings_version_installed": "40"},
    )

    assert result.status == "partially_applied"
    assert set(result.stale_components) == {"runtime", "notifier", "installed_manifest"}
    assert result.requires_daemon_restart is True
    assert result.requires_notifier_restart is True
    assert any(item.component == "System Daemon Runtime" and item.expected == 65 and item.observed == 39 for item in result.mismatches)
    assert "Apply Settings to Runtime" in result.repair_actions


def test_settings_reconciliation_labels_manifest_only_stale_as_safe_for_manual_testing(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.settings_version = 7

    result = reconcile_settings(
        settings,
        runtime_values={"settings_version": "7", "notifier_settings_version": "7"},
        installed_values={"settings_version_installed": "5"},
    )

    assert result.status == "installed_manifest_stale"
    assert not hasattr(result, "safe_to_manual_test")
    assert result.requires_reinstall is True


def test_settings_diagnostics_keeps_stale_installed_notifier_state_historical(tmp_path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    settings = load_settings(db)
    settings.settings_version = 10
    live_status = UserNotifierStatus(
        install_status="loaded_running",
        loaded=True,
        running=True,
        process_pid=123,
        plist_path="/tmp/notifier.plist",
        launchctl_domain="gui/501",
    )

    diagnostics = settings_diagnostics(
        db,
        settings,
        runtime_values={
            "settings_version": "10",
            "notifier_settings_version": "10",
            **status_to_runtime_values(live_status),
        },
        installed_values={"settings_version_installed": "10", "user_notifier_running": "0", "user_notifier_install_status": "unknown"},
    )

    assert diagnostics["user_alert_agent"]["running"] is True
    assert diagnostics["user_alert_agent"]["deliverable"] is False
    assert diagnostics["user_alert_agent"]["deliverability_predicates"]["current_diagnostic_event_received"] is False
    assert diagnostics["user_alert_agent"]["status"] == "loaded"
    assert diagnostics["historical_installed_state"]["user_notifier_running"] == "0"
    assert diagnostics["settings_reconciliation"]["status"] == "synced"


def test_repair_settings_sync_updates_runtime_and_manifest_without_bumping_version(tmp_path) -> None:
    ui_db = AuditDatabase(tmp_path / "ui.sqlite", tmp_path / "logs")
    runtime_db_path = tmp_path / "runtime.sqlite"
    runtime_db = AuditDatabase(runtime_db_path, tmp_path / "runtime-logs")
    settings = load_settings(ui_db)
    settings.settings_version = 42
    ui_db.set_background_monitor_state("monitor_settings_json", json.dumps(settings.to_dict(), sort_keys=True))
    runtime_db.set_background_monitor_state("settings_version", "5")
    runtime_db.set_background_monitor_state("installed_settings_version", "5")

    result = repair_settings_sync(ui_db, active_db_path=runtime_db_path)

    assert result.status == "repaired"
    assert result.settings_version == 42
    assert load_settings(runtime_db).settings_version == 42
    assert runtime_db.get_background_monitor_state("settings_version", "") == "42"
    assert runtime_db.get_background_monitor_state("installed_settings_version", "") == "42"
