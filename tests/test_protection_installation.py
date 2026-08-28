from __future__ import annotations

import json
import plistlib
import sqlite3
from pathlib import Path

from mac_audit_agent.protection.__main__ import main
from mac_audit_agent.protection.components import active_protection_components
from mac_audit_agent.protection.installer import ActiveProtectionInstallOptions, install_active_protection
from mac_audit_agent.protection.repair import ActiveProtectionRepairOptions, repair_active_protection
from mac_audit_agent.protection.status import resolve_active_protection_status


def test_component_inventory_is_concrete() -> None:
    components = {item.component_id: item for item in active_protection_components()}
    assert set(components) == {"system_daemon", "development_ransomware_observer", "user_notifier", "service_watchdog", "sensor_health_manager", "system_runtime", "user_runtime", "active_db", "runtime_manifest"}
    assert components["system_daemon"].launchd_label == "com.mac-audit-agent.monitor"
    assert components["user_notifier"].launchd_label == "com.mac-audit-agent.user-notifier"
    assert components["development_ransomware_observer"].launchd_label == "com.mac-audit-agent.monitor"
    assert "not Endpoint Security parity" in components["development_ransomware_observer"].purpose
    assert all(item.repair_actions or item.runtime_path for item in components.values())


def test_isolated_install_generates_daemon_notifier_db_and_manifest(tmp_path: Path) -> None:
    result = install_active_protection(ActiveProtectionInstallOptions(test_root=tmp_path))
    assert result.status == "test_root_verified"
    daemon = tmp_path / "Library/LaunchDaemons/com.mac-audit-agent.monitor.plist"
    notifier = tmp_path / "Users/tester/Library/LaunchAgents/com.mac-audit-agent.user-notifier.plist"
    watchdog = tmp_path / "Library/LaunchDaemons/com.mac-audit-agent.service-watchdog.plist"
    sensor_health = tmp_path / "Library/LaunchDaemons/com.mac-audit-agent.sensor-health.plist"
    database = tmp_path / "Library/Application Support/MacAuditAgent/mac_audit_agent.sqlite3"
    manifest = tmp_path / "Library/Application Support/MacAuditAgent/runtime/install_manifest.json"
    assert plistlib.loads(daemon.read_bytes())["Label"] == "com.mac-audit-agent.monitor"
    assert plistlib.loads(notifier.read_bytes())["Label"] == "com.mac-audit-agent.user-notifier"
    assert plistlib.loads(watchdog.read_bytes())["Label"] == "com.mac-audit-agent.service-watchdog"
    assert plistlib.loads(sensor_health.read_bytes())["Label"] == "com.mac-audit-agent.sensor-health"
    assert json.loads(manifest.read_text())["db_path"] == str(database)
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT value FROM background_monitor_state WHERE key='protection_mode'").fetchone()[0] == "protected"


def test_isolated_repair_is_idempotent_and_preserves_database(tmp_path: Path) -> None:
    install_active_protection(ActiveProtectionInstallOptions(test_root=tmp_path))
    database = tmp_path / "Library/Application Support/MacAuditAgent/mac_audit_agent.sqlite3"
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT OR REPLACE INTO background_monitor_state VALUES('preserved_event','yes')")
    first = repair_active_protection(ActiveProtectionRepairOptions(test_root=tmp_path))
    second = repair_active_protection(ActiveProtectionRepairOptions(test_root=tmp_path))
    assert first.status == second.status == "test_root_verified"
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT value FROM background_monitor_state WHERE key='preserved_event'").fetchone()[0] == "yes"


def test_live_status_resolver_is_structured_and_actionable() -> None:
    status = resolve_active_protection_status()
    assert status.status in {"installed_running", "partially_installed", "not_installed", "degraded", "failed", "unknown"}
    assert status.system_daemon["label"] == "com.mac-audit-agent.monitor"
    assert status.user_notifier["label"] == "com.mac-audit-agent.user-notifier"
    assert status.recommended_primary_action
    assert status.recommended_command
    assert status.evidence["historical_logs_are_authoritative"] is False


def test_test_root_cli_install_is_headless_and_verifies(tmp_path: Path, capsys) -> None:
    code = main(["install", "--mode", "protected", "--with-system-daemon", "--with-user-notifier", "--apply-current-settings", "--verify", "--test-root", str(tmp_path)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["status"] == "test_root_verified"
    assert payload["verification"]["live_launchctl_not_claimed"] is True
