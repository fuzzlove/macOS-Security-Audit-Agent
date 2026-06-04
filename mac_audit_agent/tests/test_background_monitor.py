import os
import json
import plistlib
import sys
import subprocess
from pathlib import Path
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QMessageBox

from mac_audit_agent.launch_agent import (
    LAUNCH_AGENT_LABEL,
    LAUNCHCTL_BIN,
    LOG_BIN,
    PLUTIL_BIN,
    LaunchAgentManager,
    build_launch_agent_plist,
    default_launch_agent_paths,
    launchctl_target,
    project_root,
    default_monitor_db_path,
    monitor_log_root,
    protected_monitor_manifest_path,
    runtime_monitor_script_path,
    runtime_package_root,
    runtime_root,
    user_home_dir,
    user_launchctl_uid,
    verify_protected_monitor_integrity,
)
from mac_audit_agent.hardware_monitor import HardwareMonitor, HardwareMonitorSnapshot, USBReconnectObserver
from mac_audit_agent.models import BackgroundMonitorEvent, EventAlertTrace, Finding, ScanResult, ScanSummary, utc_now_iso
from mac_audit_agent.monitor import FALLBACK_MONITOR_LOG, BackgroundMonitorService, STDERR_MONITOR_LOG, clear_monitor_log_files, is_heartbeat_fresh, is_pid_alive, main as monitor_main
from mac_audit_agent.monitor import _resolve_monitor_db_path
from mac_audit_agent.persistence_monitor import PersistenceMonitor, PersistenceSnapshot
from mac_audit_agent.network_monitor import NetworkMonitor, NetworkMonitorSnapshot
from mac_audit_agent.native_event_bridge import NativeEventBridge, NativeEventFrame, native_event_frame_to_event, normalize_native_event_type
from mac_audit_agent.notification_manager import NotificationManager, applescript_escape, send_alert_dialog, send_notification
from mac_audit_agent.privacy_monitor import PrivacyMonitor, PrivacyMonitorSnapshot
from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json
from mac_audit_agent.session_monitor import SessionMonitor, SessionSnapshot, SessionStateObserver
from mac_audit_agent.self_impact_watchdog import MonitorSelfImpactWatchdog, SelfImpactMetrics
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.system_monitor_readiness import (
    DEPLOYMENT_EVENT_FLOW_EVENT_TYPE,
    SystemMonitorReadiness,
    process_deployment_event_flow_request,
)
from mac_audit_agent.rules import canonical_event_type, sanitize_signal_text
from mac_audit_agent.ui.background_monitor_panel import BackgroundMonitorPanel
from mac_audit_agent.workflow_layer import InvestigatorWorkflowLayer


class FakeCompletedProcess:
    def __init__(self, returncode=0, stdout="", stderr="") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakePopenProcess:
    def __init__(self, returncode=None) -> None:
        self.returncode = returncode

    def poll(self):
        return self.returncode


class FakeLaunchAgent:
    def __init__(self, installed: bool, running: bool) -> None:
        self._installed = installed
        self._running = running
        self.plist_path = "/tmp/com.mac-audit-agent.monitor.plist"
        self.log_path = "/tmp/background_monitor.stdout.log"

    def status(self):
        return type(
            "Status",
            (),
            {
                "installed": self._installed,
                "loaded": self._running,
                "running": self._running,
                "enabled": self._installed,
                "plist_path": self.plist_path,
                "label": LAUNCH_AGENT_LABEL,
                "log_path": self.log_path,
                "db_path": "/tmp/test.sqlite",
                "process_pid": 123,
                "last_heartbeat": "2026-04-24T12:00:00Z",
                "last_event_timestamp": "2026-04-24T12:01:00Z",
                "last_error": "",
                "notification_status": "available via macOS user notification",
                "current_launchctl_domain": launchctl_target(),
            },
        )()

    def install(self):
        self._installed = True
        return Path(self.plist_path)

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    def uninstall(self):
        self._installed = False

    def show_logs(self):
        return self.log_path


def _monitor_status(**overrides):
    defaults = {
        "installed": True,
        "loaded": True,
        "running": True,
        "enabled": True,
        "plist_path": "/tmp/com.mac-audit-agent.monitor.plist",
        "label": LAUNCH_AGENT_LABEL,
        "log_path": "/tmp/background_monitor.stdout.log",
        "db_path": "/tmp/test.sqlite",
        "process_pid": os.getpid(),
        "last_heartbeat": utc_now_iso(),
        "last_event_timestamp": "",
        "last_error": "",
        "notification_status": "available",
        "current_launchctl_domain": "system",
    }
    defaults.update(overrides)
    return type("Status", (), defaults)()


def test_launch_agent_plist_generated_correctly(tmp_path: Path) -> None:
    payload = build_launch_agent_plist(db_path=tmp_path / "audit.sqlite", poll_interval_seconds=30, python_executable="/usr/bin/python3")
    assert payload["Label"] == LAUNCH_AGENT_LABEL
    assert payload["ProgramArguments"] == ["/usr/bin/python3", str(runtime_monitor_script_path()), "--run"]
    assert payload["RunAtLoad"] is True
    assert payload["KeepAlive"] is True
    assert payload["WorkingDirectory"] == str(runtime_root())
    assert "PYTHONPATH" not in payload["EnvironmentVariables"]
    assert payload["EnvironmentVariables"]["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin"
    assert payload["StandardOutPath"].endswith("background_monitor.stdout.log")
    assert payload["StandardErrorPath"].endswith("background_monitor.stderr.log")
    plistlib.dumps(payload)


def test_launch_daemon_plist_generated_correctly(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_RUNTIME_ROOT", tmp_path / "system-runtime")
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_LOG_ROOT", tmp_path / "system-logs")
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_DB_PATH", tmp_path / "system.sqlite3")
    payload = build_launch_agent_plist(db_path=tmp_path / "system.sqlite3", poll_interval_seconds=30, python_executable="/usr/bin/python3", scope="system")
    assert payload["Label"] == LAUNCH_AGENT_LABEL
    assert payload["ProgramArguments"] == ["/usr/bin/python3", str(tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py"), "--run"]
    assert "ProcessType" not in payload
    assert payload["WorkingDirectory"] == str(tmp_path / "system-runtime")
    assert payload["EnvironmentVariables"]["MAC_AUDIT_AGENT_LAUNCH_SCOPE"] == "system"
    assert payload["EnvironmentVariables"]["MAC_AUDIT_AGENT_RUNTIME_ROOT"] == str(tmp_path / "system-runtime")
    assert payload["EnvironmentVariables"]["MAC_AUDIT_AGENT_LOG_ROOT"] == str(tmp_path / "system-logs")
    assert payload["EnvironmentVariables"]["MAC_AUDIT_AGENT_DB_PATH"] == str(tmp_path / "system.sqlite3")
    assert payload["StandardOutPath"].startswith(str(tmp_path / "system-logs"))
    assert payload["StandardErrorPath"].startswith(str(tmp_path / "system-logs"))
    assert launchctl_target("system") == "system"
    assert default_monitor_db_path("system") == tmp_path / "system.sqlite3"
    assert monitor_log_root("system") == tmp_path / "system-logs"
    assert default_launch_agent_paths("system").plist_path.parent == Path("/Library/LaunchDaemons")


def test_system_monitor_plist_generated_with_system_mode(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_RUNTIME_ROOT", tmp_path / "system-runtime")
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_LOG_ROOT", tmp_path / "system-logs")
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_DB_PATH", tmp_path / "system.sqlite3")
    payload = build_launch_agent_plist(
        db_path=tmp_path / "system.sqlite3",
        poll_interval_seconds=30,
        python_executable="/usr/bin/python3",
        scope="system",
        mode="system-daemon",
    )
    assert payload["ProgramArguments"] == [
        "/usr/bin/python3",
        str(tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py"),
        "--run",
        "--mode",
        "system-daemon",
    ]
    assert payload["EnvironmentVariables"]["MAC_AUDIT_AGENT_MONITOR_ROLE"] == "system-daemon"
    assert payload["EnvironmentVariables"]["MAC_AUDIT_AGENT_LAUNCH_SCOPE"] == "system"


def test_system_monitor_install_uses_shared_system_db_even_if_manager_was_created_with_user_db(tmp_path: Path, monkeypatch) -> None:
    system_db = tmp_path / "Application Support" / "MacAuditAgent" / "mac_audit_agent.sqlite3"
    system_plist = tmp_path / "LaunchDaemons" / f"{LAUNCH_AGENT_LABEL}.plist"
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_RUNTIME_ROOT", tmp_path / "system-runtime")
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_LOG_ROOT", tmp_path / "system-logs")
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_DB_PATH", system_db)
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_LAUNCH_DAEMON_PATH", system_plist)
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.geteuid", lambda: 0)
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.chown", lambda *_args, **_kwargs: None)
    manager = LaunchAgentManager(tmp_path / "user.sqlite3", scope="system", runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0, stdout="OK"))
    manager.paths = type(manager.paths)(
        plist_path=system_plist,
        stdout_path=tmp_path / "system-logs" / "background_monitor.stdout.log",
        stderr_path=tmp_path / "system-logs" / "background_monitor.stderr.log",
    )

    plist_path = manager.install_system_monitor()

    payload = plistlib.loads(plist_path.read_bytes())
    assert payload["EnvironmentVariables"]["MAC_AUDIT_AGENT_DB_PATH"] == str(system_db)
    manifest = json.loads(protected_monitor_manifest_path("system").read_text(encoding="utf-8"))
    assert manifest["db_path"] == str(system_db)
    assert manifest["hash_algorithm"] == "sha256+sha512"
    assert manifest["manifest_digest_algorithm"] == "sha512"
    assert "manifest_digest_sha512" in manifest
    assert "sha512" in manifest["tracked_files"]["monitor.py"]


def test_canonical_event_type_maps_alert_aliases() -> None:
    assert canonical_event_type("session_locked") == "screen_locked"
    assert canonical_event_type("session_unlocked") == "screen_unlocked"
    assert canonical_event_type("possible_lid_opened") == "lid_opened"
    assert canonical_event_type("mouse_activity_detected") == "mouse_or_keyboard_activity_after_idle"
    assert canonical_event_type("input_activity_after_idle") == "mouse_or_keyboard_activity_after_idle"
    assert canonical_event_type("hid_activity_after_idle") == "mouse_or_keyboard_activity_after_idle"
    assert canonical_event_type("current_usb_device_inventory_changed") == "usb_device_connected"


def test_system_daemon_mode_without_explicit_db_path_resolves_shared_system_db(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_DB_PATH", tmp_path / "system.sqlite3")
    monkeypatch.setattr("mac_audit_agent.monitor.SYSTEM_DB_PATH", tmp_path / "system.sqlite3", raising=False)
    assert _resolve_monitor_db_path(None, "system-daemon") == tmp_path / "system.sqlite3"


def _patch_readiness_system_paths(tmp_path: Path, monkeypatch):
    system_db = tmp_path / "Application Support" / "MacAuditAgent" / "mac_audit_agent.sqlite3"
    runtime = tmp_path / "Application Support" / "MacAuditAgent" / "runtime"
    logs = tmp_path / "Logs" / "MacAuditAgent"
    plist = tmp_path / "LaunchDaemons" / f"{LAUNCH_AGENT_LABEL}.plist"
    paths = type(
        "Paths",
        (),
        {
            "plist_path": plist,
            "stdout_path": logs / "background_monitor.stdout.log",
            "stderr_path": logs / "background_monitor.stderr.log",
        },
    )()
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_DB_PATH", system_db)
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_RUNTIME_ROOT", runtime)
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_LOG_ROOT", logs)
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_LAUNCH_DAEMON_PATH", plist)
    monkeypatch.setattr("mac_audit_agent.launch_agent.default_launch_agent_paths", lambda scope=None: paths if scope == "system" else paths)
    monkeypatch.setattr("mac_audit_agent.system_monitor_readiness.system_monitor_location_status", lambda _paths=None: {"valid": True, "expected_plist_path": str(plist), "observed_plist_path": str(plist), "message": "ok"})
    return system_db, runtime, logs, plist, paths


def test_runtime_version_mismatch_detected(tmp_path: Path, monkeypatch) -> None:
    system_db, runtime, logs, plist, _paths = _patch_readiness_system_paths(tmp_path, monkeypatch)
    runtime.mkdir(parents=True)
    logs.mkdir(parents=True)
    plist.parent.mkdir(parents=True)
    plist.write_bytes(plistlib.dumps(build_launch_agent_plist(db_path=system_db, scope="system", mode="system-daemon")))
    AuditDatabase(system_db).record_monitor_heartbeat(utc_now_iso())
    manifest_path = protected_monitor_manifest_path("system")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps({"runtime_version": "old-version", "db_path": str(system_db)}), encoding="utf-8")
    readiness = SystemMonitorReadiness(system_db, runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0))
    monkeypatch.setattr(readiness.system_manager, "status", lambda: _monitor_status(plist_path=str(plist), db_path=str(system_db)))

    report = readiness.audit_deployment()

    version_check = next(check for check in report.checks if check.check_id == "runtime_version")
    assert version_check.status == "WARNING"
    assert "Repair System Monitor runtime" in report.repair_actions


def test_deployment_audit_finds_old_db_path(tmp_path: Path, monkeypatch) -> None:
    system_db, runtime, logs, plist, _paths = _patch_readiness_system_paths(tmp_path, monkeypatch)
    runtime.mkdir(parents=True)
    logs.mkdir(parents=True)
    plist.parent.mkdir(parents=True)
    old_db = tmp_path / "old-user.sqlite3"
    plist.write_bytes(plistlib.dumps(build_launch_agent_plist(db_path=old_db, scope="system", mode="system-daemon")))
    AuditDatabase(system_db).record_monitor_heartbeat(utc_now_iso())
    readiness = SystemMonitorReadiness(system_db, runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0))
    monkeypatch.setattr(readiness.system_manager, "status", lambda: _monitor_status(plist_path=str(plist), db_path=str(system_db)))

    report = readiness.audit_deployment()

    db_check = next(check for check in report.checks if check.check_id == "database_path")
    assert db_check.status == "FAIL"
    assert str(old_db) in db_check.observed


def test_deployment_audit_finds_missing_runtime(tmp_path: Path, monkeypatch) -> None:
    system_db, _runtime, logs, plist, _paths = _patch_readiness_system_paths(tmp_path, monkeypatch)
    logs.mkdir(parents=True)
    plist.parent.mkdir(parents=True)
    plist.write_bytes(plistlib.dumps(build_launch_agent_plist(db_path=system_db, scope="system", mode="system-daemon")))
    readiness = SystemMonitorReadiness(system_db, runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0))
    monkeypatch.setattr(readiness.system_manager, "status", lambda: _monitor_status(plist_path=str(plist), db_path=str(system_db)))

    report = readiness.audit_deployment()

    runtime_check = next(check for check in report.checks if check.check_id == "runtime_exists")
    assert runtime_check.status == "FAIL"
    assert report.deployment_state == "Broken"


def test_deployment_audit_finds_invalid_permissions(tmp_path: Path, monkeypatch) -> None:
    system_db, runtime, logs, plist, _paths = _patch_readiness_system_paths(tmp_path, monkeypatch)
    runtime.mkdir(parents=True)
    logs.mkdir(parents=True)
    plist.parent.mkdir(parents=True)
    plist.write_bytes(plistlib.dumps(build_launch_agent_plist(db_path=system_db, scope="system", mode="system-daemon")))
    readiness = SystemMonitorReadiness(system_db, runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0))
    monkeypatch.setattr(readiness.system_manager, "status", lambda: _monitor_status(plist_path=str(plist), db_path=str(system_db)))

    report = readiness.audit_deployment()

    permission_check = next(check for check in report.checks if check.check_id == "launchdaemon_permissions")
    assert permission_check.status == "FAIL"


def test_deployment_repair_updates_runtime_manifest_and_db_path(tmp_path: Path, monkeypatch) -> None:
    system_db, runtime, logs, plist, _paths = _patch_readiness_system_paths(tmp_path, monkeypatch)
    runtime.mkdir(parents=True)
    logs.mkdir(parents=True)
    plist.parent.mkdir(parents=True)
    plist.write_bytes(plistlib.dumps(build_launch_agent_plist(db_path=tmp_path / "old.sqlite3", scope="system", mode="system-daemon")))
    readiness = SystemMonitorReadiness(system_db, runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0))
    monkeypatch.setattr("mac_audit_agent.system_monitor_readiness.os.geteuid", lambda: 0)
    calls = []

    def fake_install():
        calls.append("install")
        plist.write_bytes(plistlib.dumps(build_launch_agent_plist(db_path=system_db, scope="system", mode="system-daemon")))
        manifest_path = protected_monitor_manifest_path("system")
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps({"runtime_version": readiness.application_manifest()["runtime_version"], "db_path": str(system_db)}), encoding="utf-8")
        return plist

    monkeypatch.setattr(readiness.system_manager, "install_system_monitor", fake_install)
    monkeypatch.setattr(readiness.system_manager, "status", lambda: _monitor_status(plist_path=str(plist), db_path=str(system_db)))
    monkeypatch.setattr(readiness.system_manager, "start", lambda: calls.append("start"))
    monkeypatch.setattr(readiness.user_notifier_manager, "status", lambda: _monitor_status(installed=True))
    report = readiness.audit_deployment()

    notes = readiness.repair_mismatches(report)

    assert "install" in calls
    assert "start" in calls
    assert any("repaired system monitor" in note for note in notes)
    payload = plistlib.loads(plist.read_bytes())
    assert payload["EnvironmentVariables"]["MAC_AUDIT_AGENT_DB_PATH"] == str(system_db)
    assert json.loads(protected_monitor_manifest_path("system").read_text(encoding="utf-8"))["db_path"] == str(system_db)


def test_event_flow_verification_works(tmp_path: Path, monkeypatch) -> None:
    system_db, _runtime, _logs, _plist, _paths = _patch_readiness_system_paths(tmp_path, monkeypatch)
    AuditDatabase(system_db)
    readiness = SystemMonitorReadiness(system_db, runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0))
    monkeypatch.setattr(readiness.system_manager, "status", lambda: _monitor_status(db_path=str(system_db)))
    monkeypatch.setattr(readiness.user_notifier_manager, "status", lambda: _monitor_status(installed=True, loaded=True))
    original_request = readiness.request_event_flow_test

    def request_and_process():
        request_id = original_request()
        process_deployment_event_flow_request(AuditDatabase(system_db))
        return request_id

    monkeypatch.setattr(readiness, "request_event_flow_test", request_and_process)
    result = readiness.verify_event_flow(timeout_seconds=1)

    assert all(stage.status == "PASS" for stage in result.stages if stage.check_id != "notifier_receives_event")
    assert AuditDatabase(system_db).recent_background_monitor_events(limit=1, event_type=DEPLOYMENT_EVENT_FLOW_EVENT_TYPE)


def test_heartbeat_verification_and_health_score_generated(tmp_path: Path, monkeypatch) -> None:
    system_db, runtime, logs, plist, _paths = _patch_readiness_system_paths(tmp_path, monkeypatch)
    runtime.mkdir(parents=True)
    logs.mkdir(parents=True)
    plist.parent.mkdir(parents=True)
    plist.write_bytes(plistlib.dumps(build_launch_agent_plist(db_path=system_db, scope="system", mode="system-daemon")))
    AuditDatabase(system_db).record_monitor_heartbeat(utc_now_iso())
    readiness = SystemMonitorReadiness(system_db, runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0))
    monkeypatch.setattr(readiness.system_manager, "status", lambda: _monitor_status(plist_path=str(plist), db_path=str(system_db)))

    report = readiness.audit_deployment()

    heartbeat = next(check for check in report.checks if check.check_id == "heartbeat_fresh")
    assert heartbeat.status == "PASS"
    assert 0 <= report.health_score <= 100


def test_audit_does_not_automatically_repair(tmp_path: Path, monkeypatch) -> None:
    system_db, _runtime, _logs, _plist, _paths = _patch_readiness_system_paths(tmp_path, monkeypatch)
    readiness = SystemMonitorReadiness(system_db, runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0))
    calls = []
    monkeypatch.setattr(readiness.system_manager, "install_system_monitor", lambda: calls.append("install"))
    monkeypatch.setattr(readiness.system_manager, "start", lambda: calls.append("start"))

    report = readiness.audit_deployment()

    assert report.deployment_state in {"Broken", "Repair Recommended"}
    assert calls == []


def test_user_notifier_plist_generated_with_user_mode(tmp_path: Path) -> None:
    payload = build_launch_agent_plist(
        db_path=tmp_path / "audit.sqlite",
        poll_interval_seconds=30,
        python_executable="/usr/bin/python3",
        scope="user",
        mode="user-notifier",
    )
    assert payload["ProgramArguments"][-2:] == ["--mode", "user-notifier"]
    assert payload["EnvironmentVariables"]["MAC_AUDIT_AGENT_MONITOR_ROLE"] == "user-notifier"


def test_system_monitor_install_requires_admin_approval(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.geteuid", lambda: 501)
    manager = LaunchAgentManager(tmp_path / "audit.sqlite", scope="system", runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0, stdout="OK"))
    with pytest.raises(RuntimeError, match="requires root privileges"):
        manager.install_system_monitor()


def test_system_daemon_does_not_call_applescript_directly(tmp_path: Path) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", mode="system-daemon")
    assert service.notifications.status().startswith("system daemon")
    event = service.run_self_test()
    assert event.event_type == "monitor_self_test"
    assert service.db.latest_monitor_events(limit=1)[0].event_type == "monitor_self_test"
    assert service.db.latest_monitor_heartbeat()


def test_user_notifier_processes_pending_events(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", mode="user-notifier")
    event = BackgroundMonitorEvent(
        event_id="pending-1",
        timestamp="2026-04-25T00:00:00+00:00",
        event_type="launchdaemon_added",
        severity="critical",
        source="baseline_diff",
        evidence="New LaunchDaemon detected: com.example.daemon",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    service.db.record_monitor_event(event, dedupe_window_seconds=0)
    calls = []
    monkeypatch.setattr(service.notifications, "notify", lambda item, force=False: calls.append(item.event_type) or (True, ""))
    notified = service.process_pending_notifications()
    assert calls == ["launchdaemon_added"]
    assert [item.event_type for item in notified] == ["launchdaemon_added"]


def test_user_mode_remains_default() -> None:
    manager = LaunchAgentManager(Path("/tmp/audit.sqlite"))
    assert manager.scope == "user"
    assert manager.paths.plist_path.parent == Path.home() / "Library" / "LaunchAgents"


def test_user_launchctl_target_uses_sudo_uid_instead_of_gui_zero(monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.getuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "501")
    assert user_launchctl_uid() == 501
    assert launchctl_target("user") == "gui/501"


def test_explicit_user_scope_is_not_overridden_by_system_environment(monkeypatch) -> None:
    monkeypatch.setenv("MAC_AUDIT_AGENT_LAUNCH_SCOPE", "system")
    assert launchctl_target() == "system"
    assert launchctl_target("user") == f"gui/{user_launchctl_uid()}"
    assert default_launch_agent_paths("user").plist_path.parent == user_home_dir() / "Library" / "LaunchAgents"
    payload = build_launch_agent_plist(db_path=Path("/tmp/audit.sqlite"), scope="user", mode="user-notifier")
    assert payload["WorkingDirectory"] == str(user_home_dir() / ".mac_audit_agent" / "runtime")
    assert payload["ProgramArguments"][1] == str(user_home_dir() / ".mac_audit_agent" / "runtime" / "mac_audit_agent" / "monitor.py")
    assert payload["EnvironmentVariables"]["MAC_AUDIT_AGENT_LAUNCH_SCOPE"] == "user"


def test_user_paths_use_sudo_invoking_user_home_instead_of_root_home(tmp_path: Path, monkeypatch) -> None:
    invoking_home = tmp_path / "Users" / "admin"
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.getuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setattr(
        "mac_audit_agent.launch_agent.pwd.getpwuid",
        lambda uid: type("User", (), {"pw_uid": uid, "pw_name": "admin", "pw_dir": str(invoking_home)})(),
    )
    assert user_home_dir() == invoking_home
    assert default_launch_agent_paths("user").plist_path == invoking_home / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist"
    assert runtime_root("user") == invoking_home / ".mac_audit_agent" / "runtime"


def test_launch_agent_stop_tolerates_domain_does_not_support_action(tmp_path: Path) -> None:
    calls = []

    def fake_runner(command, capture_output=True, text=True):
        calls.append(command)
        return FakeCompletedProcess(returncode=125, stderr="Boot-out failed: 125: Domain does not support specified action")

    manager = LaunchAgentManager(tmp_path / "audit.sqlite", runner=fake_runner)
    manager.paths = type(manager.paths)(
        plist_path=tmp_path / "com.mac-audit-agent.monitor.plist",
        stdout_path=tmp_path / "background_monitor.stdout.log",
        stderr_path=tmp_path / "background_monitor.stderr.log",
    )
    manager.stop()
    assert calls == [[LAUNCHCTL_BIN, "bootout", launchctl_target(), str(manager.paths.plist_path)]]


def test_protected_monitor_tamper_rule_is_registered() -> None:
    from mac_audit_agent.rules import rule_for_event

    rule = rule_for_event("protected_monitor_tamper_detected")
    assert rule.rule_id == "protected_monitor_tamper_detected"
    assert rule.severity == "critical"
    assert rule.source_detector == "integrity_check"


def test_protected_mode_requires_admin_approval(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.geteuid", lambda: 501)
    manager = LaunchAgentManager(tmp_path / "audit.sqlite", scope="system", runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0, stdout="OK"))
    with pytest.raises(RuntimeError, match="requires root privileges"):
        manager.install_protected_mode()


def test_protected_monitor_integrity_detects_owner_mode_and_hash_changes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.geteuid", lambda: 0)
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.chown", lambda *args, **kwargs: None)
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_root", lambda scope=None: tmp_path / "system-runtime")
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_package_root", lambda scope=None: tmp_path / "system-runtime" / "mac_audit_agent")
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_monitor_script_path", lambda scope=None: tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py")
    monkeypatch.setattr("mac_audit_agent.launch_agent.monitor_log_root", lambda scope=None: tmp_path / "system-logs")
    monkeypatch.setattr("mac_audit_agent.launch_agent.default_monitor_db_path", lambda scope=None: tmp_path / "system.sqlite3")

    source_pkg = tmp_path / "source" / "mac_audit_agent"
    source_pkg.mkdir(parents=True, exist_ok=True)
    (source_pkg / "__init__.py").write_text("", encoding="utf-8")
    (source_pkg / "monitor.py").write_text("print('ok')\n", encoding="utf-8")
    manager = LaunchAgentManager(tmp_path / "audit.sqlite", runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0, stdout="OK"), scope="system")
    manager._runtime_root = lambda: tmp_path / "system-runtime"
    manager._runtime_package_root = lambda: tmp_path / "system-runtime" / "mac_audit_agent"
    manager._runtime_monitor_script_path = lambda: tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py"
    manager.paths = type(manager.paths)(
        plist_path=tmp_path / "Library" / "LaunchDaemons" / f"{LAUNCH_AGENT_LABEL}.plist",
        stdout_path=tmp_path / "system-logs" / "background_monitor.stdout.log",
        stderr_path=tmp_path / "system-logs" / "background_monitor.stderr.log",
    )
    manager.paths.plist_path.parent.mkdir(parents=True, exist_ok=True)
    manager.paths.stdout_path.parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "system-runtime" / "mac_audit_agent").mkdir(parents=True, exist_ok=True)
    (tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py").write_text("print('ok')\n", encoding="utf-8")
    monkeypatch.setattr("mac_audit_agent.launch_agent.default_launch_agent_paths", lambda scope=None: manager.paths)
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_LAUNCH_DAEMON_PATH", manager.paths.plist_path)
    manager.install_protected_mode()
    manifest_path = protected_monitor_manifest_path("system")
    assert manifest_path.exists()

    original_stat = Path.stat

    class FakeBadStat:
        st_uid = 501
        st_gid = 20
        st_mode = 0o100666

    monkeypatch.setattr("pathlib.Path.stat", lambda self: FakeBadStat() if self == manager.paths.plist_path else original_stat(self))
    integrity = verify_protected_monitor_integrity(scope="system")
    assert integrity["tamper_detected"] is True
    assert any("owner mismatch" in item or "world writable" in item for item in integrity["evidence"])

    (tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py").write_text("print('changed')\n", encoding="utf-8")
    monkeypatch.setattr("pathlib.Path.stat", original_stat)
    integrity = verify_protected_monitor_integrity(scope="system")
    assert integrity["tamper_detected"] is True
    assert any("hash changed" in item for item in integrity["evidence"])


def test_protected_monitor_integrity_detects_manifest_digest_tampering(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.geteuid", lambda: 0)
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.chown", lambda *args, **kwargs: None)
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_root", lambda scope=None: tmp_path / "system-runtime")
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_package_root", lambda scope=None: tmp_path / "system-runtime" / "mac_audit_agent")
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_monitor_script_path", lambda scope=None: tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py")
    monkeypatch.setattr("mac_audit_agent.launch_agent.monitor_log_root", lambda scope=None: tmp_path / "system-logs")
    monkeypatch.setattr("mac_audit_agent.launch_agent.default_monitor_db_path", lambda scope=None: tmp_path / "system.sqlite3")

    source_pkg = tmp_path / "source" / "mac_audit_agent"
    source_pkg.mkdir(parents=True, exist_ok=True)
    (source_pkg / "__init__.py").write_text("", encoding="utf-8")
    (source_pkg / "monitor.py").write_text("print('ok')\n", encoding="utf-8")

    manager = LaunchAgentManager(tmp_path / "audit.sqlite", runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0, stdout="OK"), scope="system")
    manager._runtime_root = lambda: tmp_path / "system-runtime"
    manager._runtime_package_root = lambda: tmp_path / "system-runtime" / "mac_audit_agent"
    manager._runtime_monitor_script_path = lambda: tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py"
    manager.paths = type(manager.paths)(
        plist_path=tmp_path / "Library" / "LaunchDaemons" / f"{LAUNCH_AGENT_LABEL}.plist",
        stdout_path=tmp_path / "system-logs" / "background_monitor.stdout.log",
        stderr_path=tmp_path / "system-logs" / "background_monitor.stderr.log",
    )
    manager.paths.plist_path.parent.mkdir(parents=True, exist_ok=True)
    manager.paths.stdout_path.parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "system-runtime" / "mac_audit_agent").mkdir(parents=True, exist_ok=True)
    (tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py").write_text("print('ok')\n", encoding="utf-8")
    monkeypatch.setattr("mac_audit_agent.launch_agent.default_launch_agent_paths", lambda scope=None: manager.paths)
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_LAUNCH_DAEMON_PATH", manager.paths.plist_path)
    manager.install_protected_mode()

    manifest_path = protected_monitor_manifest_path("system")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["manifest_digest_sha512"] = "0" * 128
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    integrity = verify_protected_monitor_integrity(scope="system")
    assert integrity["tamper_detected"] is True
    assert integrity["manifest_digest_status"] == "mismatch"
    assert any("manifest digest changed" in item for item in integrity["evidence"])


def test_lock_down_protected_files_uses_root_owned_system_permissions(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.geteuid", lambda: 0)
    recorded_chown: list[tuple[Path, int, int]] = []
    recorded_chmod: list[tuple[Path, int]] = []
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.chown", lambda path, uid, gid: recorded_chown.append((Path(path), uid, gid)))
    monkeypatch.setattr("pathlib.Path.chmod", lambda self, mode: recorded_chmod.append((Path(self), mode)))
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_root", lambda scope=None: tmp_path / "system-runtime")
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_package_root", lambda scope=None: tmp_path / "system-runtime" / "mac_audit_agent")
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_monitor_script_path", lambda scope=None: tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py")
    monkeypatch.setattr("mac_audit_agent.launch_agent.monitor_log_root", lambda scope=None: tmp_path / "system-logs")
    monkeypatch.setattr("mac_audit_agent.launch_agent.default_monitor_db_path", lambda scope=None: tmp_path / "system.sqlite3")

    source_pkg = tmp_path / "source" / "mac_audit_agent"
    source_pkg.mkdir(parents=True, exist_ok=True)
    (source_pkg / "__init__.py").write_text("", encoding="utf-8")
    (source_pkg / "monitor.py").write_text("print('ok')\n", encoding="utf-8")

    manager = LaunchAgentManager(tmp_path / "audit.sqlite", runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0, stdout="OK"), scope="system")
    manager._runtime_root = lambda: tmp_path / "system-runtime"
    manager._runtime_package_root = lambda: tmp_path / "system-runtime" / "mac_audit_agent"
    manager._runtime_monitor_script_path = lambda: tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py"
    manager.paths = type(manager.paths)(
        plist_path=tmp_path / "Library" / "LaunchDaemons" / f"{LAUNCH_AGENT_LABEL}.plist",
        stdout_path=tmp_path / "system-logs" / "background_monitor.stdout.log",
        stderr_path=tmp_path / "system-logs" / "background_monitor.stderr.log",
    )
    manager.paths.plist_path.parent.mkdir(parents=True, exist_ok=True)
    manager.paths.stdout_path.parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "system-runtime" / "mac_audit_agent").mkdir(parents=True, exist_ok=True)
    (tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py").write_text("print('ok')\n", encoding="utf-8")
    monkeypatch.setattr("mac_audit_agent.launch_agent.default_launch_agent_paths", lambda scope=None: manager.paths)
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_LAUNCH_DAEMON_PATH", manager.paths.plist_path)
    manager.install_protected_mode()
    notes = manager.lock_down_protected_files()

    assert any(path == manager.paths.plist_path and uid == 0 for path, uid, _gid in recorded_chown)
    assert any(path == tmp_path / "system-runtime" and uid == 0 for path, uid, _gid in recorded_chown)
    assert any(path == tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py" and mode == 0o755 for path, mode in recorded_chmod)
    assert any("locked down" in note for note in notes)


def test_protected_monitor_integrity_detects_world_writable_plist(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.geteuid", lambda: 0)
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.chown", lambda *args, **kwargs: None)
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_root", lambda scope=None: tmp_path / "system-runtime")
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_package_root", lambda scope=None: tmp_path / "system-runtime" / "mac_audit_agent")
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_monitor_script_path", lambda scope=None: tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py")
    monkeypatch.setattr("mac_audit_agent.launch_agent.monitor_log_root", lambda scope=None: tmp_path / "system-logs")
    monkeypatch.setattr("mac_audit_agent.launch_agent.default_monitor_db_path", lambda scope=None: tmp_path / "system.sqlite3")

    source_pkg = tmp_path / "source" / "mac_audit_agent"
    source_pkg.mkdir(parents=True, exist_ok=True)
    (source_pkg / "__init__.py").write_text("", encoding="utf-8")
    (source_pkg / "monitor.py").write_text("print('ok')\n", encoding="utf-8")

    manager = LaunchAgentManager(tmp_path / "audit.sqlite", runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0, stdout="OK"), scope="system")
    manager._runtime_root = lambda: tmp_path / "system-runtime"
    manager._runtime_package_root = lambda: tmp_path / "system-runtime" / "mac_audit_agent"
    manager._runtime_monitor_script_path = lambda: tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py"
    manager.paths = type(manager.paths)(
        plist_path=tmp_path / "Library" / "LaunchDaemons" / f"{LAUNCH_AGENT_LABEL}.plist",
        stdout_path=tmp_path / "system-logs" / "background_monitor.stdout.log",
        stderr_path=tmp_path / "system-logs" / "background_monitor.stderr.log",
    )
    manager.paths.plist_path.parent.mkdir(parents=True, exist_ok=True)
    manager.paths.stdout_path.parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "system-runtime" / "mac_audit_agent").mkdir(parents=True, exist_ok=True)
    (tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py").write_text("print('ok')\n", encoding="utf-8")
    monkeypatch.setattr("mac_audit_agent.launch_agent.default_launch_agent_paths", lambda scope=None: manager.paths)
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_LAUNCH_DAEMON_PATH", manager.paths.plist_path)
    manager.install_protected_mode()

    original_stat = Path.stat

    class FakeBadStat:
        st_uid = 0
        st_gid = 80
        st_mode = 0o100666

    monkeypatch.setattr("pathlib.Path.stat", lambda self: FakeBadStat() if self == manager.paths.plist_path else original_stat(self))
    integrity = verify_protected_monitor_integrity(scope="system")
    assert integrity["tamper_detected"] is True
    assert any("world writable" in item or "mode mismatch" in item for item in integrity["evidence"])


def test_uninstall_path_exists_and_removes_protected_plist(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.geteuid", lambda: 0)
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.chown", lambda *args, **kwargs: None)
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_root", lambda scope=None: tmp_path / "system-runtime")
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_package_root", lambda scope=None: tmp_path / "system-runtime" / "mac_audit_agent")
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_monitor_script_path", lambda scope=None: tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py")
    monkeypatch.setattr("mac_audit_agent.launch_agent.monitor_log_root", lambda scope=None: tmp_path / "system-logs")
    monkeypatch.setattr("mac_audit_agent.launch_agent.default_monitor_db_path", lambda scope=None: tmp_path / "system.sqlite3")
    source_pkg = tmp_path / "source" / "mac_audit_agent"
    source_pkg.mkdir(parents=True, exist_ok=True)
    (source_pkg / "__init__.py").write_text("", encoding="utf-8")
    (source_pkg / "monitor.py").write_text("print('ok')\n", encoding="utf-8")
    manager = LaunchAgentManager(tmp_path / "audit.sqlite", runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0, stdout="OK"), scope="system")
    manager._runtime_root = lambda: tmp_path / "system-runtime"
    manager._runtime_package_root = lambda: tmp_path / "system-runtime" / "mac_audit_agent"
    manager._runtime_monitor_script_path = lambda: tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py"
    manager.paths = type(manager.paths)(
        plist_path=tmp_path / "Library" / "LaunchDaemons" / f"{LAUNCH_AGENT_LABEL}.plist",
        stdout_path=tmp_path / "system-logs" / "background_monitor.stdout.log",
        stderr_path=tmp_path / "system-logs" / "background_monitor.stderr.log",
    )
    manager.paths.plist_path.parent.mkdir(parents=True, exist_ok=True)
    manager.paths.stdout_path.parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "system-runtime" / "mac_audit_agent").mkdir(parents=True, exist_ok=True)
    (tmp_path / "system-runtime" / "mac_audit_agent" / "monitor.py").write_text("print('ok')\n", encoding="utf-8")
    monkeypatch.setattr("mac_audit_agent.launch_agent.default_launch_agent_paths", lambda scope=None: manager.paths)
    monkeypatch.setattr("mac_audit_agent.launch_agent.SYSTEM_LAUNCH_DAEMON_PATH", manager.paths.plist_path)
    report_path = tmp_path / "reports" / "monitor-report.html"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("<html>report</html>", encoding="utf-8")
    manager.install_protected_mode()
    assert manager.paths.plist_path.exists()
    manager.uninstall_protected_mode(remove_runtime=False)
    assert not manager.paths.plist_path.exists()
    assert report_path.exists()
    assert hasattr(manager, "uninstall_protected_mode")


def test_system_monitor_install_rejects_user_launchagents_path(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.geteuid", lambda: 0)
    manager = LaunchAgentManager(tmp_path / "audit.sqlite", scope="system")
    manager.paths = type(manager.paths)(
        plist_path=Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist",
        stdout_path=tmp_path / "system-logs" / "background_monitor.stdout.log",
        stderr_path=tmp_path / "system-logs" / "background_monitor.stderr.log",
    )
    with pytest.raises(RuntimeError, match="/Library/LaunchDaemons"):
        manager.install_system_monitor()


def test_launch_agent_install_validates_with_plutil_and_sets_permissions(tmp_path: Path, monkeypatch) -> None:
    calls = []
    chmod_calls = []
    chown_calls = []

    def fake_runner(command, capture_output=True, text=True):
        calls.append(command)
        return FakeCompletedProcess(returncode=0, stdout="OK")

    monkeypatch.setattr("mac_audit_agent.launch_agent.os.chmod", lambda path, mode, **kwargs: chmod_calls.append((Path(path), mode)))
    monkeypatch.setattr("mac_audit_agent.launch_agent.os.chown", lambda path, uid, gid: chown_calls.append((Path(path), uid, gid)))
    runtime_base = tmp_path / "runtime"
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_root", lambda scope=None: runtime_base)
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_package_root", lambda scope=None: runtime_base / "mac_audit_agent")
    monkeypatch.setattr("mac_audit_agent.launch_agent.monitor_script_path", lambda: tmp_path / "source" / "mac_audit_agent" / "monitor.py")
    source_pkg = tmp_path / "source" / "mac_audit_agent"
    source_pkg.mkdir(parents=True, exist_ok=True)
    (source_pkg / "__init__.py").write_text("", encoding="utf-8")
    (source_pkg / "monitor.py").write_text("print('ok')\n", encoding="utf-8")

    manager = LaunchAgentManager(tmp_path / "audit.sqlite", runner=fake_runner)
    manager.paths = type(manager.paths)(
        plist_path=tmp_path / "com.mac-audit-agent.monitor.plist",
        stdout_path=tmp_path / "background_monitor.stdout.log",
        stderr_path=tmp_path / "background_monitor.stderr.log",
    )
    plist_path = manager.install()

    assert plist_path == manager.paths.plist_path
    assert manager.paths.plist_path.exists()
    payload = plistlib.loads(manager.paths.plist_path.read_bytes())
    assert payload["ProgramArguments"][-2:] == ["--mode", "user-notifier"]
    assert payload["EnvironmentVariables"]["MAC_AUDIT_AGENT_MONITOR_ROLE"] == "user-notifier"
    assert any(command[:2] == [PLUTIL_BIN, "-lint"] for command in calls)
    assert any(call == (manager.paths.plist_path, 0o644) for call in chmod_calls)
    assert any(call[0] == manager.paths.plist_path for call in chown_calls)


def test_launch_agent_start_stop_without_root(tmp_path: Path) -> None:
    calls = []

    def fake_runner(command, capture_output=True, text=True):
        calls.append(command)
        if command[:2] == [PLUTIL_BIN, "-lint"]:
            return FakeCompletedProcess(returncode=0, stdout="OK")
        if command[:2] == [LAUNCHCTL_BIN, "print"]:
            return FakeCompletedProcess(returncode=0, stdout="state = running")
        return FakeCompletedProcess(returncode=0, stdout="OK")

    runtime_base = tmp_path / "runtime"
    source_pkg = tmp_path / "source" / "mac_audit_agent"
    source_pkg.mkdir(parents=True, exist_ok=True)
    (source_pkg / "__init__.py").write_text("", encoding="utf-8")
    (source_pkg / "monitor.py").write_text("print('ok')\n", encoding="utf-8")
    manager = LaunchAgentManager(tmp_path / "audit.sqlite", runner=fake_runner)
    manager.paths = type(manager.paths)(
        plist_path=tmp_path / "com.mac-audit-agent.monitor.plist",
        stdout_path=tmp_path / "background_monitor.stdout.log",
        stderr_path=tmp_path / "background_monitor.stderr.log",
    )
    from unittest.mock import patch
    with patch("mac_audit_agent.launch_agent.runtime_root", lambda scope=None: runtime_base), patch(
        "mac_audit_agent.launch_agent.runtime_package_root", lambda scope=None: runtime_base / "mac_audit_agent"
    ), patch("mac_audit_agent.launch_agent.monitor_script_path", lambda: source_pkg / "monitor.py"):
        manager.paths.plist_path.write_bytes(plistlib.dumps(build_launch_agent_plist(db_path=tmp_path / "audit.sqlite", python_executable="/usr/bin/python3")))
        manager.paths.stdout_path.parent.mkdir(parents=True, exist_ok=True)
        (runtime_base / "mac_audit_agent").mkdir(parents=True, exist_ok=True)
        (runtime_base / "mac_audit_agent" / "monitor.py").write_text("print('ok')\n", encoding="utf-8")
        manager.start()
        manager.stop()
    joined = " ".join(" ".join(command) for command in calls)
    assert "sudo" not in joined
    assert "system" not in joined
    assert any(command[:2] == [LAUNCHCTL_BIN, "bootstrap"] for command in calls)
    assert any(command == [LAUNCHCTL_BIN, "bootstrap", launchctl_target(), str(manager.paths.plist_path)] for command in calls)
    assert any(command == [LAUNCHCTL_BIN, "kickstart", "-k", f"{launchctl_target()}/{LAUNCH_AGENT_LABEL}"] for command in calls)
    assert any(command == [LAUNCHCTL_BIN, "bootout", f"{launchctl_target()}/{LAUNCH_AGENT_LABEL}"] for command in calls)
    assert any(command == [LAUNCHCTL_BIN, "bootout", launchctl_target(), str(manager.paths.plist_path)] for command in calls)
    assert calls.index([LAUNCHCTL_BIN, "bootout", f"{launchctl_target()}/{LAUNCH_AGENT_LABEL}"]) < calls.index([LAUNCHCTL_BIN, "bootout", launchctl_target(), str(manager.paths.plist_path)])
    assert any(command[:2] == [LAUNCHCTL_BIN, "bootout"] for command in calls)


def test_launch_agent_errors_include_exact_command_and_stderr(tmp_path: Path) -> None:
    def fake_runner(command, capture_output=True, text=True):
        if command[:2] == [PLUTIL_BIN, "-lint"]:
            return FakeCompletedProcess(returncode=0, stdout="OK")
        if command[:2] == [LOG_BIN, "show"]:
            return FakeCompletedProcess(returncode=0, stdout="launchd tail line")
        return FakeCompletedProcess(returncode=1, stderr="domain does not support the specified action")

    runtime_base = tmp_path / "runtime"
    source_pkg = tmp_path / "source" / "mac_audit_agent"
    source_pkg.mkdir(parents=True, exist_ok=True)
    (source_pkg / "__init__.py").write_text("", encoding="utf-8")
    (source_pkg / "monitor.py").write_text("print('ok')\n", encoding="utf-8")
    manager = LaunchAgentManager(tmp_path / "audit.sqlite", runner=fake_runner)
    manager.paths = type(manager.paths)(
        plist_path=tmp_path / "com.mac-audit-agent.monitor.plist",
        stdout_path=tmp_path / "background_monitor.stdout.log",
        stderr_path=tmp_path / "background_monitor.stderr.log",
    )
    from unittest.mock import patch
    with patch("mac_audit_agent.launch_agent.runtime_root", lambda scope=None: runtime_base), patch(
        "mac_audit_agent.launch_agent.runtime_package_root", lambda scope=None: runtime_base / "mac_audit_agent"
    ), patch("mac_audit_agent.launch_agent.monitor_script_path", lambda: source_pkg / "monitor.py"):
        manager.paths.plist_path.write_bytes(plistlib.dumps(build_launch_agent_plist(db_path=tmp_path / "audit.sqlite", python_executable="/usr/bin/python3")))
        manager.paths.stdout_path.parent.mkdir(parents=True, exist_ok=True)
        (runtime_base / "mac_audit_agent").mkdir(parents=True, exist_ok=True)
        (runtime_base / "mac_audit_agent" / "monitor.py").write_text("print('ok')\n", encoding="utf-8")

        try:
            manager.start()
        except RuntimeError as exc:
            message = str(exc)
        else:
            raise AssertionError("expected RuntimeError")

    assert f"{LAUNCHCTL_BIN} bootstrap {launchctl_target()} {manager.paths.plist_path}" in message
    assert "domain does not support the specified action" in message
    assert "launchd log tail:" in message
    assert "launchd tail line" in message


def test_launch_agent_start_preflight_checks_working_directory_owner_mode_and_log_dirs(tmp_path: Path, monkeypatch) -> None:
    runtime_base = tmp_path / "runtime"
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_root", lambda scope=None: runtime_base)
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_package_root", lambda scope=None: runtime_base / "mac_audit_agent")
    monkeypatch.setattr("mac_audit_agent.launch_agent.monitor_script_path", lambda: tmp_path / "source" / "mac_audit_agent" / "monitor.py")
    source_pkg = tmp_path / "source" / "mac_audit_agent"
    source_pkg.mkdir(parents=True, exist_ok=True)
    (source_pkg / "__init__.py").write_text("", encoding="utf-8")
    (source_pkg / "monitor.py").write_text("print('ok')\n", encoding="utf-8")
    manager = LaunchAgentManager(tmp_path / "audit.sqlite", runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0, stdout="OK"))
    manager.paths = type(manager.paths)(
        plist_path=tmp_path / "com.mac-audit-agent.monitor.plist",
        stdout_path=tmp_path / "logs" / "background_monitor.stdout.log",
        stderr_path=tmp_path / "logs" / "background_monitor.stderr.log",
    )
    payload = build_launch_agent_plist(db_path=tmp_path / "audit.sqlite", python_executable="/usr/bin/python3")
    payload["WorkingDirectory"] = str(tmp_path / "missing-root")
    manager.paths.plist_path.parent.mkdir(parents=True, exist_ok=True)
    manager.paths.plist_path.write_bytes(plistlib.dumps(payload))
    os.chmod(manager.paths.plist_path, 0o644)

    try:
        manager.start()
    except RuntimeError as exc:
        message = str(exc)
    else:
        raise AssertionError("expected RuntimeError")
    assert "WorkingDirectory does not exist" in message

    runtime_base.mkdir(parents=True, exist_ok=True)
    payload["WorkingDirectory"] = str(runtime_base)
    manager.paths.plist_path.write_bytes(plistlib.dumps(payload))
    try:
        manager.start()
    except RuntimeError as exc:
        message = str(exc)
    else:
        raise AssertionError("expected RuntimeError")
    assert "log directory does not exist" in message

    manager.paths.stdout_path.parent.mkdir(parents=True, exist_ok=True)
    original_stat = Path.stat

    class FakeStat:
        st_uid = 0
        st_mode = 0o100644

    monkeypatch.setattr("pathlib.Path.stat", lambda self: FakeStat() if self == manager.paths.plist_path else original_stat(self))
    try:
        manager.start()
    except RuntimeError as exc:
        message = str(exc)
    else:
        raise AssertionError("expected RuntimeError")
    assert "plist owner is" in message

    class FakeWrongModeStat:
        st_uid = os.getuid()
        st_mode = 0o100600

    monkeypatch.setattr("pathlib.Path.stat", lambda self: FakeWrongModeStat() if self == manager.paths.plist_path else original_stat(self))
    try:
        manager.start()
    except RuntimeError as exc:
        message = str(exc)
    else:
        raise AssertionError("expected RuntimeError")
    assert "plist mode is" in message


def test_launch_agent_force_reinstall_attempts_bootout_remove_recreate_bootstrap_and_kickstart(tmp_path: Path) -> None:
    calls = []

    def fake_runner(command, capture_output=True, text=True):
        calls.append(command)
        if command[:2] == [PLUTIL_BIN, "-lint"]:
            return FakeCompletedProcess(returncode=0, stdout="OK")
        if command[:2] == [LAUNCHCTL_BIN, "print"]:
            return FakeCompletedProcess(returncode=0, stdout="state = running\npid = 123")
        return FakeCompletedProcess(returncode=0, stdout="OK")

    runtime_base = tmp_path / "runtime"
    source_pkg = tmp_path / "source" / "mac_audit_agent"
    source_pkg.mkdir(parents=True, exist_ok=True)
    (source_pkg / "__init__.py").write_text("", encoding="utf-8")
    (source_pkg / "monitor.py").write_text("print('ok')\n", encoding="utf-8")
    manager = LaunchAgentManager(tmp_path / "audit.sqlite", runner=fake_runner)
    manager.paths = type(manager.paths)(
        plist_path=tmp_path / "com.mac-audit-agent.monitor.plist",
        stdout_path=tmp_path / "logs" / "background_monitor.stdout.log",
        stderr_path=tmp_path / "logs" / "background_monitor.stderr.log",
    )
    manager.paths.plist_path.parent.mkdir(parents=True, exist_ok=True)
    manager.paths.stdout_path.parent.mkdir(parents=True, exist_ok=True)
    from unittest.mock import patch
    with patch("mac_audit_agent.launch_agent.runtime_root", lambda scope=None: runtime_base), patch(
        "mac_audit_agent.launch_agent.runtime_package_root", lambda scope=None: runtime_base / "mac_audit_agent"
    ), patch("mac_audit_agent.launch_agent.monitor_script_path", lambda: source_pkg / "monitor.py"):
        manager.paths.plist_path.write_bytes(plistlib.dumps(build_launch_agent_plist(db_path=tmp_path / "audit.sqlite", python_executable="/usr/bin/python3")))
        plist_path, notes = manager.force_reinstall()

    assert plist_path == manager.paths.plist_path
    assert any(command == [LAUNCHCTL_BIN, "bootout", f"{launchctl_target()}/{LAUNCH_AGENT_LABEL}"] for command in calls)
    assert any(command == [LAUNCHCTL_BIN, "bootout", launchctl_target(), str(manager.paths.plist_path)] for command in calls)
    assert any(command == [LAUNCHCTL_BIN, "bootstrap", launchctl_target(), str(manager.paths.plist_path)] for command in calls)
    assert any(command == [LAUNCHCTL_BIN, "kickstart", "-k", f"{launchctl_target()}/{LAUNCH_AGENT_LABEL}"] for command in calls)
    assert any(note.startswith("removed:") for note in notes)
    assert any(note.startswith("recreated:") for note in notes)


def test_launch_agent_label_mismatch_detected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "mac_audit_agent.launch_agent.build_launch_agent_plist",
        lambda **kwargs: {"Label": "wrong.label", "ProgramArguments": []},
    )
    manager = LaunchAgentManager(tmp_path / "audit.sqlite", runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0))
    try:
        manager.install()
    except RuntimeError as exc:
        assert "Invalid LaunchAgent Label" in str(exc)
    else:
        raise AssertionError("expected RuntimeError")


def test_launch_agent_status_error_includes_exact_print_command(tmp_path: Path) -> None:
    def fake_runner(command, capture_output=True, text=True):
        return FakeCompletedProcess(returncode=1, stderr="domain does not support the specified action")

    manager = LaunchAgentManager(tmp_path / "audit.sqlite", runner=fake_runner)
    manager.paths = type(manager.paths)(
        plist_path=tmp_path / "com.mac-audit-agent.monitor.plist",
        stdout_path=tmp_path / "background_monitor.stdout.log",
        stderr_path=tmp_path / "background_monitor.stderr.log",
    )
    manager.paths.plist_path.write_text("plist", encoding="utf-8")

    status = manager.status()

    assert status.running is False
    assert f"{LAUNCHCTL_BIN} print {launchctl_target()}/{LAUNCH_AGENT_LABEL}" in status.last_error
    assert "domain does not support the specified action" in status.last_error


def test_record_monitor_heartbeat_and_aliases(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.record_monitor_heartbeat("2026-04-24T12:00:00Z")
    event = BackgroundMonitorEvent(
        event_id="heartbeat-test",
        timestamp="2026-04-24T12:00:01Z",
        event_type="monitor_test_event",
        severity="info",
        source="ui",
        evidence="test event",
        confidence="high",
        recommendation="review",
        simulated=True,
        notification_sent=True,
        notification_error="",
        metadata_json="{}",
    )
    assert db.record_monitor_event(event) is True
    assert db.get_background_monitor_status().last_heartbeat == "2026-04-24T12:00:00Z"
    saved = db.latest_monitor_events(limit=1)[0]
    assert saved.event_id == "heartbeat-test"
    assert saved.simulated is True
    assert saved.notification_sent is True


def test_background_monitor_events_are_saved_and_rate_limited(tmp_path: Path, monkeypatch) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    event = BackgroundMonitorEvent(
        event_id="event-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="camera_activity_suspected",
        severity="medium",
        source="process_correlation",
        process_name="Zoom",
        pid=123,
        evidence="Camera-capable app observed.",
        confidence="medium",
        recommendation="Verify Zoom use.",
        metadata_json="{}",
    )

    monkeypatch.setattr(service.notifications, "should_notify", lambda _event: False)
    service._persist_events([event])
    service._persist_events([BackgroundMonitorEvent(**{**event.to_dict(), "event_id": "event-2"})])

    saved = db.recent_background_monitor_events(limit=10)
    assert len(saved) == 1
    assert saved[0].process_name == "Zoom"


def test_first_event_is_never_rate_limited(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    monkeypatch.setattr(service.notifications, "should_notify", lambda _event: False)
    event = service._build_event("camera_activity_suspected", "Capture-capable process observed: Photo Booth", severity="medium", confidence="medium", source="camera_process_detector", process_name="Photo Booth", pid=100)
    assert service.record_event(event) is True


def test_notification_manager_notifies_allowlisted_critical_events_by_default_and_rate_limits(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    calls = []
    manager = NotificationManager(db, runner=lambda *args, **kwargs: calls.append(args[0]) or FakeCompletedProcess(returncode=0))
    event = BackgroundMonitorEvent(
        event_id="notify-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="launchdaemon_added",
        severity="critical",
        source="ui",
        evidence="New LaunchDaemon detected: com.example.daemon",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    settings = manager.settings()
    assert settings["notify_all_events"] is False
    assert settings["notify_important_events"] is True
    assert settings["popup_only_severe_events"] is True
    assert settings["notification_sound"] == "Glass"
    assert settings["duplicate_rate_limit_seconds"] == 10
    assert manager.should_notify(event) is True
    sent, error = manager.notify(event)
    assert sent is True
    assert error == ""
    assert event.notification_returncode == 0
    assert calls
    assert calls[0][0] == "/usr/bin/osascript"
    repeat = BackgroundMonitorEvent(**{**event.to_dict(), "event_id": "notify-2", "timestamp": "2026-04-24T12:00:05+00:00"})
    assert manager.should_notify(repeat) is False


def test_cfaa_acknowledgment_runs_once_per_gui_session_and_records_acceptance(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    popen_calls = []
    process = FakePopenProcess()

    def runner(command, **kwargs):
        assert command == ["/bin/launchctl", "print", f"gui/{os.getuid()}"]
        return FakeCompletedProcess(returncode=0, stdout="uid = 501\nasid = 100003\n")

    manager = NotificationManager(
        db,
        runner=runner,
        popen_factory=lambda command, **kwargs: popen_calls.append((command, kwargs)) or process,
    )
    assert manager.start_cfaa_login_acknowledgment() is True
    assert manager.start_cfaa_login_acknowledgment() is False
    assert len(popen_calls) == 1
    assert "18 U.S.C. 1030" in popen_calls[0][0][2]
    assert db.get_background_monitor_state("cfaa_acknowledgment_status") == "pending for gui/501:asid/100003"

    process.returncode = 0
    assert manager.poll_cfaa_login_acknowledgment() is True
    assert db.get_background_monitor_state("cfaa_acknowledged_session") == "gui/501:asid/100003"
    assert db.get_background_monitor_state("cfaa_acknowledged_at")
    assert manager.start_cfaa_login_acknowledgment() is False
    assert len(popen_calls) == 1


def test_high_priority_event_uses_configured_alert_style(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    calls = []
    manager = NotificationManager(db, runner=lambda *args, **kwargs: calls.append(args[0]) or FakeCompletedProcess(returncode=0))
    event = BackgroundMonitorEvent(
        event_id="alert-style-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="camera_activity_confirmed",
        severity="high",
        source="process_poll",
        process_name="FaceTime",
        evidence="Camera activity confirmed for FaceTime.",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    sent, error = manager.notify(event)
    assert sent is True
    assert error == ""
    assert "display dialog" in calls[0][2]


def test_user_can_change_event_severity(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    preferences = manager.event_preferences()
    preferences["capture_capable_process_observed"]["severity"] = "critical"
    manager.update_event_preferences(preferences)
    assert manager.preference_for("capture_capable_process_observed")["severity"] == "critical"


def test_new_admin_and_launchdaemon_default_priorities(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    assert manager.preference_for("new_admin_user_detected")["severity"] == "critical"
    assert manager.preference_for("launchdaemon_added")["severity"] == "critical"


def test_low_event_logs_but_does_not_popup_by_default(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    event = BackgroundMonitorEvent(
        event_id="low-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="heartbeat",
        severity="info",
        source="monitor",
        evidence="heartbeat",
        confidence="high",
        recommendation="none",
        metadata_json="{}",
    )
    assert manager.should_notify(event) is False
    assert event.notification_decision == "log_only"


def test_input_activity_resumed_after_idle_notifies_by_default(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    event = BackgroundMonitorEvent(
        event_id="input-idle-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="input_activity_resumed_after_idle",
        severity="medium",
        source="hid_idle_time",
        evidence="Keyboard, mouse, and trackpad were idle for at least 120 seconds before input resumed.",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    assert manager.preference_for(event.event_type)["severity"] == "medium"
    assert manager.preference_for(event.event_type)["notification_mode"] == "dialog"
    assert manager.should_notify(event) is True


def test_input_activity_resumed_after_idle_uses_cfaa_dialog(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    calls = []
    manager = NotificationManager(db, runner=lambda *args, **kwargs: calls.append(args[0]) or FakeCompletedProcess(returncode=0))
    event = BackgroundMonitorEvent(
        event_id="input-idle-dialog",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="input_activity_resumed_after_idle",
        severity="medium",
        source="hid_idle_time",
        evidence="Keyboard, mouse, and trackpad were idle for at least 120 seconds before input resumed.",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    sent, error = manager.notify(event)
    assert sent is True
    assert error == ""
    assert any("display dialog" in command[2] for command in calls)
    assert any("Authorized use reminder" in command[2] for command in calls)


@pytest.mark.parametrize(
    "event_type",
    [
        "idle_resume_detected",
        "mouse_or_keyboard_activity_after_idle",
    ],
)
def test_idle_resume_variants_use_cfaa_dialog(tmp_path: Path, event_type: str) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    calls = []
    manager = NotificationManager(db, runner=lambda *args, **kwargs: calls.append(args[0]) or FakeCompletedProcess(returncode=0))
    event = BackgroundMonitorEvent(
        event_id=f"{event_type}-dialog",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type=event_type,
        severity="medium",
        source="hid_idle_time",
        evidence="Activity was detected after a period of inactivity.",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    sent, error = manager.notify(event)
    assert sent is True
    assert error == ""
    assert any("display dialog" in command[2] for command in calls)
    assert any("Authorized use reminder" in command[2] for command in calls)


def test_visibility_sensitive_physical_and_device_events_notify_by_default(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    for event_type, severity in [
        ("camera_activity_suspected", "medium"),
        ("camera_activity_confirmed", "high"),
        ("bluetooth_device_connected", "medium"),
        ("bluetooth_device_disconnected", "medium"),
        ("usb_device_removed", "medium"),
        ("unknown_hid_device_detected", "high"),
        ("display_wake", "medium"),
        ("display_sleep", "medium"),
        ("screen_locked", "medium"),
        ("lid_opened", "high"),
        ("lid_closed", "high"),
        ("idle_resume_detected", "medium"),
        ("mouse_or_keyboard_activity_after_idle", "medium"),
        ("system_moisture_detected", "critical"),
    ]:
        event = BackgroundMonitorEvent(
            event_id=f"{event_type}-1",
            timestamp="2026-04-24T12:00:00+00:00",
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
        assert manager.preference_for(event.event_type)["notify"] is True
        assert manager.should_notify(event) is True


def test_security_overlay_buttons_use_full_legible_labels(tmp_path: Path, monkeypatch) -> None:
    state_path = tmp_path / "state" / "security_overlay.json"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "active": True,
        "event_type": "input_activity_resumed_after_idle",
        "severity": "critical",
        "style": "critical_red",
        "title": "Authorized Use Notice",
        "details": "Activity was detected after a period of inactivity.",
        "summary": "Review required.",
        "timestamp": "2026-06-02T12:00:00+00:00",
        "count": 1,
        "persistent": True,
        "dismiss_after_seconds": 0,
        "buttons": ["Open Timeline", "Preserve Evidence Snapshot", "Acknowledge"],
    }
    state_path.write_text(json.dumps(payload), encoding="utf-8")

    from mac_audit_agent.security_overlay import SecurityOverlay
    app = QApplication.instance() or QApplication([])
    overlay = SecurityOverlay(state_path)
    overlay.refresh()

    assert overlay.open_timeline.text() == "Open Timeline"
    assert overlay.preserve_snapshot.text() == "Preserve Evidence Snapshot"
    assert overlay.acknowledge.text() == "Acknowledge"
    assert overlay.open_timeline.minimumHeight() >= 34
    assert overlay.preserve_snapshot.minimumHeight() >= 34
    assert overlay.acknowledge.minimumHeight() >= 34
    overlay.close()
    assert app is not None


def test_visible_alert_decision_and_overlay_payload_restore_bottom_right_styles(tmp_path: Path, monkeypatch) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    state_path = tmp_path / "state" / "security_overlay.json"
    pid_path = tmp_path / "state" / "security_overlay.pid"
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_STATE_PATH", state_path)
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_PID_PATH", pid_path)
    monkeypatch.setattr(manager, "_ensure_security_overlay_process", lambda: None)

    cases = [
        ("launchdaemon_added", "critical_red"),
        ("usb_device_connected", "high_orange"),
        ("new_usb_device_detected", "critical_red"),
        ("apple_security_forecast_elevated", "neutral_grey"),
        ("apple_security_forecast_urgent", "high_orange"),
        ("input_activity_resumed_after_idle", "critical_red"),
    ]
    for event_type, expected_style in cases:
        event = BackgroundMonitorEvent(
            event_id=f"{event_type}-overlay",
            timestamp="2026-04-24T12:00:00+00:00",
            event_type=event_type,
            severity="critical" if "urgent" in event_type or event_type in {"launchdaemon_added", "new_usb_device_detected"} else "high" if event_type == "usb_device_connected" else "medium",
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
        decision = manager.should_show_visible_alert(event)
        assert decision.show is True
        assert decision.style == expected_style
        assert manager.update_security_overlay(event) is True
        payload = json.loads(state_path.read_text(encoding="utf-8"))
        assert payload["active"] is True
        assert payload["style"] == expected_style
        assert payload["visible_alert_shown"] is True
        assert payload["buttons"]


def test_visible_alert_cooldown_suppresses_repeat_overlay(tmp_path: Path, monkeypatch) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    state_path = tmp_path / "state" / "security_overlay.json"
    pid_path = tmp_path / "state" / "security_overlay.pid"
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_STATE_PATH", state_path)
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_PID_PATH", pid_path)
    monkeypatch.setattr(manager, "_ensure_security_overlay_process", lambda: None)
    event = BackgroundMonitorEvent(
        event_id="usb-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="usb_device_connected",
        severity="info",
        source="test",
        evidence="USB connected",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
        rule_id="usb_device_connected",
        trigger_rule_id="usb_device_connected",
        rule_name="usb_device_connected",
        trigger_rule_name="usb_device_connected",
    )
    assert manager.update_security_overlay(event) is True
    db.set_background_monitor_state(manager._visible_alert_last_key(event), "2026-04-24T12:00:00+00:00")
    repeat = BackgroundMonitorEvent(
        **{**event.to_dict(), "event_id": "usb-2", "timestamp": "2026-04-24T12:05:00+00:00"}
    )
    decision = manager.should_show_visible_alert(repeat)
    assert decision.show is False
    assert decision.reason == "within_cooldown"


def test_medium_event_logs_but_does_not_popup_by_default(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    event = BackgroundMonitorEvent(
        event_id="med-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="display_sleep",
        severity="medium",
        source="monitor",
        evidence="display sleep",
        confidence="high",
        recommendation="none",
        metadata_json="{}",
    )
    assert manager.should_notify(event) is False
    assert event.notification_decision == "log_only"


def test_capture_capable_process_logs_but_does_not_popup_by_default(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    event = BackgroundMonitorEvent(
        event_id="capture-log-only-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="capture_capable_process_observed",
        severity="medium",
        source="process_poll",
        process_name="FaceTime",
        evidence="Capture-capable process observed: FaceTime",
        confidence="low",
        recommendation="review",
        metadata_json="{}",
    )
    assert manager.should_notify(event) is False
    assert event.notification_decision == "log_only"
    assert event.notification_reason == "event type is log-only by default"
    assert event.popup_allowed is False


def test_opera_helper_video_capture_logs_but_does_not_popup(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    event = BackgroundMonitorEvent(
        event_id="opera-log-only-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="capture_capable_process_observed",
        severity="medium",
        source="process_poll",
        process_name="Opera Helper (Renderer)",
        evidence="browser video_capture service observed for Opera Helper (Renderer)",
        confidence="low",
        recommendation="review",
        metadata_json="{}",
    )
    assert manager.should_notify(event) is False
    assert event.notification_decision == "log_only"
    assert event.notification_reason == "browser helper process logged silently"
    assert event.popup_allowed is False


def test_camera_activity_confirmed_pops_by_default(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    event = BackgroundMonitorEvent(
        event_id="camera-confirmed-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="camera_activity_confirmed",
        severity="high",
        source="avfoundation",
        process_name="FaceTime",
        evidence="Camera activity confirmed for FaceTime.",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    assert manager.should_notify(event) is True
    assert event.notification_reason == "first_severe_event"
    assert event.popup_allowed is True


def test_lid_transition_events_popup_once(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    opened = BackgroundMonitorEvent(
        event_id="lid-open-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="possible_lid_opened",
        severity="high",
        source="session_poll",
        evidence="Possible lid opened transition detected.",
        confidence="medium",
        recommendation="review",
        metadata_json="{}",
    )
    assert manager.should_notify(opened) is True
    db.set_background_monitor_state(manager._last_key(opened), opened.timestamp)
    repeat = BackgroundMonitorEvent(**{**opened.to_dict(), "event_id": "lid-open-2", "timestamp": "2026-04-24T12:01:00+00:00"})
    assert manager.should_notify(repeat) is False
    assert repeat.notification_decision == "suppressed_cooldown"

    closed = BackgroundMonitorEvent(
        event_id="lid-close-1",
        timestamp="2026-04-24T12:02:00+00:00",
        event_type="possible_lid_closed",
        severity="high",
        source="session_poll",
        evidence="Possible lid closed transition detected.",
        confidence="medium",
        recommendation="review",
        metadata_json="{}",
    )
    assert manager.should_notify(closed) is True


def test_visible_alert_signature_distinguishes_device_transition_context(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    first = BackgroundMonitorEvent(
        event_id="usb-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="usb_device_connected",
        severity="info",
        source="ioreg_usb_observer",
        process_name="IOUSBHost",
        evidence="USB device recognized: keyboard.",
        confidence="high",
        recommendation="review",
        related_path="/dev/disk1",
        previous_state="device not present",
        current_state="keyboard",
        metadata_json="{}",
    )
    second = BackgroundMonitorEvent(
        event_id="usb-2",
        timestamp="2026-04-24T12:00:10+00:00",
        event_type="usb_device_connected",
        severity="info",
        source="ioreg_usb_observer",
        process_name="IOUSBHost",
        evidence="USB device recognized: mouse.",
        confidence="high",
        recommendation="review",
        related_path="/dev/disk2",
        previous_state="device not present",
        current_state="mouse",
        metadata_json="{}",
    )
    assert manager._visible_alert_last_key(first) != manager._visible_alert_last_key(second)


def test_idle_cfaa_reminder_prefers_overlay_and_does_not_call_dialog_when_overlay_visible(tmp_path: Path, monkeypatch) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    event = BackgroundMonitorEvent(
        event_id="idle-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="idle_resume_detected",
        severity="medium",
        source="hid_idle_time",
        evidence="Input resumed after idle.",
        confidence="high",
        recommendation="review",
        rule_id="idle_resume_detected",
        trigger_rule_id="idle_resume_detected",
        rule_name="Idle Resume Detected",
        trigger_rule_name="Idle Resume Detected",
        visible_alert_shown=True,
        alert_style="critical_red",
        metadata_json="{}",
    )
    called = []

    def fail_dialog(*_args, **_kwargs):
        called.append("dialog")
        raise AssertionError("dialog should not be called when the overlay is already visible")

    monkeypatch.setattr(manager, "_run_dialog_attempt", fail_dialog)

    sent, error = manager.notify_cfaa_idle_reminder(event)

    assert sent is True
    assert error == ""
    assert called == []


def test_run_dialog_attempt_timeout_returns_completed_process(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")

    def runner(command, **kwargs):
        raise subprocess.TimeoutExpired(cmd=command, timeout=5, output="", stderr="timed out")

    manager = NotificationManager(db, runner=runner)
    command, result = manager._run_dialog_attempt("High priority test message")

    assert command[0] == "/usr/bin/osascript"
    assert result.returncode == 124
    assert "timed out" in result.stderr


def test_new_admin_user_pops_by_default(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    event = BackgroundMonitorEvent(
        event_id="admin-added-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="new_admin_user_detected",
        severity="critical",
        source="baseline_diff",
        evidence="New admin user added: analyst2",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    assert manager.should_notify(event) is True
    assert event.popup_allowed is True


def test_launchdaemon_added_pops_by_default(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    event = BackgroundMonitorEvent(
        event_id="daemon-added-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="launchdaemon_added",
        severity="critical",
        source="baseline_diff",
        evidence="New LaunchDaemon detected: com.example.daemon",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    assert manager.should_notify(event) is True
    assert event.popup_allowed is True


def test_usb_events_send_a_non_modal_recognition_notification_by_default(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    event = BackgroundMonitorEvent(
        event_id="usb-log-only-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="usb_device_connected",
        severity="medium",
        source="hardware",
        evidence="USB device connected.",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    assert manager.should_notify(event) is True
    assert event.notification_reason == "first_severe_event"
    assert manager.preference_for("usb_device_connected")["notification_mode"] == "notification"


def test_hardware_monitor_baselines_usb_then_emits_new_recognition() -> None:
    monitor = HardwareMonitor()
    baseline = HardwareMonitorSnapshot(
        usb_devices=[{"vendor_id": "1", "product_id": "2", "serial": "existing", "location_id": "3", "vendor": "Acme", "name": "Existing"}]
    )
    current = HardwareMonitorSnapshot(
        usb_devices=[
            {"vendor_id": "1", "product_id": "2", "serial": "existing", "location_id": "3", "vendor": "Acme", "name": "Existing"},
            {"vendor_id": "4", "product_id": "5", "serial": "new", "location_id": "6", "vendor": "Acme", "name": "New Device"},
        ]
    )
    assert monitor.evaluate(None, baseline) == []
    events = monitor.evaluate(baseline, current)
    assert [event.event_type for event in events] == ["usb_device_connected", "usb_inventory_changed"]
    assert "Acme New Device" in events[0].evidence


def test_hardware_monitor_assigns_distinct_ids_to_usb_devices_in_same_snapshot() -> None:
    monitor = HardwareMonitor()
    events = monitor.usb_connection_events(
        [],
        [
            {"vendor_id": "1", "product_id": "2", "serial": "first", "location_id": "3"},
            {"vendor_id": "4", "product_id": "5", "serial": "second", "location_id": "6"},
        ],
        timestamp="2026-05-31T12:00:00+00:00",
    )
    assert len({event.event_id for event in events}) == 2


def test_hardware_monitor_parses_only_connected_bluetooth_devices() -> None:
    monitor = HardwareMonitor()
    devices = monitor._parse_bluetooth_devices(
        """
+-o Keyboard  <class IOBluetoothDevice, id 1>
    "Name" = "Research Keyboard"
    "DeviceAddress" = "AA-BB-CC-DD-EE-FF"
    "Connected" = Yes
+-o Headset  <class IOBluetoothDevice, id 2>
    "Name" = "Offline Headset"
    "DeviceAddress" = "11-22-33-44-55-66"
    "Connected" = No
"""
    )
    assert devices == [{"name": "Research Keyboard", "address": "AA-BB-CC-DD-EE-FF", "vendor_id": "", "product_id": ""}]


def test_hardware_monitor_emits_connected_bluetooth_event_with_provenance() -> None:
    monitor = HardwareMonitor()
    current = HardwareMonitorSnapshot(bluetooth_devices=[{"name": "Research Mouse", "address": "AA-BB"}])
    events = monitor.evaluate(HardwareMonitorSnapshot(), current)
    assert [event.event_type for event in events] == ["bluetooth_device_connected", "bluetooth_inventory_changed"]
    assert events[0].trigger_subsource == "ioreg_bluetooth"
    assert "Research Mouse" in events[0].evidence


def test_hardware_monitor_emits_removed_usb_and_bluetooth_events() -> None:
    monitor = HardwareMonitor()
    previous = HardwareMonitorSnapshot(
        usb_devices=[{"vendor_id": "1", "product_id": "2", "serial": "old", "location_id": "3", "name": "USB Token"}],
        bluetooth_devices=[{"name": "BT Mouse", "address": "AA-BB"}],
    )
    current = HardwareMonitorSnapshot()
    events = monitor.evaluate(previous, current)
    types = [event.event_type for event in events]
    assert "usb_device_removed" in types
    assert "usb_inventory_changed" in types
    assert "bluetooth_device_disconnected" in types
    assert "bluetooth_inventory_changed" in types


def test_native_event_bridge_normalizes_native_events(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    bridge = NativeEventBridge(db, event_log_path=tmp_path / "native_events.jsonl")
    bridge.event_log_path.parent.mkdir(parents=True, exist_ok=True)
    bridge.event_log_path.write_text(
        json.dumps(
            {
                "event_type": "usb_inventory_changed",
                "source": "native_usb_monitor",
                "timestamp": "2026-06-01T12:00:00+00:00",
                "confidence": "high",
                "severity": "medium",
                "evidence": {"added": ["phone"], "removed": []},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    drained = bridge.drain()
    assert len(drained) == 1
    assert drained[0].event_type == "usb_device_connected"
    frame = NativeEventFrame(
        event_type="lid_state_open",
        source="native_power_monitor",
        timestamp="2026-06-01T12:00:00+00:00",
        confidence="high",
        severity="high",
        evidence={"previous_state": "closed", "current_state": "open"},
        previous_state="closed",
        current_state="open",
    )
    event = native_event_frame_to_event(frame)
    assert normalize_native_event_type("lid_state_open") == "lid_opened"
    assert event.event_type == "lid_opened"
    assert event.rule_id
    assert event.trigger_source == "native_event_helper"
    assert event.previous_state == "closed"
    assert event.current_state == "open"


def test_hardware_monitor_emits_only_explicit_new_moisture_markers() -> None:
    monitor = HardwareMonitor()
    baseline = HardwareMonitorSnapshot(moisture_markers={"USB-C status normal"})
    current = HardwareMonitorSnapshot(moisture_markers={"USB-C status normal", "Liquid detected in USB-C port"})
    events = monitor.evaluate(baseline, current)
    assert [event.event_type for event in events] == ["system_moisture_detected"]
    assert events[0].severity == "critical"


def test_usb_reconnect_observer_enqueues_new_connection() -> None:
    snapshots = [
        [{"vendor_id": "1", "product_id": "2", "serial": "abc", "location_id": "3", "session_id": "old"}],
        [],
        [{"vendor_id": "1", "product_id": "2", "serial": "abc", "location_id": "3", "session_id": "new"}],
    ]
    monitor = HardwareMonitor()
    last_snapshot = snapshots[-1]
    monitor.collect_usb_devices = lambda: snapshots.pop(0) if snapshots else last_snapshot
    observer = USBReconnectObserver(monitor, poll_seconds=0.01, quiet_window_seconds=0.01)
    observer.start()
    try:
        import time
        deadline = time.monotonic() + 1
        events = []
        while time.monotonic() < deadline and not events:
            time.sleep(0.02)
            events = observer.drain()
    finally:
        observer.stop()
    assert [event.event_type for event in events] == ["usb_device_connected"]
    assert '"session_id": "new"' in events[0].metadata_json


def test_service_groups_usb_observer_burst_into_one_alert(tmp_path: Path) -> None:
    hardware = HardwareMonitor()
    events = hardware.usb_connection_events(
        [],
        [
            {"vendor_id": "1", "product_id": "2", "serial": "first", "location_id": "3", "session_id": "old", "name": "Phone"},
            {"vendor_id": "1", "product_id": "2", "serial": "first", "location_id": "3", "session_id": "new", "name": "Phone"},
            {"vendor_id": "4", "product_id": "5", "serial": "second", "location_id": "6", "name": "Adapter"},
        ],
    )
    service = BackgroundMonitorService(tmp_path / "audit.sqlite")
    grouped = service._coalesce_usb_observer_events(events)
    assert len(grouped) == 1
    assert grouped[0].event_type == "usb_device_connected"
    assert "USB reconnect recognized 2 device(s)" in grouped[0].evidence
    assert "connection=" not in grouped[0].evidence


def test_service_alerts_critical_once_for_first_seen_usb_identity(tmp_path: Path) -> None:
    hardware = HardwareMonitor()
    trusted = {"vendor_id": "1", "product_id": "2", "serial": "trusted", "location_id": "3", "name": "Phone"}
    new = {"vendor_id": "4", "product_id": "5", "serial": "new", "location_id": "6", "name": "Adapter"}
    service = BackgroundMonitorService(tmp_path / "audit.sqlite")
    assert service._classify_usb_observer_events([], [trusted]) == []

    events = hardware.usb_connection_events([], [new])
    first_seen = service._classify_usb_observer_events(events, [trusted, new])
    assert len(first_seen) == 1
    assert first_seen[0].event_type == "new_usb_device_detected"
    assert first_seen[0].severity == "critical"

    reconnect = service._classify_usb_observer_events(events, [trusted, new])
    assert len(reconnect) == 1
    assert reconnect[0].event_type == "usb_device_connected"
    assert reconnect[0].severity == "info"


def test_usb_and_moisture_events_use_distinct_sounds(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    usb = BackgroundMonitorEvent(
        event_id="usb-sound",
        timestamp="2026-05-31T12:00:00+00:00",
        event_type="usb_device_connected",
        severity="info",
        source="hardware",
        evidence="USB device recognized.",
    )
    moisture = BackgroundMonitorEvent(
        event_id="moisture-sound",
        timestamp="2026-05-31T12:00:00+00:00",
        event_type="system_moisture_detected",
        severity="critical",
        source="hardware",
        evidence="Liquid detected.",
    )
    assert manager._sound_for(usb, manager.settings()) == "Pop"
    assert manager._sound_for(moisture, manager.settings()) == "Basso"


def test_new_usb_device_uses_critical_alert_and_usb_sound(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    event = BackgroundMonitorEvent(
        event_id="new-usb",
        timestamp="2026-05-31T12:00:00+00:00",
        event_type="new_usb_device_detected",
        severity="critical",
        source="hardware",
        evidence="New USB device identity detected.",
    )
    preference = manager.preference_for(event.event_type)
    assert preference["severity"] == "critical"
    assert preference["notification_mode"] == "both"
    assert manager._sound_for(event, manager.settings()) == "Pop"


def test_network_monitor_detects_ip_assignment_and_vpn_connection() -> None:
    monitor = NetworkMonitor()
    previous = NetworkMonitorSnapshot(
        interface="en0",
        ip_address="192.168.1.10",
        netmask="255.255.255.0",
        gateway="192.168.1.1",
        subnet="192.168.1.0/24",
        scope="private",
        vpn_interfaces=[],
    )
    current = NetworkMonitorSnapshot(
        interface="en0",
        ip_address="192.168.1.20",
        netmask="255.255.255.0",
        gateway="192.168.1.1",
        subnet="192.168.1.0/24",
        scope="private",
        vpn_interfaces=[{"interface": "utun3", "ip_address": "10.8.0.12", "netmask": "255.255.255.255", "broadcast": ""}],
    )
    events = monitor.evaluate(previous, current)
    assert [event.event_type for event in events] == [
        "network_ip_assigned",
        "new_network_connection_detected",
        "new_outbound_connection_detected",
        "vpn_connected",
    ]
    assert events[0].severity == "info"
    assert "192.168.1.20" in events[0].evidence
    assert events[1].severity == "high"
    assert "192.168.1.20" in events[1].evidence
    assert events[2].severity == "high"
    assert "192.168.1.20" in events[2].evidence
    assert events[3].severity == "info"
    assert "utun3" in events[3].evidence


def test_new_network_connection_event_is_visible_by_default(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    event = BackgroundMonitorEvent(
        event_id="network-new-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="new_network_connection_detected",
        severity="high",
        source="network_state_observer",
        evidence="New active network connection observed on en0: 192.168.1.20.",
        confidence="high",
        recommendation="Confirm the new connection matches expected network activity.",
        rule_id="new_network_connection_detected",
        trigger_rule_id="new_network_connection_detected",
        rule_name="New Network Connection Detected",
        trigger_rule_name="New Network Connection Detected",
        process_name="network_state_observer",
    )
    decision = manager.should_show_visible_alert(event)
    assert decision.show is True
    assert decision.style == "high_orange"


def test_network_info_alert_uses_overlay_and_bypasses_min_severity(tmp_path: Path, monkeypatch) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    state_path = tmp_path / "state" / "security_overlay.json"
    pid_path = tmp_path / "state" / "security_overlay.pid"
    popen_calls = []
    process = FakePopenProcess()
    process.pid = 44556
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_STATE_PATH", state_path)
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_PID_PATH", pid_path)
    monkeypatch.setattr("mac_audit_agent.notification_manager.os.kill", lambda pid, signal: None)
    db.set_background_monitor_state("security_overlay_enabled", "1")
    manager = NotificationManager(db, popen_factory=lambda command, **kwargs: popen_calls.append(command) or process)
    manager.update_settings(
        notify_all_events=False,
        notify_important_events=True,
        notify_min_severity="critical",
        notification_sound="Glass",
        duplicate_rate_limit_seconds=10,
        high_priority_alert_style="notification",
        notification_mode="notification",
        popup_only_severe_events=True,
        browser_capture_process_popup=False,
    )
    event = BackgroundMonitorEvent(
        event_id="network-1",
        timestamp="2026-05-31T12:00:00+00:00",
        event_type="network_ip_assigned",
        severity="info",
        source="network_state_observer",
        evidence="IP address assigned on en0: 192.168.1.20 (subnet 192.168.1.0/24, gateway 192.168.1.1). Detected at 2026-05-31T12:00:00+00:00.",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
        rule_id="network_ip_assigned",
        trigger_rule_id="network_ip_assigned",
        rule_name="network_ip_assigned",
        trigger_rule_name="network_ip_assigned",
    )
    assert manager.should_notify(event) is True
    sent, error = manager.notify(event)
    assert sent is True
    assert error == ""
    assert manager._sound_for(event, manager.settings()) == ""
    assert json.loads(state_path.read_text(encoding="utf-8"))["severity"] == "info"
    assert len(popen_calls) == 1


def test_persistence_monitor_detects_new_launchdaemon_and_login_items(monkeypatch) -> None:
    monitor = PersistenceMonitor()
    previous = PersistenceSnapshot(
        launch_items=[
            type(
                "LaunchItem",
                (),
                {
                    "path": "/Library/LaunchDaemons/com.old.plist",
                    "label": "com.old",
                    "program": "/usr/bin/true",
                    "program_arguments": ["/usr/bin/true"],
                    "run_at_load": True,
                    "keep_alive": False,
                    "suspicious": False,
                    "reasons": [],
                    "to_dict": lambda self=None: {
                        "path": "/Library/LaunchDaemons/com.old.plist",
                        "label": "com.old",
                        "program": "/usr/bin/true",
                        "program_arguments": ["/usr/bin/true"],
                        "run_at_load": True,
                        "keep_alive": False,
                        "suspicious": False,
                        "reasons": [],
                    },
                },
            )()
        ],
        login_items=["Finder"],
    )
    current = PersistenceSnapshot(
        launch_items=[
            previous.launch_items[0],
            type(
                "LaunchItem",
                (),
                {
                    "path": "/Library/LaunchDaemons/com.new.plist",
                    "label": "com.new",
                    "program": "/usr/bin/true",
                    "program_arguments": ["/usr/bin/true"],
                    "run_at_load": True,
                    "keep_alive": False,
                    "suspicious": False,
                    "reasons": [],
                    "to_dict": lambda self=None: {
                        "path": "/Library/LaunchDaemons/com.new.plist",
                        "label": "com.new",
                        "program": "/usr/bin/true",
                        "program_arguments": ["/usr/bin/true"],
                        "run_at_load": True,
                        "keep_alive": False,
                        "suspicious": False,
                        "reasons": [],
                    },
                },
            )()
        ],
        login_items=["Finder", "NewLoginItem"],
    )
    events = monitor.evaluate(previous, current)
    assert [event.event_type for event in events] == ["launchdaemon_added", "persistence_item_created_high_risk"]
    assert events[0].severity == "critical"
    assert "com.new.plist" in events[0].evidence
    assert events[1].severity == "critical"
    assert "NewLoginItem" in events[1].evidence


def test_persistence_detector_logs_previous_and_current_inventory(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite")
    log_lines = []
    current = PersistenceSnapshot(
        launch_items=[],
        login_items=[],
    )
    service.persistence_monitor.collect_snapshot = lambda: current  # type: ignore[assignment]
    monkeypatch.setattr(service, "_write_log_line", lambda message: log_lines.append(message))
    first = service._run_persistence_detector()
    assert first == []
    assert any("persistence baseline established" in line for line in log_lines)
    assert any("persistence inventory previous" in line for line in log_lines)
    assert any("persistence inventory current" in line for line in log_lines)


def test_workflow_layer_replay_review_and_explainability(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    workflow = InvestigatorWorkflowLayer(db)
    first_scan = ScanResult(
        scan_id="scan-1",
        timestamp="2026-05-31T12:00:00+00:00",
        hostname="host",
        current_user="user",
        findings=[
            Finding(
                id="finding-1",
                category="Persistence",
                title="Suspicious Launch Item",
                severity="high",
                description="A LaunchDaemon references a writable path.",
                evidence="/Library/LaunchDaemons/com.bad.plist -> /tmp/run.sh",
                command_used="local plist parsing",
                remediation_suggestion="Review the plist owner and referenced binary.",
                warning="Can restart unwanted software automatically.",
                evidence_summary="/Library/LaunchDaemons/com.bad.plist -> /tmp/run.sh",
                why_this_matters="Launch items provide persistence.",
                recommended_next_steps="Review the plist owner and referenced binary.",
            )
        ],
    )
    second_scan = ScanResult(
        scan_id="scan-2",
        timestamp="2026-05-31T12:05:00+00:00",
        hostname="host",
        current_user="user",
        findings=first_scan.findings,
    )
    db.record_scan(ScanSummary("scan-1", "2026-05-31T12:00:00+00:00", "2026-05-31T12:00:30+00:00", 1, 88, "first", 0, "Good"))
    db.record_scan_result(first_scan)
    db.record_finding("scan-1", first_scan.findings[0])
    db.record_scan(ScanSummary("scan-2", "2026-05-31T12:05:00+00:00", "2026-05-31T12:05:30+00:00", 1, 84, "second", 1, "Needs Review"))
    db.record_scan_result(second_scan)
    db.record_finding("scan-2", second_scan.findings[0])
    replay = workflow.build_security_replay(limit=10, focus_scan_id="scan-2")
    assert any(moment.scan_id == "scan-2" for moment in replay)
    queue = workflow.build_review_queue(scan_id="scan-2")
    assert queue[0].title == "Suspicious Launch Item"
    explanation = workflow.explain_finding(second_scan.findings[0], scan=second_scan)
    assert explanation["what_happened"] == "A LaunchDaemon references a writable path."
    assert explanation["supporting_evidence"]
    assert explanation["next_action"]


def test_workflow_layer_context_window_includes_surrounding_activity(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    workflow = InvestigatorWorkflowLayer(db)
    anchor = datetime.now(timezone.utc)
    scan_timestamp = (anchor - timedelta(minutes=5)).isoformat()
    event_timestamp = (anchor + timedelta(minutes=10)).isoformat()
    scan = ScanResult(
        scan_id="scan-context",
        timestamp=scan_timestamp,
        hostname="host",
        current_user="user",
        findings=[
            Finding(
                id="finding-context",
                category="Persistence",
                title="Context Finding",
                severity="medium",
                description="A launch item exists.",
                evidence="/Library/LaunchAgents/com.example.agent.plist",
                command_used="local plist parsing",
                remediation_suggestion="Review the plist.",
                warning="Could be legitimate.",
                evidence_summary="/Library/LaunchAgents/com.example.agent.plist",
                why_this_matters="Launch items can provide persistence.",
                recommended_next_steps="Review the plist.",
            )
        ],
    )
    db.record_scan(ScanSummary("scan-context", scan_timestamp, scan_timestamp, 1, 90, "context", 0, "Good"))
    db.record_scan_result(scan)
    db.record_finding("scan-context", scan.findings[0])
    db.record_monitor_event(
        BackgroundMonitorEvent(
            event_id="network-context",
            timestamp=event_timestamp,
            event_type="network_ip_assigned",
            severity="info",
            source="network_state_observer",
            evidence="IP address assigned on en0: 192.168.1.25.",
            confidence="high",
            recommendation="Confirm the new network connection is expected.",
            metadata_json="{}",
        )
    )
    db.set_review_status(
        item_type="finding",
        item_key="finding-context",
        label="Context Finding",
        review_state="reviewed",
        linked_scan_id="scan-context",
        linked_finding_id="finding-context",
    )
    window = workflow.build_context_window(
        anchor.isoformat(),
        focus_label="Context Finding",
        focus_kind="finding",
        focus_category="Persistence",
        focus_id="finding-context",
        focus_scan_id="scan-context",
    )
    assert window.window_start == (anchor - timedelta(minutes=15)).isoformat()
    assert window.window_end == (anchor + timedelta(minutes=15)).isoformat()
    assert any(moment.focus for moment in window.moments)
    assert any(moment.category == "scan" for moment in window.moments)
    assert any(moment.category == "network" for moment in window.moments)
    assert any(moment.category == "admin" for moment in window.moments)
    assert any("LaunchAgents" in " ".join(moment.evidence) for moment in window.moments if moment.evidence)


def test_workflow_layer_learns_benign_suppressions(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    workflow = InvestigatorWorkflowLayer(db)
    scan = ScanResult(
        scan_id="scan-benign",
        timestamp="2026-05-31T12:10:00+00:00",
        hostname="host",
        current_user="user",
        findings=[
            Finding(
                id="finding-benign",
                category="Persistence",
                title="Benign Launch Item",
                severity="medium",
                description="A LaunchAgent is present.",
                evidence="/Library/LaunchAgents/com.example.agent.plist",
                command_used="local plist parsing",
                remediation_suggestion="Review the plist.",
                warning="Could be legitimate.",
                evidence_summary="/Library/LaunchAgents/com.example.agent.plist",
                why_this_matters="Launch items can provide persistence.",
                recommended_next_steps="Review the plist.",
            )
        ],
    )
    db.record_scan(ScanSummary("scan-benign", "2026-05-31T12:10:00+00:00", "2026-05-31T12:10:30+00:00", 1, 90, "benign", 0, "Good"))
    db.record_scan_result(scan)
    db.record_finding("scan-benign", scan.findings[0])
    workflow.mark_benign("scan-benign", "finding-benign", notes="Expected management agent.")
    suppression = db.find_suppression_rule(scan.findings[0])
    assert suppression is not None
    assert suppression.active is True
    assert suppression.review_state == "false positive"


def test_security_overlay_groups_critical_events_and_launches_one_process(tmp_path: Path, monkeypatch) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    state_path = tmp_path / "state" / "security_overlay.json"
    pid_path = tmp_path / "state" / "security_overlay.pid"
    popen_calls = []
    process = FakePopenProcess()
    process.pid = 98765
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_STATE_PATH", state_path)
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_PID_PATH", pid_path)
    monkeypatch.setattr("mac_audit_agent.notification_manager.os.kill", lambda pid, signal: None)
    db.set_background_monitor_state("security_overlay_enabled", "1")
    manager = NotificationManager(db, popen_factory=lambda command, **kwargs: popen_calls.append(command) or process)
    event = BackgroundMonitorEvent(
        event_id="overlay-1",
        timestamp="2026-05-31T12:00:00+00:00",
        event_type="system_moisture_detected",
        severity="critical",
        source="hardware",
        evidence="Liquid detected in USB-C port.",
    )
    assert manager.update_security_overlay(event) is True
    assert json.loads(state_path.read_text(encoding="utf-8"))["count"] == 1
    assert len(popen_calls) == 1

    repeat = BackgroundMonitorEvent(**{**event.to_dict(), "event_id": "overlay-2", "timestamp": "2026-05-31T12:01:00+00:00"})
    assert manager.update_security_overlay(repeat) is False
    assert json.loads(state_path.read_text(encoding="utf-8"))["count"] == 1
    assert len(popen_calls) == 1


def test_security_overlay_ignores_low_severity_events(tmp_path: Path, monkeypatch) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    state_path = tmp_path / "state" / "security_overlay.json"
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_STATE_PATH", state_path)
    db.set_background_monitor_state("security_overlay_enabled", "1")
    manager = NotificationManager(db)
    event = BackgroundMonitorEvent(
        event_id="overlay-low",
        timestamp="2026-05-31T12:00:00+00:00",
        event_type="usb_device_connected",
        severity="low",
        source="hardware",
        evidence="USB recognized.",
    )
    assert manager.update_security_overlay(event) is True
    assert json.loads(state_path.read_text(encoding="utf-8"))["severity"] == "low"


def test_new_activity_overlay_is_visible_without_optional_overlay_setting(tmp_path: Path, monkeypatch) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    state_path = tmp_path / "state" / "security_overlay.json"
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_STATE_PATH", state_path)
    manager = NotificationManager(db)
    monkeypatch.setattr(manager, "_ensure_security_overlay_process", lambda: None)
    event = BackgroundMonitorEvent(
        event_id="bluetooth-connected-overlay",
        timestamp="2026-06-02T12:00:00+00:00",
        event_type="bluetooth_device_connected",
        severity="medium",
        source="hardware",
        evidence="Bluetooth device connected: Research Mouse.",
    )
    assert manager.update_security_overlay(event) is True
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert payload["severity"] == "medium"
    assert payload["event_type"] == "bluetooth_device_connected"


def test_log_only_activity_routes_overlay_without_invoking_notification(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", record_startup=False)
    monkeypatch.setattr(service.notifications, "update_security_overlay", lambda event: True)
    monkeypatch.setattr(service.notifications, "notify", lambda *_args, **_kwargs: pytest.fail("notification should not run"))
    event = BackgroundMonitorEvent(
        event_id="camera-stop-overlay",
        timestamp="2026-06-02T12:00:00+00:00",
        event_type="camera_activity_stopped",
        severity="info",
        source="AVFoundation",
        evidence="Camera stopped.",
    )
    assert service._route_log_only_activity_overlay(event) is True


def test_user_notifier_renders_daemon_log_only_activity_overlay_once(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", mode="user-notifier", record_startup=False)
    overlays = []
    monkeypatch.setattr(service.notifications, "update_security_overlay", lambda event: overlays.append(event.event_type) or True)
    event = BackgroundMonitorEvent(
        event_id="daemon-bluetooth-overlay",
        timestamp="2026-06-02T12:00:00+00:00",
        event_type="camera_activity_stopped",
        severity="info",
        source="hardware_detector",
        evidence="Camera stopped.",
    )
    service.db.record_monitor_event(event, dedupe_window_seconds=0)
    notified = service.process_pending_notifications()
    assert len(notified) == 0
    assert overlays == ["camera_activity_stopped"]
    assert service.db.latest_monitor_events(limit=1)[0].notification_decision == "overlay_only"


def test_security_overlay_reconciliation_relaunches_active_overlay(tmp_path: Path, monkeypatch) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    state_path = tmp_path / "state" / "security_overlay.json"
    pid_path = tmp_path / "state" / "security_overlay.pid"
    state_path.parent.mkdir(parents=True)
    state_path.write_text(json.dumps({"active": True, "event_type": "system_moisture_detected"}), encoding="utf-8")
    popen_calls = []
    process = FakePopenProcess()
    process.pid = 12345
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_STATE_PATH", state_path)
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_PID_PATH", pid_path)
    db.set_background_monitor_state("security_overlay_enabled", "1")
    manager = NotificationManager(db, popen_factory=lambda command, **kwargs: popen_calls.append(command) or process)
    assert manager.reconcile_security_overlay() is True
    assert len(popen_calls) == 1
    assert db.get_background_monitor_state("security_overlay_status") == "active: system_moisture_detected"


def test_duplicate_critical_event_updates_overlay_counter_even_when_db_dedupes(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite")
    overlay_calls = []
    monkeypatch.setattr(service.notifications, "should_notify", lambda _event: False)
    monkeypatch.setattr(service.notifications, "update_security_overlay", lambda event: overlay_calls.append(event.event_type) or True)
    first = service._build_event(
        "system_moisture_detected",
        "Liquid detected in USB-C port.",
        severity="critical",
        confidence="high",
        source="hardware",
    )
    second = BackgroundMonitorEvent(**{**first.to_dict(), "event_id": "moisture-repeat"})
    assert service.record_monitor_event(first) == first.event_id
    assert service.record_monitor_event(second) is None
    assert overlay_calls == ["system_moisture_detected"]


def test_cfaa_findings_digest_groups_findings_and_suppresses_unchanged_repeat(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    calls = []
    manager = NotificationManager(db, runner=lambda *args, **kwargs: calls.append(args[0]) or FakeCompletedProcess(returncode=0))
    findings = [
        {"severity": "high", "title": "CVE finding", "cve_ids": ["CVE-2026-0001"]},
        {"severity": "info", "title": "Informational finding", "cve_ids": ["CVE-2026-0002"]},
    ]
    assert manager.notify_findings_digest(findings) == (True, "")
    assert manager.notify_findings_digest(findings) == (False, "unchanged findings digest")
    assert len(calls) == 1
    assert "18 U.S.C. 1030" in calls[0][2]


def test_applescript_escape_prevents_broken_strings() -> None:
    value = 'A "quoted" \\ value'
    escaped = applescript_escape(value)
    assert escaped == 'A \\"quoted\\" \\\\ value'


def test_send_notification_uses_osascript_and_sound() -> None:
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return FakeCompletedProcess(returncode=0)

    send_notification("Mac Audit Agent", "Security Event", 'Camera "suspected"', sound="Glass", runner=runner)
    command, kwargs = calls[0]
    assert command[0] == "/usr/bin/osascript"
    assert "sound name \"Glass\"" in command[2]
    assert "subtitle \"Security Event\"" in command[2]


def test_send_alert_dialog_uses_osascript() -> None:
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return FakeCompletedProcess(returncode=0)

    send_alert_dialog("Mac Audit Agent - High Priority Event", "FaceTime observed", runner=runner)
    command, _kwargs = calls[0]
    assert command[0] == "/usr/bin/osascript"
    assert "display dialog" in command[2]


def test_send_alert_dialog_timeout_is_converted_to_failure() -> None:
    def runner(command, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=command, timeout=5, output="", stderr="timed out")

    result = send_alert_dialog("Mac Audit Agent - High Priority Event", "FaceTime observed", runner=runner)
    assert result.returncode == 124
    assert "timed out" in (result.stderr or "")


def test_high_event_uses_dialog_fallback_after_notification_failure(tmp_path: Path, monkeypatch) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    fallback_path = tmp_path / "monitor.log"
    monkeypatch.setattr("mac_audit_agent.notification_manager.FALLBACK_MONITOR_LOG", fallback_path)
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if "display notification" in command[2]:
            return FakeCompletedProcess(returncode=1, stderr="not allowed")
        return FakeCompletedProcess(returncode=0, stdout="dialog ok")

    manager = NotificationManager(db, runner=runner)
    preferences = manager.event_preferences()
    preferences["camera_activity_confirmed"]["notification_mode"] = "notification"
    manager.update_event_preferences(preferences)
    event = BackgroundMonitorEvent(
        event_id="fallback-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="camera_activity_confirmed",
        severity="high",
        source="process_poll",
        process_name="FaceTime",
        evidence="Camera activity confirmed for FaceTime.",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    sent, error = manager.notify(event)
    assert sent is True
    assert error == ""
    assert any("display notification" in command[2] for command in calls)
    assert any("display dialog" in command[2] for command in calls)
    assert "notification attempt" in fallback_path.read_text(encoding="utf-8")


def test_visible_alert_candidate_forces_overlay_even_when_notification_gate_is_false(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    service.notifications.update_settings(
        notify_all_events=False,
        notify_important_events=True,
        notify_min_severity="critical",
        notification_sound="Glass",
        duplicate_rate_limit_seconds=10,
        high_priority_alert_style="notification",
        notification_mode="notification",
        popup_only_severe_events=True,
        browser_capture_process_popup=False,
        show_visible_alerts=False,
        show_physical_session_alerts=True,
        show_usb_bluetooth_alerts=True,
        show_network_change_alerts=True,
        show_admin_persistence_alerts=True,
        show_apple_forecast_alerts=True,
        idle_activity_warning_minutes=2,
        cfaa_idle_warning_enabled=True,
        cooldown_seconds_per_category=600,
    )
    event = service._build_event(
        "lid_opened",
        "Lid opened transition detected.",
        severity="high",
        confidence="high",
        source="session_poll",
        process_name="WindowServer",
    )
    assert event.rule_id == "lid_opened"
    calls = []

    def fake_notify(alert_event, notify_force=False):
        calls.append(notify_force)
        alert_event.visible_alert_shown = True
        alert_event.notification_sent = True
        alert_event.notification_error = ""
        alert_event.notification_returncode = 0
        alert_event.notification_decision = "sent"
        return True, ""

    monkeypatch.setattr(service, "_notify_event", fake_notify)
    assert service.record_monitor_event(event) == event.event_id
    assert calls == [True]
    trace = service.db.get_event_alert_trace(event.event_id)
    assert trace is not None
    assert trace.alert_required is True
    assert trace.notification_policy_result == "sent"


def test_process_pending_notifications_survives_notification_timeout(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    monkeypatch.setattr(service, "_route_log_only_activity_overlay", lambda _event, mark_processed=True: False)
    monkeypatch.setattr(service, "_should_notify_event", lambda _event, notify_force=False: True)
    monkeypatch.setattr(service, "_notify_event", lambda _event, notify_force=False: (_ for _ in ()).throw(subprocess.TimeoutExpired(cmd=["/usr/bin/osascript"], timeout=5, output="", stderr="timed out")))
    event = service._build_event(
        "camera_activity_confirmed",
        "Camera activity confirmed for FaceTime.",
        severity="high",
        confidence="high",
        source="process_poll",
        process_name="FaceTime",
    )
    monkeypatch.setattr(service.db, "pending_background_monitor_events", lambda limit=10: [event])

    pending = service.process_pending_notifications(limit=10)

    assert pending == []
    assert service.db.get_background_monitor_state("notification_pipeline_broken", "") == "1"
    assert "Notifier delivery failed" in service.db.get_background_monitor_state("last_error", "")


def test_repeated_high_event_within_cooldown_is_suppressed(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    event = BackgroundMonitorEvent(
        event_id="cool-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="launchdaemon_added",
        severity="critical",
        source="baseline_diff",
        process_name="com.example.daemon",
        pid=321,
        evidence="New LaunchDaemon detected: com.example.daemon",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    assert manager.should_notify(event) is True
    db.set_background_monitor_state("notify:launchdaemon_added:com.example.daemon:New LaunchDaemon detected: com.example.daemon", event.timestamp)
    repeat = BackgroundMonitorEvent(**{**event.to_dict(), "event_id": "cool-2", "timestamp": "2026-04-24T12:01:00+00:00"})
    assert manager.should_notify(repeat) is False
    assert repeat.notification_decision == "suppressed_cooldown"
    assert repeat.cooldown_remaining_seconds > 0


def test_user_preference_can_disable_camera_popup(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    preferences = manager.event_preferences()
    preferences["camera_activity_confirmed"]["notify"] = False
    preferences["camera_activity_confirmed"]["notification_mode"] = "none"
    manager.update_event_preferences(preferences)
    event = BackgroundMonitorEvent(
        event_id="camera-disable-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="camera_activity_confirmed",
        severity="high",
        source="process_poll",
        process_name="FaceTime",
        evidence="Camera activity confirmed for FaceTime.",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    assert manager.should_notify(event) is False
    assert event.notification_decision == "disabled_by_user"


def test_user_can_enable_browser_capture_popups_manually(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db)
    preferences = manager.event_preferences()
    preferences["capture_capable_process_observed"] = {
        "enabled": True,
        "severity": "high",
        "notify": True,
        "cooldown_seconds": 300,
        "notification_mode": "dialog",
    }
    manager.update_event_preferences(preferences)
    manager.update_settings(
        notify_all_events=False,
        notify_important_events=True,
        notify_min_severity="info",
        notification_sound="Glass",
        duplicate_rate_limit_seconds=10,
        high_priority_alert_style="dialog",
        notification_mode="dialog",
        popup_only_severe_events=True,
        browser_capture_process_popup=True,
    )
    event = BackgroundMonitorEvent(
        event_id="browser-popup-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="capture_capable_process_observed",
        severity="medium",
        source="process_poll",
        process_name="Opera Helper (Renderer)",
        evidence="browser video_capture service observed for Opera Helper (Renderer)",
        confidence="low",
        recommendation="review",
        metadata_json="{}",
    )
    assert manager.should_notify(event) is True
    assert event.popup_allowed is True


def test_user_preference_can_promote_usb_event_to_popup(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    calls = []
    manager = NotificationManager(db, runner=lambda *args, **kwargs: calls.append(args[0]) or FakeCompletedProcess(returncode=0))
    preferences = manager.event_preferences()
    preferences["usb_device_connected"] = {
        "enabled": True,
        "severity": "high",
        "notify": True,
        "cooldown_seconds": 120,
        "notification_mode": "dialog",
    }
    manager.update_event_preferences(preferences)
    event = BackgroundMonitorEvent(
        event_id="usb-1",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="usb_device_connected",
        severity="medium",
        source="hardware",
        evidence="USB device connected.",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    assert manager.should_notify(event) is True
    sent, error = manager.notify(event)
    assert sent is True
    assert error == ""
    assert any("display dialog" in command[2] for command in calls)


def test_notification_failure_does_not_crash_and_logs_error(tmp_path: Path, monkeypatch) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    fallback_path = tmp_path / "monitor.log"
    monkeypatch.setattr("mac_audit_agent.notification_manager.FALLBACK_MONITOR_LOG", fallback_path)
    manager = NotificationManager(db, runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=1, stderr="denied"))
    event = BackgroundMonitorEvent(
        event_id="notify-fail",
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="major_security_event",
        severity="critical",
        source="ui",
        evidence="failure path",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    sent, error = manager.notify(event)
    assert sent is False
    assert "denied" in error
    content = fallback_path.read_text(encoding="utf-8")
    assert "denied" in content
    assert "notification attempt" in content
    assert event.notification_returncode == 1


def test_notification_readiness_keeps_security_alerting_ready_when_notification_center_fails(tmp_path: Path, monkeypatch) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    readiness_path = tmp_path / "app-support" / "MacAuditAgent" / "notification_readiness.json"
    monkeypatch.setattr("mac_audit_agent.notification_manager.NOTIFICATION_READINESS_PATH", readiness_path)
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_STATE_PATH", tmp_path / "overlay" / "security_overlay.json")
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_PID_PATH", tmp_path / "overlay" / "security_overlay.pid")

    def fake_runner(command, **_kwargs):
        if any("display notification" in part for part in command):
            return FakeCompletedProcess(returncode=1, stderr="notification failed")
        if any("display dialog" in part for part in command):
            return FakeCompletedProcess(returncode=0, stdout="button returned: Acknowledge")
        return FakeCompletedProcess(returncode=0, stdout="OK")

    manager = NotificationManager(db, runner=fake_runner)
    monkeypatch.setattr(manager, "_ensure_security_overlay_process", lambda: True)

    result = manager.readiness_check()

    assert result["overlay"]["success"] is True
    assert result["dialog"]["success"] is True
    assert result["notification_center"]["success"] is False
    assert result["overall_status"] == "PASS"
    assert result["security_alerting_ready"] is True
    assert db.get_background_monitor_state("notification_status", "").startswith("security alerts ready")
    assert readiness_path.exists()
    assert db.latest_notification_capabilities() is not None
    assert db.latest_alert_delivery_records(limit=1)[0].delivery_method_used in {"overlay", "dialog"}


def test_notification_readiness_overlay_passes_even_when_visible_alerts_disabled(tmp_path: Path, monkeypatch) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_STATE_PATH", tmp_path / "overlay" / "security_overlay.json")
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_PID_PATH", tmp_path / "overlay" / "security_overlay.pid")
    db.set_background_monitor_state("show_visible_alerts", "0")

    manager = NotificationManager(db, runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0, stdout="ok"))
    monkeypatch.setattr(manager, "_ensure_security_overlay_process", lambda: True)

    result = manager.readiness_check()

    assert result["overlay"]["success"] is True
    assert result["overall_status"] == "PASS"


def test_process_pending_notifications_advances_cursor_for_sequential_events(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    monkeypatch.setattr(service.notifications, "should_notify", lambda _event, force=False: False)
    first = service._build_event(
        "usb_device_connected",
        "USB device connected.",
        severity="info",
        confidence="high",
        source="hardware_detector",
        process_name="IOUSBHost",
    )
    second = service._build_event(
        "usb_device_removed",
        "USB device removed.",
        severity="medium",
        confidence="high",
        source="hardware_detector",
        process_name="IOUSBHost",
    )
    assert service.record_monitor_event(first) == first.event_id
    assert service.record_monitor_event(second) == second.event_id
    monkeypatch.setattr(service, "_route_log_only_activity_overlay", lambda _event, mark_processed=True: False)
    monkeypatch.setattr(service, "_should_notify_event", lambda _event, notify_force=False: True)

    def fake_notify(event, notify_force=False):
        event.visible_alert_shown = True
        event.notification_sent = True
        event.notification_error = ""
        event.notification_returncode = 0
        return True, ""

    monkeypatch.setattr(service, "_notify_event", fake_notify)

    notified = service.process_pending_notifications(limit=10)

    assert [event.event_id for event in notified] == [first.event_id, second.event_id]
    assert service.db.get_background_monitor_state("last_event_consumed", "") == second.event_id
    assert service.db.get_background_monitor_state("notifier_cursor_after", "") == second.event_id
    assert service.db.get_background_monitor_state("notification_pipeline_broken", "") == "0"


def test_usb_reconnect_observer_emits_immediately_for_first_topology_change(tmp_path: Path) -> None:
    monitor = HardwareMonitor(executor=lambda *_args, **_kwargs: (0, "", ""))
    observer = USBReconnectObserver(monitor, poll_seconds=0.1, quiet_window_seconds=0.0)
    previous = [{"vendor_id": "1", "product_id": "2", "serial": "A", "name": "USB Keyboard"}]
    current = []
    events = monitor.usb_connection_events(previous, current, timestamp="2026-06-01T12:00:00+00:00")
    assert [event.event_type for event in events] == ["usb_device_removed", "usb_inventory_changed"]


def test_camera_detection_never_records_images_or_audio() -> None:
    monitor = PrivacyMonitor()
    event = monitor._event(
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="camera_activity_suspected",
        severity="medium",
        source="process_correlation",
        evidence="Observed camera-capable app.",
        confidence="medium",
        recommendation="Review app usage.",
        metadata={"image": "raw", "audio": "raw", "processes": [{"name": "Zoom"}]},
    )
    metadata = json.loads(event.metadata_json)
    assert "image" not in metadata
    assert "audio" not in metadata


def test_camera_process_detector_detects_photo_booth_from_sample_ps_output() -> None:
    def executor(command):
        if command[:3] == ["/bin/ps", "-axo", "pid=,comm=,args="]:
            return 0, "123  /Applications/Photo Booth.app/Contents/MacOS/Photo Booth  /Applications/Photo Booth.app/Contents/MacOS/Photo Booth\n", ""
        return 1, "", "unsupported"

    monitor = PrivacyMonitor(executor=executor)
    snapshot = monitor.collect_snapshot()
    events = monitor.evaluate(None, snapshot)
    assert any(event.event_type == "capture_capable_process_observed" for event in events)
    assert any(event.process_name == "Photo Booth" for event in events)


def test_camera_process_detector_detects_facetime_from_sample_ps_output() -> None:
    def executor(command):
        if command[:3] == ["/bin/ps", "-axo", "pid=,comm=,args="]:
            return 0, "321  FaceTime  /System/Applications/FaceTime.app/Contents/MacOS/FaceTime\n", ""
        return 1, "", "unsupported"

    monitor = PrivacyMonitor(executor=executor)
    snapshot = monitor.collect_snapshot()
    events = monitor.evaluate(None, snapshot)
    assert any(event.event_type == "capture_capable_process_observed" and event.process_name == "FaceTime" for event in events)


def test_camera_process_detector_detects_facetime_app_path() -> None:
    def executor(command):
        if command[:3] == ["/bin/ps", "-axo", "pid=,comm=,args="]:
            return 0, "321  /System/Applications/FaceTime.app/Contents/MacOS/FaceTime  /System/Applications/FaceTime.app/Contents/MacOS/FaceTime\n", ""
        return 1, "", "unsupported"

    monitor = PrivacyMonitor(executor=executor)
    snapshot = monitor.collect_snapshot()
    events = monitor.evaluate(None, snapshot)
    assert any(event.event_type == "capture_capable_process_observed" and event.process_name == "FaceTime" for event in events)


def test_capture_process_disappearance_creates_closed_event() -> None:
    monitor = PrivacyMonitor(executor=lambda _command: (1, "", "unsupported"))
    previous = monitor.collect_snapshot()
    previous.capture_capable_processes = [{"pid": 123, "name": "Photo Booth", "command": "/Applications/Photo Booth.app/Contents/MacOS/Photo Booth", "args": "/Applications/Photo Booth.app/Contents/MacOS/Photo Booth", "redacted_args": "/Applications/Photo Booth.app/Contents/MacOS/Photo Booth"}]
    current = monitor.collect_snapshot()
    current.capture_capable_processes = []
    events = monitor.evaluate(previous, current)
    assert any(event.event_type == "capture_capable_process_closed" for event in events)


def test_camera_helper_process_creates_camera_activity_suspected() -> None:
    monitor = PrivacyMonitor(executor=lambda _command: (1, "", "unsupported"))
    previous = monitor.collect_snapshot()
    previous.camera_helper_processes = []
    current = monitor.collect_snapshot()
    current.camera_helper_processes = [{"pid": 777, "name": "VDCAssistant", "command": "/usr/libexec/VDCAssistant", "args": "/usr/libexec/VDCAssistant", "redacted_args": "/usr/libexec/VDCAssistant"}]
    current.capture_capable_processes = [{"pid": 123, "name": "Photo Booth", "command": "/Applications/Photo Booth.app/Contents/MacOS/Photo Booth", "args": "/Applications/Photo Booth.app/Contents/MacOS/Photo Booth", "redacted_args": "/Applications/Photo Booth.app/Contents/MacOS/Photo Booth"}]
    events = monitor.evaluate(previous, current)
    assert any(event.event_type == "camera_activity_suspected" for event in events)


def test_camera_active_api_emits_start_once_and_stop_transition() -> None:
    monitor = PrivacyMonitor(executor=lambda _command: (1, "", "unsupported"))
    inactive = PrivacyMonitorSnapshot(camera_active_api=False)
    active = PrivacyMonitorSnapshot(camera_active_api=True)
    started = monitor.evaluate(inactive, active)
    repeated = monitor.evaluate(active, active)
    stopped = monitor.evaluate(active, inactive)
    assert [event.event_type for event in started] == ["camera_activity_confirmed"]
    assert all(event.event_type != "camera_activity_confirmed" for event in repeated)
    assert [event.event_type for event in stopped] == ["camera_activity_stopped"]


def test_ps_parser_handles_paths_with_spaces() -> None:
    def executor(command):
        if command[:3] == ["/bin/ps", "-axo", "pid=,comm=,args="]:
            return 0, "123  Photo Booth  /Applications/Photo Booth.app/Contents/MacOS/Photo Booth\n", ""
        return 1, "", "unsupported"

    monitor = PrivacyMonitor(executor=executor)
    snapshot = monitor.collect_snapshot()
    assert snapshot.capture_capable_processes
    assert snapshot.capture_capable_processes[0]["name"] == "Photo Booth"


def test_microphone_process_detector_detects_zoom_from_sample_ps_output() -> None:
    def executor(command):
        if command[:3] == ["/bin/ps", "-axo", "pid=,comm=,args="]:
            return 0, "456  /Applications/zoom.us.app/Contents/MacOS/zoom.us  /Applications/zoom.us.app/Contents/MacOS/zoom.us\n", ""
        if command[:2] == ["launchctl", "print-disabled"]:
            return 1, "", "unsupported"
        return 1, "", "unsupported"

    monitor = PrivacyMonitor(executor=executor)
    snapshot = monitor.collect_snapshot()
    events = monitor.evaluate(None, snapshot)
    assert any(event.event_type == "microphone_activity_suspected" for event in events)
    assert any(event.process_name == "zoom.us" for event in events)


def test_privacy_monitor_emits_tcc_and_unified_log_indicators() -> None:
    monitor = PrivacyMonitor(executor=lambda _command: (1, "", "unsupported"))
    previous = None
    current = type("Snapshot", (), {
        "camera_authorization": "authorized",
        "microphone_authorization": "authorized",
        "camera_active_api": False,
        "capture_capable_processes": [],
        "camera_helper_processes": [],
        "microphone_processes": [],
        "suspicious_capture_processes": [],
        "screen_sharing_enabled": False,
        "screen_recording_permissions": [],
        "camera_permissions": [{"client": "com.example.CameraApp", "auth_value": 2}],
        "microphone_permissions": [{"client": "com.example.MicApp", "auth_value": 2}],
        "unified_log_indicators": [{"event_type": "camera_activity_suspected", "severity": "info", "confidence": "low", "evidence": "Unified log mentioned camera-related activity."}],
    })()
    events = monitor.evaluate(previous, current)
    event_types = [event.event_type for event in events]
    assert "camera_activity_suspected" in event_types
    assert "microphone_activity_suspected" in event_types
    assert any(event.source == "TCC" for event in events)
    assert any(event.source == "unified_log" for event in events)


def test_screen_detection_never_records_screen_content() -> None:
    monitor = SessionMonitor()
    event = monitor._event(
        timestamp="2026-04-24T12:00:00+00:00",
        event_type="screen_wake",
        severity="info",
        source="IOKit",
        evidence="Display woke.",
        confidence="high",
        recommendation="Review nearby events.",
        metadata={"screen_content": "frame-bytes", "image_bytes": "abc", "display_awake": True},
    )
    metadata = json.loads(event.metadata_json)
    assert "screen_content" not in metadata
    assert "image_bytes" not in metadata
    assert metadata["display_awake"] is True


def test_ioreg_clamshell_closed_output_creates_possible_lid_closed() -> None:
    outputs = {
        ("/usr/sbin/ioreg", "-r", "-n", "IODisplayWrangler", "-d", "1"): (0, '"CurrentPowerState" = 4', ""),
        ("/usr/bin/pmset", "-g", "ps"): (0, "AC Power", ""),
        ("/usr/bin/python3", "-c", "from Quartz import CGSessionCopyCurrentDictionary as f; import json; print(f() or {})"): (0, '{"CGSSessionScreenIsLocked"=0}', ""),
        ("/usr/bin/stat", "-f", "%Su", "/dev/console"): (0, "m\n", ""),
        ("/usr/sbin/ioreg", "-r", "-k", "AppleClamshellState", "-d", "4"): (0, '"AppleClamshellState" = Yes', ""),
        ("/usr/bin/pmset", "-g", "log"): (1, "", "unsupported"),
        ("/usr/bin/log", "show", "--last", "5m", "--style", "compact", "--predicate", 'eventMessage CONTAINS[c] "Display is turned off" OR eventMessage CONTAINS[c] "Display is turned on" OR eventMessage CONTAINS[c] "Wake" OR eventMessage CONTAINS[c] "Sleep"'): (1, "", "unsupported"),
        ("/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession", "-current"): (1, "", "unsupported"),
    }

    def executor(command):
        return outputs.get(tuple(command), (1, "", "unsupported"))

    monitor = SessionMonitor(executor=executor)
    previous = monitor.collect_snapshot()
    previous.clamshell_state = "open"
    current = monitor.collect_snapshot()
    events = monitor.evaluate(previous, current)
    assert any(event.event_type == "possible_lid_closed" for event in events)


def test_ioreg_clamshell_open_output_creates_possible_lid_opened() -> None:
    outputs = {
        ("/usr/sbin/ioreg", "-r", "-n", "IODisplayWrangler", "-d", "1"): (0, '"CurrentPowerState" = 4', ""),
        ("/usr/bin/pmset", "-g", "ps"): (0, "AC Power", ""),
        ("/usr/bin/python3", "-c", "from Quartz import CGSessionCopyCurrentDictionary as f; import json; print(f() or {})"): (0, '{"CGSSessionScreenIsLocked"=0}', ""),
        ("/usr/bin/stat", "-f", "%Su", "/dev/console"): (0, "m\n", ""),
        ("/usr/sbin/ioreg", "-r", "-k", "AppleClamshellState", "-d", "4"): (0, '"AppleClamshellState" = No', ""),
        ("/usr/bin/pmset", "-g", "log"): (1, "", "unsupported"),
        ("/usr/bin/log", "show", "--last", "5m", "--style", "compact", "--predicate", 'eventMessage CONTAINS[c] "Display is turned off" OR eventMessage CONTAINS[c] "Display is turned on" OR eventMessage CONTAINS[c] "Wake" OR eventMessage CONTAINS[c] "Sleep"'): (1, "", "unsupported"),
        ("/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession", "-current"): (1, "", "unsupported"),
    }

    def executor(command):
        return outputs.get(tuple(command), (1, "", "unsupported"))

    monitor = SessionMonitor(executor=executor)
    previous = monitor.collect_snapshot()
    previous.clamshell_state = "closed"
    current = monitor.collect_snapshot()
    events = monitor.evaluate(previous, current)
    assert any(event.event_type == "possible_lid_opened" for event in events)


def test_pmset_display_sleep_and_wake_log_markers_create_events() -> None:
    monitor = SessionMonitor(executor=lambda _command: (1, "", "unsupported"))
    previous = monitor.collect_snapshot()
    current = monitor.collect_snapshot()
    current.recent_markers = {
        "display_sleep|2026-04-25 00:00:00 +0000",
        "display_wake|2026-04-25 00:01:00 +0000",
    }
    events = monitor.evaluate(previous, current)
    assert any(event.event_type == "display_sleep" for event in events)
    assert any(event.event_type == "display_wake" for event in events)


def test_pmset_clamshell_sleep_and_lidopen_markers_create_lid_events() -> None:
    monitor = SessionMonitor(executor=lambda _command: (1, "", "unsupported"))
    markers = monitor._parse_pmset_markers(
        "2026-04-25 00:00:00 +0000 Sleep Entering Sleep state due to 'Clamshell Sleep'\n"
        "2026-04-25 00:01:00 +0000 Wake Wake from Normal Sleep [CDNVA] due to EC.LidOpen\n"
    )
    assert any(marker.startswith("possible_lid_closed|") for marker in markers)
    assert any(marker.startswith("possible_lid_opened|") for marker in markers)


def test_input_activity_resumed_after_idle_creates_medium_event() -> None:
    monitor = SessionMonitor(executor=lambda _command: (1, "", "unsupported"))
    previous = SessionSnapshot(hid_idle_seconds=305.0)
    current = SessionSnapshot(hid_idle_seconds=1.0)
    events = monitor.evaluate(previous, current)
    assert any(event.event_type == "input_activity_resumed_after_idle" for event in events)
    event = next(event for event in events if event.event_type == "input_activity_resumed_after_idle")
    assert event.severity == "medium"
    assert "idle for at least 120 seconds" in event.evidence


def test_input_activity_idle_started_creates_aggregate_info_event() -> None:
    monitor = SessionMonitor(executor=lambda _command: (1, "", "unsupported"))
    events = monitor.evaluate(SessionSnapshot(hid_idle_seconds=10.0), SessionSnapshot(hid_idle_seconds=121.0))
    event = next(event for event in events if event.event_type == "input_activity_idle_started")
    assert event.severity == "info"
    assert "Aggregate keyboard, mouse, and trackpad input" in event.evidence


def test_session_state_observer_enqueues_lid_events_quickly() -> None:
    snapshots = [
        SessionSnapshot(display_state="awake", system_power_state="awake", session_locked=False, console_user="m", clamshell_state="open"),
        SessionSnapshot(display_state="awake", system_power_state="awake", session_locked=False, console_user="m", clamshell_state="closed"),
    ]
    monitor = SessionMonitor(executor=lambda _command: (1, "", "unsupported"))
    monitor.collect_snapshot = lambda: snapshots.pop(0) if snapshots else SessionSnapshot(display_state="awake", system_power_state="awake", session_locked=False, console_user="m", clamshell_state="closed")
    observer = SessionStateObserver(monitor, poll_seconds=0.01)
    observer.start()
    try:
        import time
        deadline = time.monotonic() + 1
        events = []
        while time.monotonic() < deadline and not events:
            time.sleep(0.02)
            events = observer.drain()
    finally:
        observer.stop()
    assert any(event.event_type == "possible_lid_closed" for event in events)


def test_console_user_change_creates_session_transition_event() -> None:
    monitor = SessionMonitor(executor=lambda _command: (1, "", "unsupported"))
    previous = monitor.collect_snapshot()
    previous.console_user = ""
    current = monitor.collect_snapshot()
    current.console_user = "m"
    events = monitor.evaluate(previous, current)
    assert any(event.event_type == "screen_unlocked" for event in events)


def test_missing_cgsession_does_not_crash_and_session_locked_is_unknown(tmp_path: Path, monkeypatch) -> None:
    outputs = {
        ("/usr/bin/python3", "-c", "from Quartz import CGSessionCopyCurrentDictionary as f; import json; print(f() or {})"): (127, "", "command not found: /usr/bin/python3"),
        ("/usr/bin/pmset", "-g", "assertions"): (127, "", "command not found: /usr/bin/pmset"),
        ("/usr/bin/log", "show", "--last", "2m", "--style", "compact", "--predicate", 'eventMessage CONTAINS[c] "locked" OR eventMessage CONTAINS[c] "unlocked"'): (127, "", "command not found: /usr/bin/log"),
    }

    def executor(command):
        return outputs.get(tuple(command), (127, "", f"command not found: {command[0]}"))

    monkeypatch.setattr("mac_audit_agent.session_monitor.Path.exists", lambda self: False if str(self).endswith("/CGSession") else True)
    monitor = SessionMonitor(executor=executor)
    assert monitor._session_locked() is None


def test_collect_detector_snapshot_returns_partial_data_if_session_detector_fails(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    monkeypatch.setattr(
        service.privacy_monitor,
        "collect_snapshot",
        lambda: type("Snapshot", (), {"capture_capable_processes": [{"name": "FaceTime", "pid": 4242}], "screen_sharing_enabled": False})(),
    )
    monkeypatch.setattr(service.session_monitor, "collect_snapshot", lambda: (_ for _ in ()).throw(RuntimeError("session failed")))
    snapshot = service.collect_detector_snapshot()
    assert snapshot["capture_capable_processes"] == [{"name": "FaceTime", "pid": 4242}]


def test_snapshot_exits_successfully_when_cgsession_missing(tmp_path: Path, monkeypatch, capsys) -> None:
    class FakeService:
        def __init__(self, db_path, poll_interval_seconds=5, record_startup=True):
            self.db = AuditDatabase(db_path, tmp_path / "logs")

        def collect_detector_snapshot(self):
            return {
                "capture_capable_processes": [{"name": "FaceTime", "pid": 4242}],
                "display_state": "unknown",
                "clamshell_state": "unknown",
                "session_locked": None,
                "screen_sharing_enabled": False,
                "remote_login_enabled": False,
                "db_path": str(tmp_path / "audit.sqlite"),
            }

    monkeypatch.setattr("mac_audit_agent.monitor.BackgroundMonitorService", FakeService)
    exit_code = monitor_main(["--db-path", str(tmp_path / "audit.sqlite"), "--snapshot"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"session_locked": null' in captured.out


def test_suspicious_process_detector_detects_tmp_update_helper(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    monkeypatch.setattr(service.notifications, "should_notify", lambda _event: False)
    monkeypatch.setattr(service, "_list_processes", lambda: [{"pid": 321, "name": "update_helper", "command": "/tmp/update_helper", "args": "/tmp/update_helper 120"}])
    events = service._run_suspicious_process_detector()
    assert events
    assert events[0].event_type == "suspicious_process_observed"
    assert events[0].process_name == "update_helper"


def test_background_monitor_panel_handles_running_and_stopped_states(tmp_path: Path) -> None:
    from unittest.mock import patch

    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    with patch("mac_audit_agent.ui.background_monitor_panel.is_pid_alive", return_value=False), patch(
        "mac_audit_agent.ui.background_monitor_panel.is_heartbeat_fresh", return_value=False
    ):
        panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
        assert "stopped" in panel.status_label.text()
        assert "LaunchAgent installed: yes" in panel.health_panel.toPlainText()
        assert str(FALLBACK_MONITOR_LOG.expanduser().resolve()) in panel.health_panel.toPlainText()
    with patch("mac_audit_agent.ui.background_monitor_panel.is_pid_alive", return_value=True):
        panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=True))
        assert "running" in panel.status_label.text()
    assert app is not None


def test_background_monitor_panel_show_context_button_enables_for_selected_event(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    event = BackgroundMonitorEvent(
        event_id="event-context",
        timestamp="2026-05-31T12:10:00+00:00",
        event_type="vpn_connected",
        severity="info",
        source="network_state_observer",
        evidence="VPN connection assigned: utun3 10.0.0.2.",
        confidence="high",
        recommendation="Confirm the VPN connection is expected.",
        metadata_json="{}",
    )
    db.record_monitor_event(event)
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    panel.refresh_events()
    panel.events_table.selectRow(0)
    assert panel.show_context_button.text() == "Show Context"
    assert panel.show_context_button.isEnabled()
    assert app is not None


def test_background_monitor_panel_reads_events_from_shared_system_db_in_system_mode(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    user_db = AuditDatabase(tmp_path / "user.sqlite", tmp_path / "user-logs")
    shared_db_path = tmp_path / "system" / "mac_audit_agent.sqlite3"
    shared_db = AuditDatabase(shared_db_path, tmp_path / "system-logs")
    user_db.set_background_monitor_state("monitor_mode", "system")
    user_db.set_background_monitor_state("monitor_install_mode", "system")
    shared_db.record_monitor_event(
        BackgroundMonitorEvent(
            event_id="shared-system-event",
            timestamp="2026-06-02T12:00:00+00:00",
            event_type="possible_lid_opened",
            severity="high",
            source="session_detector",
            evidence="Shared system DB lid open event.",
        )
    )
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.default_monitor_db_path", lambda scope=None: shared_db_path)

    panel = BackgroundMonitorPanel(user_db, FakeLaunchAgent(installed=True, running=False))
    panel.refresh_events()

    assert "possible_lid_opened" in panel.events_table.item(0, 1).text()
    assert app is not None


def test_background_monitor_panel_processes_pending_notifications_from_shared_system_db_in_system_mode(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    user_db = AuditDatabase(tmp_path / "user.sqlite", tmp_path / "user-logs")
    shared_db_path = tmp_path / "system" / "mac_audit_agent.sqlite3"
    shared_db = AuditDatabase(shared_db_path, tmp_path / "system-logs")
    user_db.set_background_monitor_state("monitor_mode", "system")
    user_db.set_background_monitor_state("monitor_install_mode", "system")
    shared_db.record_monitor_event(
        BackgroundMonitorEvent(
            event_id="shared-system-visible-alert",
            timestamp="2026-06-02T12:05:00+00:00",
            event_type="possible_lid_closed",
            severity="high",
            source="session_detector",
            evidence="Shared system DB lid close event.",
            confidence="high",
            recommendation="review",
            metadata_json="{}",
            rule_id="possible_lid_closed",
            trigger_rule_id="possible_lid_closed",
            rule_name="possible_lid_closed",
            trigger_rule_name="possible_lid_closed",
        )
    )
    panel = BackgroundMonitorPanel(user_db, FakeLaunchAgent(installed=True, running=False))
    calls = []

    class FakeNotificationService:
        def __init__(self) -> None:
            self.notifications = type(
                "Notifier",
                (),
                {
                    "status": lambda self: "available via AppleScript",
                    "settings": lambda self: {
                        "notify_all_events": False,
                        "notify_important_events": True,
                        "notify_min_severity": "info",
                        "notification_sound": "Glass",
                        "duplicate_rate_limit_seconds": 10,
                        "popup_only_severe_events": True,
                        "browser_capture_process_popup": False,
                        "show_visible_alerts": True,
                        "show_physical_session_alerts": True,
                        "show_usb_bluetooth_alerts": True,
                        "show_network_change_alerts": True,
                        "show_admin_persistence_alerts": True,
                        "show_apple_forecast_alerts": True,
                        "idle_activity_warning_minutes": 2,
                        "cfaa_idle_warning_enabled": True,
                        "cooldown_seconds_per_category": 600,
                    },
                },
            )()

        def process_pending_notifications(self, limit: int = 200):
            calls.append(limit)
            return []

    monkeypatch.setattr(panel, "_active_monitor_db", lambda: shared_db)
    monkeypatch.setattr(panel, "_notification_service", lambda: FakeNotificationService())

    panel.refresh()

    assert calls
    assert app is not None


def test_background_monitor_panel_prefers_pid_or_fresh_heartbeat_for_running(tmp_path: Path, monkeypatch) -> None:
    class ContradictoryLaunchAgent(FakeLaunchAgent):
        def status(self):
            status = super().status()
            status.process_pid = 4098
            status.running = False
            status.loaded = True
            return status

    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.is_pid_alive", lambda pid: pid == 4098)
    panel = BackgroundMonitorPanel(db, ContradictoryLaunchAgent(installed=True, running=False))
    text = panel.health_panel.toPlainText()
    assert "Monitor running: yes" in text
    assert "Monitor status: running; launchctl state parse uncertain" in text
    assert app is not None


def test_background_monitor_panel_detects_orphan_process(tmp_path: Path, monkeypatch) -> None:
    class OrphanLaunchAgent(FakeLaunchAgent):
        def status(self):
            status = super().status()
            status.loaded = False
            status.running = False
            status.process_pid = 4098
            return status

    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.is_pid_alive", lambda pid: pid == 4098)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.is_heartbeat_fresh", lambda *_args, **_kwargs: False)
    panel = BackgroundMonitorPanel(db, OrphanLaunchAgent(installed=True, running=False))
    text = panel.health_panel.toPlainText()
    assert "Monitor status: orphan monitor process" in text
    assert app is not None


def test_real_event_alert_trace_records_policy_and_overlay(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", mode="user-notifier", record_startup=False)
    monkeypatch.setattr(service.notifications, "runner", lambda *args, **kwargs: FakeCompletedProcess(returncode=0, stdout="ok", stderr=""))
    monkeypatch.setattr(service.notifications, "_ensure_security_overlay_process", lambda: True)
    monkeypatch.setattr(service.notifications, "_security_overlay_pid_alive", lambda: True)
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_STATE_PATH", tmp_path / "security_overlay.json")
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_PID_PATH", tmp_path / "security_overlay.pid")

    event = service.simulate_event(
        "usb_device_connected",
        "USB device connected during real-event trace test.",
        severity="info",
        confidence="high",
        process_name="real_usb_detector",
        pid=321,
        notify_force=True,
    )

    trace = service.db.get_event_alert_trace(event.event_id)
    assert trace is not None
    assert trace.stored_success is True
    assert trace.notification_policy_checked is True
    assert trace.notification_policy_result == "sent"
    assert trace.notification_policy_reason in {"forced", "cooldown_elapsed", "first_severe_event"}
    assert trace.overlay_dispatch_attempted is True
    assert trace.overlay_dispatch_result == "SUCCESS"
    assert trace.visible_alert_id == event.event_id
    assert app is not None


def test_process_pending_notifications_tracks_notifier_consumption(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", mode="user-notifier", record_startup=False)
    monkeypatch.setattr(service.notifications, "should_notify", lambda event, force=False: True)
    monkeypatch.setattr(service.notifications, "runner", lambda *args, **kwargs: FakeCompletedProcess(returncode=0, stdout="ok", stderr=""))
    monkeypatch.setattr(service.notifications, "_ensure_security_overlay_process", lambda: True)
    monkeypatch.setattr(service.notifications, "_security_overlay_pid_alive", lambda: True)
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_STATE_PATH", tmp_path / "security_overlay.json")
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_PID_PATH", tmp_path / "security_overlay.pid")

    event = BackgroundMonitorEvent(
        event_id="trace-consume-1",
        timestamp=utc_now_iso(),
        event_type="lid_opened",
        severity="high",
        source="lid_detector",
        process_name="lid_detector",
        pid=1,
        evidence="Lid opened during notifier consumption test.",
        confidence="high",
        recommendation="review timeline",
        rule_id="lid_opened",
        rule_name="lid_opened",
        trigger_rule_id="lid_opened",
        trigger_rule_name="lid_opened",
        trigger_source="session_detector",
    )
    service.db.record_monitor_event(event)
    service.db.record_event_alert_trace(
        EventAlertTrace(
            trace_id=f"trace-{event.event_id}",
            event_id=event.event_id,
            event_type=event.event_type,
            original_event_type=event.event_type,
            normalized_event_type=event.event_type,
            detector_source=event.source,
            created_at=event.timestamp,
            stored_db_path=str(service.db.path),
            stored_success=True,
            severity_before_policy=event.severity,
            severity_after_policy=event.severity,
        )
    )

    notified = service.process_pending_notifications()

    trace = service.db.get_event_alert_trace(event.event_id)
    assert trace is not None
    assert trace.notifier_seen is True
    assert trace.notifier_db_path == str(service.db.path)
    assert trace.overlay_dispatch_attempted is True
    assert service.db.get_background_monitor_state("notifier_running", "0") == "1"
    assert service.db.get_background_monitor_state("notifier_db_path", "") == str(service.db.path)
    assert service.db.get_background_monitor_state("events_found_last_poll", "0") == "1"
    assert service.db.get_background_monitor_state("events_alerted_last_poll", "0") == "1"
    assert service.db.get_background_monitor_state("overlay_alive", "0") == "1"
    assert notified
    assert app is not None


def test_background_monitor_panel_prefers_system_database_when_system_daemon_is_loaded(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    user_db = AuditDatabase(tmp_path / "user.sqlite", tmp_path / "logs")
    system_db_path = tmp_path / "system.sqlite"
    panel = BackgroundMonitorPanel(user_db, FakeLaunchAgent(installed=True, running=False))
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.default_monitor_db_path", lambda scope=None: system_db_path if scope == "system" else tmp_path / "user.sqlite")
    monkeypatch.setattr(panel.system_launch_agent, "status", lambda: _monitor_status(installed=True, loaded=True, running=True, process_pid=4242))

    active_db = panel._active_monitor_db()

    assert active_db.path == system_db_path
    assert app is not None


def test_background_monitor_panel_shows_loaded_but_crashed_and_stderr_tail(tmp_path: Path, monkeypatch) -> None:
    class CrashedLaunchAgent(FakeLaunchAgent):
        def status(self):
            status = super().status()
            status.loaded = True
            status.running = False
            status.process_pid = None
            return status

    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.set_background_monitor_state("last_heartbeat", "2000-04-25T00:00:00+00:00")
    stderr_path = tmp_path / "background_monitor.stderr.log"
    stderr_path.write_text("traceback line 1\ntraceback line 2\n", encoding="utf-8")
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.STDERR_MONITOR_LOG", stderr_path)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.is_pid_alive", lambda _pid: False)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.is_heartbeat_fresh", lambda *_args, **_kwargs: False)
    panel = BackgroundMonitorPanel(db, CrashedLaunchAgent(installed=True, running=False))
    text = panel.health_panel.toPlainText()
    assert "Monitor status: loaded but crashed or exited" in text
    assert "traceback line 2" in text
    assert app is not None


def test_restart_monitor_catches_launchctl_failures(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    messages = []
    monkeypatch.setattr(panel.launch_agent, "stop", lambda: None)
    monkeypatch.setattr(panel.launch_agent, "start", lambda: (_ for _ in ()).throw(RuntimeError("Command failed: /bin/launchctl kickstart -k gui/501/com.mac-audit-agent.monitor\nstderr:\nboom")))
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.warning", lambda *args, **kwargs: messages.append(args[2]))
    panel.restart_monitor()
    assert "launchctl" in messages[0]
    assert app is not None


def test_clear_monitor_logs_truncates_files_not_delete(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    fallback_path = tmp_path / "monitor.log"
    stdout_path = tmp_path / "background_monitor.stdout.log"
    stderr_path = tmp_path / "background_monitor.stderr.log"
    for path in [fallback_path, stdout_path, stderr_path]:
        path.write_text("existing log data", encoding="utf-8")
    monkeypatch.setattr(panel, "_monitor_log_paths", lambda: [fallback_path, stdout_path, stderr_path])
    monkeypatch.setattr("mac_audit_agent.monitor.FALLBACK_MONITOR_LOG", fallback_path)
    monkeypatch.setattr("mac_audit_agent.monitor.STDOUT_MONITOR_LOG", stdout_path)
    monkeypatch.setattr(panel, "_prompt_clear_monitor_logs", lambda: {"clear_event_history": False})
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.information", lambda *args, **kwargs: None)

    panel.clear_monitor_logs()

    for path in [fallback_path, stdout_path, stderr_path]:
        assert path.exists()
    assert "Monitor logs cleared by user" in fallback_path.read_text(encoding="utf-8")
    assert "Monitor logs cleared by user" in stdout_path.read_text(encoding="utf-8")
    assert stderr_path.read_text(encoding="utf-8") == ""
    assert app is not None


def test_clear_monitor_log_files_helper_truncates_and_recreates_missing_files(tmp_path: Path, monkeypatch) -> None:
    fallback_path = tmp_path / "monitor.log"
    stdout_path = tmp_path / "background_monitor.stdout.log"
    stderr_path = tmp_path / "background_monitor.stderr.log"
    fallback_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    fallback_path.write_text("fallback", encoding="utf-8")
    stdout_path.write_text("stdout", encoding="utf-8")
    stderr_path.write_text("stderr", encoding="utf-8")
    monkeypatch.setattr("mac_audit_agent.monitor.FALLBACK_MONITOR_LOG", fallback_path)
    monkeypatch.setattr("mac_audit_agent.monitor.STDOUT_MONITOR_LOG", stdout_path)
    monkeypatch.setattr("mac_audit_agent.monitor.STDERR_MONITOR_LOG", stderr_path)

    cleared = clear_monitor_log_files()

    assert cleared == [fallback_path, stdout_path, stderr_path]
    assert fallback_path.read_text(encoding="utf-8") == ""
    assert stdout_path.read_text(encoding="utf-8") == ""
    assert stderr_path.read_text(encoding="utf-8") == ""


def test_clear_monitor_logs_button_is_present(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    assert panel.clear_logs_button.text() == "Clear Monitor Logs"
    assert app is not None


def test_clear_monitor_logs_recreates_missing_files(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    fallback_path = tmp_path / "monitor.log"
    stdout_path = tmp_path / "background_monitor.stdout.log"
    stderr_path = tmp_path / "background_monitor.stderr.log"
    monkeypatch.setattr(panel, "_monitor_log_paths", lambda: [fallback_path, stdout_path, stderr_path])
    monkeypatch.setattr("mac_audit_agent.monitor.FALLBACK_MONITOR_LOG", fallback_path)
    monkeypatch.setattr("mac_audit_agent.monitor.STDOUT_MONITOR_LOG", stdout_path)
    monkeypatch.setattr(panel, "_prompt_clear_monitor_logs", lambda: {"clear_event_history": False})
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.information", lambda *args, **kwargs: None)

    panel.clear_monitor_logs()

    for path in [fallback_path, stdout_path, stderr_path]:
        assert path.exists()
    assert app is not None


def test_clear_monitor_logs_db_clear_removes_only_monitor_events_and_preserves_schema(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    event = BackgroundMonitorEvent(
        event_id="clear-me",
        timestamp="2026-04-25T00:00:00+00:00",
        event_type="monitor_test_event",
        severity="info",
        source="ui",
        evidence="clear me",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    db.record_monitor_event(event)
    fallback_path = tmp_path / "monitor.log"
    stdout_path = tmp_path / "background_monitor.stdout.log"
    monkeypatch.setattr(panel, "_monitor_log_paths", lambda: [fallback_path, stdout_path, tmp_path / "background_monitor.stderr.log"])
    monkeypatch.setattr("mac_audit_agent.monitor.FALLBACK_MONITOR_LOG", fallback_path)
    monkeypatch.setattr("mac_audit_agent.monitor.STDOUT_MONITOR_LOG", stdout_path)
    monkeypatch.setattr(panel, "_prompt_clear_monitor_logs", lambda: {"clear_event_history": True})
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.information", lambda *args, **kwargs: None)

    panel.clear_monitor_logs()

    assert db.latest_monitor_events(limit=10) == []
    table = db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='background_monitor_events'"
    ).fetchone()
    assert table is not None
    db.record_monitor_event(event)
    assert db.latest_monitor_events(limit=1)[0].event_id == "clear-me"
    assert app is not None


def test_monitor_continues_logging_after_clear(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    fallback_path = tmp_path / "monitor.log"
    stdout_path = tmp_path / "background_monitor.stdout.log"
    monkeypatch.setattr(panel, "_monitor_log_paths", lambda: [fallback_path, stdout_path, tmp_path / "background_monitor.stderr.log"])
    monkeypatch.setattr("mac_audit_agent.monitor.FALLBACK_MONITOR_LOG", fallback_path)
    monkeypatch.setattr("mac_audit_agent.monitor.STDOUT_MONITOR_LOG", stdout_path)
    monkeypatch.setattr(panel, "_prompt_clear_monitor_logs", lambda: {"clear_event_history": False})
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.information", lambda *args, **kwargs: None)

    panel.clear_monitor_logs()
    panel.service._write_log_line("post-clear log entry")

    assert "post-clear log entry" in fallback_path.read_text(encoding="utf-8")
    assert app is not None


def test_clear_monitor_logs_ui_reflects_cleared_events(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    event = BackgroundMonitorEvent(
        event_id="clear-ui",
        timestamp="2026-04-25T00:00:00+00:00",
        event_type="monitor_test_event",
        severity="info",
        source="ui",
        evidence="clear ui",
        confidence="high",
        recommendation="review",
        metadata_json="{}",
    )
    db.record_monitor_event(event)
    panel.refresh_events()
    monkeypatch.setattr(panel, "_monitor_log_paths", lambda: [tmp_path / "monitor.log", tmp_path / "background_monitor.stdout.log", tmp_path / "background_monitor.stderr.log"])
    monkeypatch.setattr("mac_audit_agent.monitor.FALLBACK_MONITOR_LOG", tmp_path / "monitor.log")
    monkeypatch.setattr("mac_audit_agent.monitor.STDOUT_MONITOR_LOG", tmp_path / "background_monitor.stdout.log")
    monkeypatch.setattr(panel, "_prompt_clear_monitor_logs", lambda: {"clear_event_history": True})
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.information", lambda *args, **kwargs: None)

    panel.clear_monitor_logs()

    assert panel.events_table.item(0, 0).text() == "No recent events"
    assert app is not None


def test_clear_monitor_logs_confirmation_required(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    fallback_path = tmp_path / "monitor.log"
    fallback_path.write_text("keep me", encoding="utf-8")
    monkeypatch.setattr(panel, "_monitor_log_paths", lambda: [fallback_path, tmp_path / "background_monitor.stdout.log", tmp_path / "background_monitor.stderr.log"])
    monkeypatch.setattr(panel, "_prompt_clear_monitor_logs", lambda: None)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.information", lambda *args, **kwargs: None)

    panel.clear_monitor_logs()

    assert fallback_path.read_text(encoding="utf-8") == "keep me"
    assert app is not None


def test_monitor_service_self_test_and_test_event_are_logged(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    monkeypatch.setattr(service.notifications, "notify", lambda _event: (True, ""))
    self_test = service.run_self_test()
    test_event = service.generate_test_event()
    events = service.db.latest_monitor_events(limit=10)
    assert self_test.event_type == "monitor_self_test"
    assert self_test.evidence == "User triggered monitor self-test."
    assert self_test.notification_sent is True
    assert test_event.event_type == "monitor_test_event"
    assert {item.event_type for item in events} >= {"monitor_self_test", "monitor_test_event"}


def test_monitor_service_fallback_log_written_when_db_write_fails(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    fallback_path = tmp_path / "monitor.log"
    monkeypatch.setattr("mac_audit_agent.monitor.FALLBACK_MONITOR_LOG", fallback_path)
    service._ensure_fallback_log_path()
    monkeypatch.setattr(service.db, "record_monitor_event", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("db down")))
    monkeypatch.setattr(service.notifications, "should_notify", lambda _event: False)
    service.generate_test_event()
    content = fallback_path.read_text(encoding="utf-8")
    assert "db write failed" in content


def test_fallback_log_path_created_and_contains_startup_heartbeat_event_and_error(tmp_path: Path, monkeypatch) -> None:
    fallback_path = tmp_path / "Library" / "Logs" / "MacAuditAgent" / "monitor.log"
    monkeypatch.setattr("mac_audit_agent.monitor.FALLBACK_MONITOR_LOG", fallback_path)
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    monkeypatch.setattr(service.notifications, "should_notify", lambda _event: False)

    service.run_once()
    service.generate_test_event()

    def boom():
        raise RuntimeError("privacy collector failed")

    monkeypatch.setattr(service.privacy_monitor, "collect_snapshot", boom)
    service.run_once()

    assert fallback_path.exists()
    assert fallback_path.parent.exists()
    content = fallback_path.read_text(encoding="utf-8")
    assert "startup: monitor initialized" in content
    assert "heartbeat:" in content
    assert "event: type=monitor_test_event" in content
    assert "run_once error: privacy collector failed" in content


def test_simulated_camera_event_is_logged_and_marked_simulated(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    monkeypatch.setattr(service.notifications, "notify", lambda _event: (True, ""))
    event = service.simulate_event("camera_activity_suspected", "Simulated camera activity suspected.", severity="medium")
    saved = service.db.latest_monitor_events(limit=1)[0]
    assert event.event_type == "camera_activity_suspected"
    assert saved.simulated is True
    assert saved.notification_sent is False
    assert saved.notification_decision == "log_only"


def test_simulate_event_calls_notification(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    calls = []
    monkeypatch.setattr(service.notifications, "notify", lambda event: calls.append(event.event_type) or (True, ""))
    service.simulate_event("camera_activity_confirmed", "Simulated confirmed camera activity.", severity="high")
    assert calls == ["camera_activity_confirmed"]


def test_facetime_capture_process_event_is_logged_silently_by_default(tmp_path: Path, monkeypatch) -> None:
    def executor(command):
        if command[:3] == ["/bin/ps", "-axo", "pid=,comm=,args="]:
            return 0, "321  FaceTime  /System/Applications/FaceTime.app/Contents/MacOS/FaceTime\n", ""
        if command[:3] == ["/bin/launchctl", "print", f"{launchctl_target()}/com.mac-audit-agent.monitor"]:
            return 1, "", "not loaded"
        return 1, "", "unsupported"

    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5, executor=executor)
    monkeypatch.setattr("mac_audit_agent.monitor.FALLBACK_MONITOR_LOG", tmp_path / "monitor.log")
    monkeypatch.setattr("mac_audit_agent.monitor.STDOUT_MONITOR_LOG", tmp_path / "background_monitor.stdout.log")
    monkeypatch.setattr(service, "_run_session_detector", lambda: [])
    monkeypatch.setattr(service, "_run_sharing_detector", lambda: [])
    monkeypatch.setattr(service, "_run_suspicious_process_detector", lambda: [])
    notifications = []
    monkeypatch.setattr(service.notifications, "notify", lambda event: notifications.append(event.event_type) or (True, ""))

    events = service.run_once()

    assert any(event.event_type == "capture_capable_process_observed" and event.process_name == "FaceTime" for event in events)
    assert notifications == []
    saved = service.db.latest_monitor_events(limit=10)
    assert any(
        event.event_type == "capture_capable_process_observed"
        and event.process_name == "FaceTime"
        and not event.notification_sent
        and event.notification_decision == "log_only"
        for event in saved
    )


def test_first_camera_detector_run_emits_initial_capture_events_from_snapshot(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    snapshot = PrivacyMonitorSnapshot(
        capture_capable_processes=[
            {
                "pid": 321,
                "name": "FaceTime",
                "command": "/System/Applications/FaceTime.app/Contents/MacOS/FaceTime",
                "args": "/System/Applications/FaceTime.app/Contents/MacOS/FaceTime",
                "redacted_args": "/System/Applications/FaceTime.app/Contents/MacOS/FaceTime",
            }
        ],
        raw_ps_lines=["321  FaceTime  /System/Applications/FaceTime.app/Contents/MacOS/FaceTime"],
    )
    monkeypatch.setattr(service.privacy_monitor, "collect_snapshot", lambda: snapshot)
    monkeypatch.setattr(service.privacy_monitor, "evaluate", lambda previous, current: [])
    monkeypatch.setattr("mac_audit_agent.monitor.FALLBACK_MONITOR_LOG", tmp_path / "monitor.log")
    monkeypatch.setattr("mac_audit_agent.monitor.STDOUT_MONITOR_LOG", tmp_path / "background_monitor.stdout.log")
    notifications = []
    monkeypatch.setattr(service.notifications, "notify", lambda event: notifications.append(event.event_type) or (True, ""))

    events = service._run_camera_detector()

    assert any(event.event_type == "capture_capable_process_observed" and event.process_name == "FaceTime" for event in events)
    assert notifications == []
    saved = service.db.latest_monitor_events(limit=10)
    assert any(
        event.event_type == "capture_capable_process_observed"
        and event.process_name == "FaceTime"
        and event.notification_decision == "log_only"
        for event in saved
    )


def test_event_still_records_when_notification_fails(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    monkeypatch.setattr("mac_audit_agent.monitor.FALLBACK_MONITOR_LOG", tmp_path / "monitor.log")
    monkeypatch.setattr(service.notifications, "should_notify", lambda _event: True)
    monkeypatch.setattr(
        service.notifications,
        "notify",
        lambda event: (
            setattr(event, "notification_sent", False),
            setattr(event, "notification_error", "denied"),
            setattr(event, "notification_returncode", 1),
            (False, "denied"),
        )[-1],
    )
    event = service._build_event(
        "capture_capable_process_observed",
        "Capture-capable process observed: FaceTime",
        severity="high",
        confidence="low",
        source="process_poll",
        process_name="FaceTime",
        pid=321,
    )
    event_id = service.record_monitor_event(event)
    assert event_id is not None
    saved = service.db.latest_monitor_events(limit=1)[0]
    assert saved.notification_sent is False
    assert saved.notification_error == "denied"
    assert saved.notification_returncode == 1


def test_simulated_lid_closed_and_opened_events_are_logged(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    monkeypatch.setattr(service.notifications, "notify", lambda _event: (True, ""))
    service.simulate_event("lid_closed", "Simulated lid close event.")
    service.simulate_event("lid_opened", "Simulated lid open event.")
    types = {item.event_type for item in service.db.latest_monitor_events(limit=10)}
    assert "possible_lid_closed" in types
    assert "possible_lid_opened" in types


def test_detector_exception_is_logged_and_loop_continues(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    monkeypatch.setattr(service, "_run_camera_detector", lambda: (_ for _ in ()).throw(RuntimeError("camera blew up")))
    monkeypatch.setattr(service, "_run_session_detector", lambda: [])
    monkeypatch.setattr(service, "_run_sharing_detector", lambda: [])
    monkeypatch.setattr(service, "_run_suspicious_process_detector", lambda: [service._build_event("major_security_event", "detector continued", severity="critical", confidence="high", source="test")])
    monkeypatch.setattr(service.notifications, "notify", lambda _event: (True, ""))
    events = service.run_once()
    assert any(event.event_type == "major_security_event" for event in events)
    assert "camera_process_detector" in service.db.get_background_monitor_status().detector_errors


def test_monitor_loop_records_heartbeat(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=5)
    monkeypatch.setattr(service, "_run_camera_detector", lambda: [])
    monkeypatch.setattr(service, "_run_session_detector", lambda: [])
    monkeypatch.setattr(service, "_run_sharing_detector", lambda: [])
    monkeypatch.setattr(service, "_run_suspicious_process_detector", lambda: [])
    service.run_once()
    assert service.db.latest_monitor_heartbeat()
    status = service.db.get_background_monitor_status()
    assert status.detector_last_run_timestamp
    assert status.detector_last_run_counts
    assert status.last_error == ""


def test_heartbeat_without_detector_timestamp_marks_degraded(tmp_path: Path, monkeypatch, capsys) -> None:
    class FakeService:
        def __init__(self, db_path, poll_interval_seconds=5, record_startup=True):
            self.db = AuditDatabase(db_path, tmp_path / "logs")
            self.db.record_monitor_heartbeat("2099-04-25T00:00:00+00:00")

        def status_payload(self):
            return {
                "monitor_running": True,
                "pid_alive": True,
                "heartbeat_fresh": True,
                "status_text": "degraded: heartbeat without detector loop",
                "last_heartbeat": "2099-04-25T00:00:00+00:00",
                "last_event": "",
                "last_error": "",
                "detector_errors": "",
                "events_last_10_minutes": 0,
                "db_path": str(tmp_path / "audit.sqlite"),
                "log_path": "/tmp/monitor.log",
                "detector_last_run_timestamp": "",
                "detector_last_run_counts": "",
                "detector_enabled_camera": True,
                "detector_enabled_session": True,
                "detector_enabled_sharing": True,
                "detector_enabled_process": True,
                "detector_last_zero_reason": "",
                "current_snapshot": {},
                "recent_events": [],
            }

    monkeypatch.setattr("mac_audit_agent.monitor.BackgroundMonitorService", FakeService)
    exit_code = monitor_main(["--db-path", str(tmp_path / "audit.sqlite"), "--status"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"degraded: heartbeat without detector loop"' in captured.out


def test_monitor_once_exits_cleanly(tmp_path: Path, monkeypatch, capsys) -> None:
    class FakeService:
        def __init__(self, db_path, poll_interval_seconds=5):
            self.db = AuditDatabase(db_path, tmp_path / "logs")

        def run_once(self):
            self.db.record_monitor_heartbeat("2026-04-25T00:00:00+00:00")
            return []

    monkeypatch.setattr("mac_audit_agent.monitor.BackgroundMonitorService", FakeService)
    exit_code = monitor_main(["--db-path", str(tmp_path / "audit.sqlite"), "--once"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"events_recorded": 0' in captured.out


def test_monitor_run_calls_detector_loop(tmp_path: Path, monkeypatch) -> None:
    calls = []

    class FakeService:
        def __init__(self, db_path, poll_interval_seconds=5, record_startup=True):
            self.db = AuditDatabase(db_path, tmp_path / "logs")

        def run_forever(self):
            calls.append("run_forever")

    monkeypatch.setattr("mac_audit_agent.monitor.BackgroundMonitorService", FakeService)
    exit_code = monitor_main(["--db-path", str(tmp_path / "audit.sqlite"), "--run"])
    assert exit_code == 0
    assert calls == ["run_forever"]


def test_run_forever_calls_detector_loop_repeatedly(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", poll_interval_seconds=3)
    calls = []

    def fake_run_once():
        calls.append("run_once")
        if len(calls) >= 2:
            raise RuntimeError("stop test")
        return []

    monkeypatch.setattr(service, "run_once", fake_run_once)
    monkeypatch.setattr(service.notifications, "start_cfaa_login_acknowledgment", lambda: False)
    monkeypatch.setattr(service.notifications, "poll_cfaa_login_acknowledgment", lambda: False)
    monkeypatch.setattr(service.notifications, "reconcile_security_overlay", lambda: False)
    monkeypatch.setattr(service.usb_observer, "start", lambda: None)
    monkeypatch.setattr("mac_audit_agent.monitor.time.sleep", lambda _seconds: None)

    try:
        service.run_forever()
    except RuntimeError as exc:
        assert str(exc) == "stop test"

    assert calls == ["run_once", "run_once"]


def test_monitor_snapshot_shows_detector_state(tmp_path: Path, monkeypatch, capsys) -> None:
    class FakeService:
        def __init__(self, db_path, poll_interval_seconds=5):
            self.db = AuditDatabase(db_path, tmp_path / "logs")

        def collect_detector_snapshot(self):
            return {
                "capture_capable_processes": [{"name": "Photo Booth", "pid": 123}],
                "display_state": "awake",
                "clamshell_state": "open",
                "session_locked": False,
                "screen_sharing_enabled": False,
                "remote_login_enabled": False,
                "db_path": str(tmp_path / "audit.sqlite"),
            }

    monkeypatch.setattr("mac_audit_agent.monitor.BackgroundMonitorService", FakeService)
    exit_code = monitor_main(["--db-path", str(tmp_path / "audit.sqlite"), "--snapshot"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"display_state": "awake"' in captured.out
    assert '"capture_capable_processes"' in captured.out


def test_monitor_snapshot_includes_raw_ps_lines_and_event_candidates(tmp_path: Path, monkeypatch, capsys) -> None:
    class FakeService:
        def __init__(self, db_path, poll_interval_seconds=5):
            self.db = AuditDatabase(db_path, tmp_path / "logs")

        def collect_detector_snapshot(self):
            return {
                "capture_capable_processes": [{"name": "FaceTime", "pid": 321}],
                "capture_capable_matches": [{"name": "FaceTime", "pid": 321}],
                "raw_ps_lines": ["321  FaceTime  /System/Applications/FaceTime.app/Contents/MacOS/FaceTime"],
                "emitted_event_candidates": [{"event_type": "capture_capable_process_observed", "process_name": "FaceTime"}],
                "display_state": "awake",
                "clamshell_state": "open",
                "session_locked": False,
                "screen_sharing_enabled": False,
                "remote_login_enabled": False,
                "db_path": str(tmp_path / "audit.sqlite"),
            }

    monkeypatch.setattr("mac_audit_agent.monitor.BackgroundMonitorService", FakeService)
    exit_code = monitor_main(["--db-path", str(tmp_path / "audit.sqlite"), "--snapshot"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"raw_ps_lines"' in captured.out
    assert '"emitted_event_candidates"' in captured.out
    assert '"FaceTime"' in captured.out


def test_monitor_test_notification_command_logs_result(tmp_path: Path, monkeypatch, capsys) -> None:
    class FakeService:
        def __init__(self, db_path, poll_interval_seconds=5, record_startup=True):
            self.db = AuditDatabase(db_path, tmp_path / "logs")

        def test_notification(self):
            self.db.set_background_monitor_state("notification_status", "security alerts ready (overlay/dialog; notification center optional)")
            return {
                "success": True,
                "overall_status": "PASS",
                "overlay": {"success": True, "error": ""},
                "dialog": {"success": True, "error": ""},
                "notification_center": {"success": False, "error": "notification failed"},
                "security_alerting_ready": True,
                "notification_center_optional": True,
                "last_test_time": "2026-04-25T00:00:00+00:00",
                "last_test_result": "PASS",
                "notification_status": "security alerts ready (overlay/dialog; notification center optional)",
                "readiness_json": {},
                "permission_note": "Notification Center is optional; overlay/dialog are sufficient for security alerting.",
                "event_id": "notification-readiness-1",
            }

    monkeypatch.setattr("mac_audit_agent.monitor.BackgroundMonitorService", FakeService)
    exit_code = monitor_main(["--db-path", str(tmp_path / "audit.sqlite"), "--test-notification"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"overall_status": "PASS"' in captured.out
    assert '"notification_center": {' in captured.out
    assert '"notification_status": "security alerts ready (overlay/dialog; notification center optional)"' in captured.out


def test_monitor_test_dialog_command_logs_result(tmp_path: Path, monkeypatch, capsys) -> None:
    class FakeService:
        def __init__(self, db_path, poll_interval_seconds=5, record_startup=True):
            self.db = AuditDatabase(db_path, tmp_path / "logs")

        def test_dialog(self):
            self.db.set_background_monitor_state("notification_status", "available via AppleScript")
            return {
                "success": True,
                "stderr": "",
                "osascript_exists": True,
                "notification_status": "available via AppleScript",
                "permission_note": "unknown",
                "event_id": "dialog-test-1",
            }

    monkeypatch.setattr("mac_audit_agent.monitor.BackgroundMonitorService", FakeService)
    exit_code = monitor_main(["--db-path", str(tmp_path / "audit.sqlite"), "--test-dialog"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"success": true' in captured.out
    assert '"event_id": "dialog-test-1"' in captured.out


def test_repair_action_attempts_bootout_bootstrap_kickstart(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    calls = []
    states = iter(["", "2026-04-25T00:00:05+00:00"])
    monkeypatch.setattr(panel.service, "stop_orphan_processes", lambda: [9001])
    monkeypatch.setattr(
        panel.launch_agent,
        "repair",
        lambda poll_interval_seconds=15: (Path(panel.launch_agent.plist_path), calls.append("bootout/bootstrap/kickstart") or ["ok"]),
        raising=False,
    )
    monkeypatch.setattr(panel.db, "get_background_monitor_status", lambda: type("Status", (), {"detector_last_run_timestamp": next(states, "2026-04-25T00:00:05+00:00")})())
    monkeypatch.setattr(panel, "refresh", lambda: None)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.information", lambda *args, **kwargs: None)
    panel.repair_monitor()
    assert calls == ["bootout/bootstrap/kickstart"]
    assert app is not None


def test_repair_alerts_notifier_recreates_plist_and_verifies_overlay(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    calls = []

    class FakeNotifierManager:
        def __init__(self) -> None:
            self.paths = type("Paths", (), {"plist_path": tmp_path / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist"})()
            self._target = "gui/501"
            self._status = type(
                "Status",
                (),
                {
                    "process_pid": os.getpid(),
                    "loaded": True,
                    "running": True,
                    "last_error": "",
                },
            )()

        def stop(self):
            calls.append("stop")

        def uninstall(self):
            calls.append("uninstall")

        def install_user_notifier(self):
            calls.append("install")
            self.paths.plist_path.parent.mkdir(parents=True, exist_ok=True)
            self.paths.plist_path.write_text("plist", encoding="utf-8")
            return self.paths.plist_path

        def _bootstrap_preflight(self):
            calls.append("preflight")

        def _bootout_commands(self):
            return [[LAUNCHCTL_BIN, "bootout", self._target, str(self.paths.plist_path)]]

        def _bootout_tolerate(self):
            return set()

        def _run(self, command, tolerate=None, check=True):
            calls.append(" ".join(command))
            return FakeCompletedProcess(returncode=0, stdout="OK", stderr="")

        def _launchctl_target(self):
            return self._target

        def start(self):
            calls.append("start")

        def status(self):
            return self._status

    notifier_service = BackgroundMonitorService(tmp_path / "audit.sqlite", mode="user-notifier", record_startup=False)
    monkeypatch.setattr(notifier_service.notifications, "should_notify", lambda event, force=False: True)
    def fake_overlay(event):
        event.visible_alert_shown = True
        event.notification_decision = "sent"
        event.notification_reason = "test"
        event.notification_sent = True
        event.notification_returncode = 0
        notifier_service.db.set_background_monitor_state("overlay_manager_alive", "1")
        notifier_service.db.set_background_monitor_state("overlay_dispatch_result", "SUCCESS")
        notifier_service.db.set_background_monitor_state("overlay_dispatch_attempted", "1")
        notifier_service.db.set_background_monitor_state("last_alert_displayed_at", event.timestamp)
        notifier_service.db.update_monitor_event_notification(
            event.event_id,
            notification_sent=True,
            notification_error="",
            notification_returncode=0,
            notification_decision="sent",
            notification_reason="test",
            cooldown_remaining_seconds=event.cooldown_remaining_seconds,
            popup_allowed=True,
            visible_alert_shown=True,
            alert_style="critical_red",
            cooldown_suppressed=False,
            last_suppression_reason="",
        )
        return True

    monkeypatch.setattr(notifier_service.notifications, "update_security_overlay", fake_overlay)

    def fake_notify(event, force=False):
        fake_overlay(event)
        event.notification_sent = True
        event.notification_returncode = 0
        event.notification_error = ""
        event.notification_decision = "sent"
        event.notification_reason = "test"
        event.visible_alert_shown = True
        event.alert_style = "critical_red"
        return True, ""

    monkeypatch.setattr(notifier_service.notifications, "notify", fake_notify)
    monkeypatch.setattr(panel, "_active_monitor_db", lambda: db)
    monkeypatch.setattr(panel, "_notifier_manager", lambda: FakeNotifierManager())
    monkeypatch.setattr(panel, "_notification_service", lambda: notifier_service)
    monkeypatch.setattr(panel.service, "stop_orphan_processes", lambda: [9001])
    monkeypatch.setattr(panel, "_repair_alerts_log_tail", lambda: "repair log tail")
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.warning", lambda *args, **kwargs: None)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.information", lambda *args, **kwargs: None)

    panel.repair_alerts_notifier()

    assert "stop" in calls
    assert "uninstall" in calls
    assert "install" in calls
    assert "start" in calls
    assert db.get_background_monitor_state("notifier_installed", "") == "1"
    assert db.get_background_monitor_state("notifier_loaded", "") == "1"
    assert db.get_background_monitor_state("notifier_pid_alive", "") == "1"
    assert db.get_background_monitor_state("overlay_manager_alive", "") == "1"
    assert db.get_background_monitor_state("last_error", "") == ""
    assert app is not None


def test_test_bottom_right_alert_uses_direct_overlay_path(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    service = BackgroundMonitorService(tmp_path / "service.sqlite", mode="user-notifier", record_startup=False)
    overlay_calls: list[str] = []

    def fake_overlay(event, **_kwargs):
        overlay_calls.append(event.event_type)
        event.visible_alert_shown = True
        return True

    monkeypatch.setattr(panel, "_event_service", lambda: service)
    monkeypatch.setattr(panel, "_notification_service", lambda: service)
    monkeypatch.setattr(service.notifications, "show_visible_security_alert", fake_overlay)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.information", lambda *args, **kwargs: None)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.warning", lambda *args, **kwargs: None)

    panel.test_bottom_right_alert()

    assert overlay_calls == [
        "protected_monitor_tamper_detected",
        "usb_device_connected",
        "apple_security_forecast_elevated",
    ]
    latest = service.db.latest_monitor_events(limit=3)
    assert len(latest) == 3
    assert all(event.visible_alert_shown for event in latest)
    assert app is not None


def test_real_mandatory_events_use_same_visible_overlay_path(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", mode="user-notifier", record_startup=False)
    overlay_calls: list[str] = []

    def fake_overlay(event, **_kwargs):
        overlay_calls.append(event.event_type)
        event.visible_alert_shown = True
        return True

    monkeypatch.setattr(service.notifications, "show_visible_security_alert", fake_overlay)

    event = BackgroundMonitorEvent(
        event_id="real-usb-visible",
        timestamp=utc_now_iso(),
        event_type="usb_reconnect_detected",
        severity="info",
        source="hardware_detector",
        evidence="USB reconnect observed by detector.",
        confidence="high",
    )

    assert service.record_monitor_event(event) == "real-usb-visible"
    stored = service.db.latest_monitor_events(limit=1)[0]
    assert stored.event_type == "usb_device_connected"
    assert stored.notification_sent is True
    assert overlay_calls == ["usb_device_connected"]
    trace = service.db.get_event_alert_trace("real-usb-visible")
    assert trace is not None
    assert trace.original_event_type == "usb_reconnect_detected"
    assert trace.normalized_event_type == "usb_device_connected"


def test_two_pending_real_events_alert_sequentially(tmp_path: Path, monkeypatch) -> None:
    writer_db = AuditDatabase(tmp_path / "audit.sqlite")
    notifier = BackgroundMonitorService(tmp_path / "audit.sqlite", mode="user-notifier", record_startup=False)
    overlay_calls: list[str] = []

    def fake_overlay(event, **_kwargs):
        overlay_calls.append(event.event_type)
        event.visible_alert_shown = True
        return True

    monkeypatch.setattr(notifier.notifications, "show_visible_security_alert", fake_overlay)
    for event_type in ["lid_opened", "bluetooth_device_connected"]:
        writer_db.record_monitor_event(
            BackgroundMonitorEvent(
                event_id=f"pending-{event_type}",
                timestamp=utc_now_iso(),
                event_type=event_type,
                severity="medium",
                source="real_detector",
                evidence=f"{event_type} observed.",
                confidence="high",
            ),
            dedupe_window_seconds=0,
        )
        writer_db.record_event_alert_trace(
            EventAlertTrace(
                trace_id=f"trace-pending-{event_type}",
                event_id=f"pending-{event_type}",
                event_type=event_type,
                original_event_type=event_type,
                normalized_event_type=event_type,
                stored_db_path=str(writer_db.path),
                stored_success=True,
                alert_queue_enqueued=True,
            )
        )

    notified = notifier.process_pending_notifications()

    assert [event.event_type for event in notified] == ["lid_opened", "bluetooth_device_connected"]
    assert overlay_calls == ["lid_opened", "bluetooth_device_connected"]
    assert notifier.db.get_background_monitor_state("notifier_cursor_after", "") == "pending-bluetooth_device_connected"


def test_idle_resume_uses_authorized_use_overlay_notice(tmp_path: Path, monkeypatch) -> None:
    state_path = tmp_path / "security_overlay.json"
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_STATE_PATH", state_path)
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_PID_PATH", tmp_path / "security_overlay.pid")
    manager = NotificationManager(AuditDatabase(tmp_path / "audit.sqlite"))
    monkeypatch.setattr(manager, "_ensure_security_overlay_process", lambda: True)
    event = BackgroundMonitorEvent(
        event_id="idle-visible",
        timestamp=utc_now_iso(),
        event_type="keyboard_activity_detected",
        severity="medium",
        source="session_detector",
        evidence="Keyboard input resumed after idle.",
        confidence="high",
    )

    assert manager.show_visible_security_alert(event, reason="authorized_use_notice") is True
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert payload["title"] == "Authorized Use Notice"
    assert payload["buttons"] == ["Open Timeline", "Preserve Evidence Snapshot", "Acknowledge"]
    assert "Activity was detected after a period of inactivity" in payload["details"]


def test_force_reinstall_action_stops_orphans_and_runs_force_reinstall(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    calls = []
    monkeypatch.setattr(panel.service, "stop_orphan_processes", lambda: [9001, 9002])
    monkeypatch.setattr(
        panel.launch_agent,
        "force_reinstall",
        lambda poll_interval_seconds=15: (Path(panel.launch_agent.plist_path), calls.append("force_reinstall") or ["ok"]),
        raising=False,
    )
    monkeypatch.setattr(panel, "refresh", lambda: None)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.information", lambda *args, **kwargs: None)

    panel.force_reinstall_monitor()

    assert calls == ["force_reinstall"]
    assert app is not None


def test_test_critical_alert_creates_visible_alert_event(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", mode="user-notifier", record_startup=False)
    monkeypatch.setattr(service.notifications, "should_notify", lambda event, force=False: True)
    def fake_overlay(event):
        event.visible_alert_shown = True
        event.notification_decision = "sent"
        event.notification_reason = "test"
        event.notification_sent = True
        event.notification_returncode = 0
        service.db.set_background_monitor_state("overlay_manager_alive", "1")
        service.db.set_background_monitor_state("overlay_dispatch_result", "SUCCESS")
        service.db.set_background_monitor_state("overlay_dispatch_attempted", "1")
        service.db.set_background_monitor_state("last_alert_displayed_at", event.timestamp)
        service.db.update_monitor_event_notification(
            event.event_id,
            notification_sent=True,
            notification_error="",
            notification_returncode=0,
            notification_decision="sent",
            notification_reason="test",
            cooldown_remaining_seconds=event.cooldown_remaining_seconds,
            popup_allowed=True,
            visible_alert_shown=True,
            alert_style="critical_red",
            cooldown_suppressed=False,
            last_suppression_reason="",
        )
        return True

    monkeypatch.setattr(service.notifications, "update_security_overlay", fake_overlay)

    def fake_notify(event, force=False):
        fake_overlay(event)
        event.notification_sent = True
        event.notification_returncode = 0
        event.notification_error = ""
        event.notification_decision = "sent"
        event.notification_reason = "test"
        event.visible_alert_shown = True
        event.alert_style = "critical_red"
        return True, ""

    monkeypatch.setattr(service.notifications, "notify", fake_notify)
    monkeypatch.setattr(panel, "_event_service", lambda: service)
    monkeypatch.setattr(panel, "_notification_service", lambda: service)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.information", lambda *args, **kwargs: None)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.warning", lambda *args, **kwargs: None)

    panel.test_critical_alert()

    latest = db.latest_monitor_events(limit=1)[0]
    assert latest.event_type == "protected_monitor_tamper_detected"
    assert latest.notification_sent is True
    assert latest.visible_alert_shown is True
    assert db.get_background_monitor_state("overlay_dispatch_result", "") in {"SUCCESS", "skipped"}
    assert app is not None


def test_primary_install_action_installs_system_daemon_and_user_notifier(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=False, running=False))
    calls = []
    system_plist = Path("/Library/LaunchDaemons") / f"{LAUNCH_AGENT_LABEL}.plist"
    user_plist = Path.home() / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist"

    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        panel.system_launch_agent,
        "install_system_monitor",
        lambda: calls.append("system-daemon") or system_plist,
    )
    monkeypatch.setattr(
        panel,
        "_system_user_notifier_manager",
        lambda: type("SystemUserNotifier", (), {"install_user_notifier": lambda self: calls.append("user-notifier") or user_plist})(),
    )
    monkeypatch.setattr(panel.system_launch_agent, "show_logs", lambda: "/Library/Logs/MacAuditAgent/background_monitor.stdout.log")
    monkeypatch.setattr(panel, "refresh", lambda: None)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.question", lambda *args, **kwargs: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.information", lambda *args, **kwargs: None)

    panel.install_monitor()

    assert calls == ["system-daemon", "user-notifier"]
    assert db.get_background_monitor_state("monitor_mode", "") == "system"
    assert db.get_background_monitor_state("plist_path", "") == str(system_plist)
    assert app is not None


def test_enable_continuous_monitoring_requires_system_install(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=False, running=False))
    calls = []
    monkeypatch.setattr(panel.launch_agent, "install", lambda: calls.append("install") or Path(panel.launch_agent.plist_path))
    monkeypatch.setattr(panel.launch_agent, "start", lambda: calls.append("start"))
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.warning", lambda *args, **kwargs: None)
    monkeypatch.setattr(panel, "refresh", lambda: None)

    panel.toggle_continuous_monitoring(True)

    assert calls == []
    assert "Install System Monitor + User Notifier" in db.get_background_monitor_state("last_error", "")
    assert app is not None


def test_enable_continuous_monitoring_starts_system_daemon_and_user_notifier(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.set_background_monitor_state("monitor_mode", "system")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=True, running=False))
    panel.system_launch_agent = FakeLaunchAgent(installed=True, running=False)
    calls = []
    states = iter(
        [
            type("Status", (), {"last_heartbeat": "", "detector_last_run_timestamp": ""})(),
            type("Status", (), {"last_heartbeat": "2026-04-25T00:00:05+00:00", "detector_last_run_timestamp": "2026-04-25T00:00:06+00:00"})(),
        ]
    )
    monkeypatch.setattr(panel.system_launch_agent, "start", lambda: calls.append("system-start"))
    monkeypatch.setattr(panel.launch_agent, "start", lambda: calls.append("user-notifier-start"))
    monkeypatch.setattr(panel.db, "get_background_monitor_status", lambda: next(states))
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.warning", lambda *args, **kwargs: None)
    monkeypatch.setattr(panel, "refresh", lambda: None)

    panel.toggle_continuous_monitoring(True)

    assert calls == ["system-start", "user-notifier-start"]
    assert app is not None


def test_start_at_login_checkbox_controls_launchagent_install(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=False, running=False))
    calls = []
    monkeypatch.setattr(panel.launch_agent, "install", lambda: calls.append("install") or Path(panel.launch_agent.plist_path))
    monkeypatch.setattr(panel.launch_agent, "uninstall", lambda: calls.append("uninstall"))
    monkeypatch.setattr(panel.launch_agent, "stop", lambda: calls.append("stop"))
    monkeypatch.setattr(panel, "refresh", lambda: None)

    panel.toggle_start_at_login(True)
    panel.toggle_start_at_login(False)

    assert calls == ["install", "stop", "uninstall"]
    assert app is not None


def test_monitor_status_reports_computed_running_from_fresh_heartbeat(tmp_path: Path, monkeypatch, capsys) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.set_background_monitor_state("loaded", "1")
    db.set_background_monitor_state("process_pid", "999999")
    db.record_monitor_heartbeat("2099-04-25T00:00:00+00:00")
    monkeypatch.setattr("mac_audit_agent.monitor.is_pid_alive", lambda _pid: False)
    exit_code = monitor_main(["--db-path", str(tmp_path / "audit.sqlite"), "--status"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"monitor_running": true' in captured.out
    assert '"heartbeat_fresh": true' in captured.out


def test_monitor_simulate_updates_last_event_timestamp(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setattr("mac_audit_agent.monitor.NotificationManager.notify", lambda self, event: (True, ""))
    exit_code = monitor_main(["--db-path", str(tmp_path / "audit.sqlite"), "--simulate", "camera_activity_suspected"])
    captured = capsys.readouterr()
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    assert exit_code == 0
    assert "simulated_event=camera_activity_suspected" in captured.out
    assert db.get_background_monitor_status().last_event_timestamp
    assert "camera_activity_suspected" in {event.event_type for event in db.latest_monitor_events(limit=10)}


def test_monitor_simulate_notify_force_bypasses_cooldown(tmp_path: Path, monkeypatch, capsys) -> None:
    calls = []

    def fake_notify(self, event, force=False):
        calls.append((event.event_type, force))
        event.notification_sent = True
        event.notification_returncode = 0
        return True, ""

    monkeypatch.setattr("mac_audit_agent.monitor.NotificationManager.notify", fake_notify)
    monkeypatch.setattr("mac_audit_agent.monitor.NotificationManager.should_notify", lambda self, event, force=False: True)
    exit_code = monitor_main(["--db-path", str(tmp_path / "audit.sqlite"), "--simulate", "capture_capable_process_observed", "--notify-force"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "simulated_event=capture_capable_process_observed" in captured.out
    assert calls == [("capture_capable_process_observed", True)]


def test_pid_and_heartbeat_helpers() -> None:
    assert is_pid_alive(os.getpid()) is True
    assert is_heartbeat_fresh("2099-04-25T00:00:00+00:00") is True
    assert is_heartbeat_fresh("2000-04-25T00:00:00+00:00") is False


def test_monitor_self_test_writes_event(tmp_path: Path, monkeypatch, capsys) -> None:
    class FakeService:
        def __init__(self, db_path, poll_interval_seconds=5):
            self.event = BackgroundMonitorEvent(
                event_id="self-test",
                timestamp="2026-04-25T00:00:00+00:00",
                event_type="monitor_self_test",
                severity="info",
                source="self_test",
                evidence="User triggered monitor self-test.",
                confidence="high",
                recommendation="review",
                metadata_json="{}",
            )

        def run_self_test(self):
            return self.event

    monkeypatch.setattr("mac_audit_agent.monitor.BackgroundMonitorService", FakeService)
    exit_code = monitor_main(["--db-path", str(tmp_path / "audit.sqlite"), "--self-test"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "self_test_event=monitor_self_test" in captured.out


def test_monitor_run_crash_writes_last_error_and_stderr_log(tmp_path: Path, monkeypatch) -> None:
    fallback_log = tmp_path / "monitor.log"
    stderr_log = tmp_path / "background_monitor.stderr.log"
    monkeypatch.setattr("mac_audit_agent.monitor.FALLBACK_MONITOR_LOG", fallback_log)
    monkeypatch.setattr("mac_audit_agent.monitor.STDERR_MONITOR_LOG", stderr_log)

    class FakeService:
        def __init__(self, db_path, poll_interval_seconds=5, record_startup=True):
            self.db = AuditDatabase(db_path, tmp_path / "logs")

        def run_forever(self):
            raise RuntimeError("boom at startup")

    monkeypatch.setattr("mac_audit_agent.monitor.BackgroundMonitorService", FakeService)
    exit_code = monitor_main(["--db-path", str(tmp_path / "audit.sqlite"), "--run"])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    assert exit_code == 1
    assert "boom at startup" in db.get_background_monitor_status().last_error
    assert "boom at startup" in stderr_log.read_text(encoding="utf-8")
    assert "boom at startup" in fallback_log.read_text(encoding="utf-8")


def test_monitor_doctor_prints_paths_and_runs_detector_cycle(tmp_path: Path, monkeypatch, capsys) -> None:
    class FakeService:
        def __init__(self, db_path, poll_interval_seconds=5, record_startup=True):
            self.db = AuditDatabase(db_path, tmp_path / "logs")

        def executor(self, command):
            if command[:2] == [PLUTIL_BIN, "-lint"]:
                return 0, "OK", ""
            return 1, "", "unsupported"

        def run_once(self):
            self.db.set_background_monitor_state("detector_last_run_timestamp", "2026-04-25T00:00:00+00:00")
            return []

    monkeypatch.setattr("mac_audit_agent.monitor.BackgroundMonitorService", FakeService)
    plist_path = tmp_path / "LaunchAgents" / f"{LAUNCH_AGENT_LABEL}.plist"
    monkeypatch.setattr("mac_audit_agent.monitor.default_launch_agent_paths", lambda: type("Paths", (), {"plist_path": plist_path, "stdout_path": tmp_path / "background_monitor.stdout.log", "stderr_path": tmp_path / "background_monitor.stderr.log"})())
    monitor_path = tmp_path / "mac_audit_agent" / "monitor.py"
    monitor_path.parent.mkdir(parents=True, exist_ok=True)
    monitor_path.write_text("print('ok')\n", encoding="utf-8")
    monkeypatch.setattr("mac_audit_agent.monitor.runtime_monitor_script_path", lambda: monitor_path)
    monkeypatch.setattr("mac_audit_agent.monitor.runtime_root", lambda: tmp_path)
    original_exists = Path.exists
    monkeypatch.setattr("pathlib.Path.exists", lambda self: True if self in {plist_path, Path(sys.executable), monitor_path} else original_exists(self))
    monkeypatch.setattr("mac_audit_agent.monitor.subprocess.run", lambda *args, **kwargs: FakeCompletedProcess(returncode=0, stdout="", stderr=""))
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    plist_path.write_bytes(plistlib.dumps({"ProgramArguments": ["/usr/bin/python3", str(monitor_path), "--run"]}))
    exit_code = monitor_main(["--db-path", str(tmp_path / "audit.sqlite"), "--doctor"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"stdout_log_path"' in captured.out
    assert '"stderr_log_path"' in captured.out
    assert f'"working_directory": "{tmp_path}"' in captured.out
    assert '"self_test_command_ok": true' in captured.out
    assert '"detector_cycle_ok": true' in captured.out


def test_background_monitor_panel_shows_import_fix_for_launchagent_module_error(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    db.set_background_monitor_state("installed", "1")
    db.set_background_monitor_state("loaded", "1")
    db.set_background_monitor_state("last_heartbeat", "")
    launch_agent = FakeLaunchAgent(installed=True, running=True)
    panel = BackgroundMonitorPanel(db, launch_agent)
    stderr_path = tmp_path / "background_monitor.stderr.log"
    stderr_path.write_text("Traceback...\nModuleNotFoundError: No module named 'mac_audit_agent'\n", encoding="utf-8")
    monkeypatch.setattr(panel, "_stderr_log_path", lambda: stderr_path)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.is_pid_alive", lambda _pid: False)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.is_heartbeat_fresh", lambda *_args, **_kwargs: False)

    panel.refresh()

    assert "loaded but crashed or exited" in panel.status_label.text()
    assert "runs from ~/.mac_audit_agent/runtime" in panel.health_panel.toPlainText()
    assert app is not None


def test_report_includes_background_monitor_events_only_when_selected(tmp_path: Path) -> None:
    scan_result = ScanResult(
        scan_id="scan-1",
        timestamp="2026-04-24T12:00:00Z",
        hostname="host",
        current_user="m",
        findings=[],
        raw_logs=[],
        collected_artifacts={},
        baseline_diff={},
        errors=[],
    )
    events = [{"timestamp": "2026-04-24T12:00:00Z", "event_type": "screen_wake", "severity": "info", "source": "IOKit", "process_name": "", "confidence": "high", "evidence": "Display woke."}]
    json_path = export_scan_result_json(scan_result, tmp_path / "report.json", include_background_monitor_logs=True, background_monitor_events=events)
    html_path = export_scan_result_html(scan_result, tmp_path / "report.html", include_background_monitor_logs=False, background_monitor_events=events)
    assert "background_monitor_events" in json_path.read_text(encoding="utf-8")
    assert "Background Monitor Events" not in html_path.read_text(encoding="utf-8")
    html_with_events = export_scan_result_html(scan_result, tmp_path / "report_with_events.html", include_background_monitor_logs=True, background_monitor_events=events)
    assert "Background Monitor Events" in html_with_events.read_text(encoding="utf-8")


def test_missing_rule_id_blocks_popup(tmp_path: Path) -> None:
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    manager = NotificationManager(db, runner=lambda *args, **kwargs: FakeCompletedProcess(returncode=0, stdout="", stderr=""))
    event = BackgroundMonitorEvent(
        event_id="event-1",
        timestamp="2026-06-01T12:00:00+00:00",
        event_type="legacy_event",
        severity="info",
        source="session_poll",
        evidence="Display woke.",
        confidence="high",
        recommendation="Review the event.",
    )
    decision = manager.evaluate_notification_decision(event)
    assert decision["decision"] == "invalid_incomplete"
    assert decision["reason"] == "missing_rule_id"
    popup, reason = manager.should_popup(event)
    assert popup is False
    assert reason == "missing rule_id"


def test_background_monitor_event_round_trips_provenance(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", record_startup=False)
    monkeypatch.setattr(service.notifications, "should_notify", lambda event, force=False: False)
    event = service._build_event(
        "screen_wake",
        "Display woke.",
        severity="info",
        confidence="high",
        source="session_poll",
        trigger_subsource="display_power",
        previous_state="sleep",
        current_state="awake",
    )
    assert service.record_monitor_event(event) == event.event_id
    saved = service.db.latest_monitor_events(limit=1)[0]
    assert saved.rule_id
    assert saved.trigger_source == "session_poll"
    assert saved.previous_state == "sleep"
    assert saved.current_state == "awake"
    assert "Detector=" in saved.source_trace


def test_alert_storm_groups_repeated_events(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", record_startup=False)
    monkeypatch.setattr(service.notifications, "notify", lambda event, force=False: (True, ""))
    monkeypatch.setattr(service.notifications, "should_notify", lambda event, force=False: True)
    base_timestamp = "2026-06-01T12:00:00+00:00"
    for index in range(21):
        event = service._build_event(
            "suspicious_process_observed",
            f"Browser process burst {index}",
            severity="high",
            confidence="medium",
            source="browser_detector",
            process_name="Opera Helper",
            related_path="/Applications/Opera.app/Contents/MacOS/Opera Helper",
            trigger_subsource="browser_process_args",
            previous_state="single process",
            current_state="repeated process observation",
        )
        event.timestamp = base_timestamp
        event.event_id = f"storm-{index}"
        service.record_monitor_event(event)
    events = service.db.latest_monitor_events(limit=5)
    assert any(item.event_type == "alert_storm_detected" for item in events)


def test_provenance_text_redacts_secrets() -> None:
    text = sanitize_signal_text("token=abc123 Authorization=Bearer super-secret cookie=sessionid")
    assert "abc123" not in text
    assert "super-secret" not in text
    assert "[redacted]" in text


def test_self_impact_watchdog_requires_sustained_pressure_and_bounds_backoff() -> None:
    watchdog = MonitorSelfImpactWatchdog(alpha=1.0)
    metrics = SelfImpactMetrics(
        cycle_seconds=12.0,
        poll_interval_seconds=3.0,
        cpu_percent=95.0,
        rss_mb=2048.0,
        emitted_events=40,
        detector_errors=2,
    )
    first = watchdog.evaluate(metrics)
    second = watchdog.evaluate(metrics)
    assert first.sustained_warning is False
    assert second.sustained_warning is True
    assert second.level == "critical"
    assert watchdog.effective_poll_interval(3) == 12


def test_monitor_self_impact_warning_records_once_and_persists_metrics(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", record_startup=False)
    service.self_impact_watchdog = MonitorSelfImpactWatchdog(alpha=1.0)
    monkeypatch.setattr(service.notifications, "notify", lambda event, force=False: (True, ""))
    monkeypatch.setattr(service.notifications, "update_security_overlay", lambda event: True)
    metrics = SelfImpactMetrics(12.0, 3.0, 95.0, 2048.0, 40, 2)
    assert service._evaluate_self_impact(cycle_seconds=12, emitted_events=40, detector_errors=2, metrics=metrics) is None
    event = service._evaluate_self_impact(cycle_seconds=12, emitted_events=40, detector_errors=2, metrics=metrics)
    assert event is not None
    assert event.event_type == "monitor_self_impact_warning"
    assert event.severity == "critical"
    assert "does not claim a denial-of-service condition" in event.recommendation
    assert service.db.get_background_monitor_state("self_impact_backoff_multiplier") == "4"
    assert service._evaluate_self_impact(cycle_seconds=12, emitted_events=40, detector_errors=2, metrics=metrics) is None
    saved = [item for item in service.db.latest_monitor_events(limit=10) if item.event_type == "monitor_self_impact_warning"]
    assert len(saved) == 1


def test_monitor_self_impact_warning_forces_bottom_right_overlay(tmp_path: Path, monkeypatch) -> None:
    state_path = tmp_path / "security_overlay.json"
    db = AuditDatabase(tmp_path / "audit.sqlite")
    manager = NotificationManager(db)
    monkeypatch.setattr("mac_audit_agent.notification_manager.OVERLAY_STATE_PATH", state_path)
    monkeypatch.setattr(manager, "_ensure_security_overlay_process", lambda: None)
    event = BackgroundMonitorEvent(
        event_id="self-impact-overlay",
        timestamp="2026-06-02T12:00:00+00:00",
        event_type="monitor_self_impact_warning",
        severity="critical",
        source="self_impact_watchdog",
        evidence="Sustained monitor resource pressure.",
    )
    assert manager.update_security_overlay(event) is True
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert payload["active"] is True
    assert payload["severity"] == "critical"


def test_system_daemon_periodic_integrity_drift_records_one_tamper_event(tmp_path: Path, monkeypatch) -> None:
    service = BackgroundMonitorService(tmp_path / "audit.sqlite", mode="system-daemon", record_startup=False)
    integrity = {
        "scope": "system",
        "tamper_detected": True,
        "severity": "critical",
        "confidence": "high",
        "plist_path": "/Library/LaunchDaemons/com.mac-audit-agent.monitor.plist",
        "evidence": ["runtime hash changed"],
        "recommendation": "Reinstall from a trusted source.",
    }
    monkeypatch.setattr("mac_audit_agent.monitor.verify_protected_monitor_integrity", lambda scope: integrity)
    first = service._run_integrity_detector()
    service._last_integrity_poll = 0.0
    second = service._run_integrity_detector()
    assert [event.event_type for event in first] == ["protected_monitor_tamper_detected"]
    assert second == []
    assert service.db.latest_monitor_events(limit=1)[0].severity == "critical"
