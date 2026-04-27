import os
import json
import plistlib
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from mac_audit_agent.launch_agent import (
    LAUNCH_AGENT_LABEL,
    LAUNCHCTL_BIN,
    LOG_BIN,
    PLUTIL_BIN,
    LaunchAgentManager,
    build_launch_agent_plist,
    launchctl_target,
    project_root,
    runtime_monitor_script_path,
    runtime_package_root,
    runtime_root,
)
from mac_audit_agent.models import BackgroundMonitorEvent, ScanResult
from mac_audit_agent.monitor import FALLBACK_MONITOR_LOG, BackgroundMonitorService, STDERR_MONITOR_LOG, clear_monitor_log_files, is_heartbeat_fresh, is_pid_alive, main as monitor_main
from mac_audit_agent.notification_manager import NotificationManager, applescript_escape, send_alert_dialog, send_notification
from mac_audit_agent.privacy_monitor import PrivacyMonitor, PrivacyMonitorSnapshot
from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json
from mac_audit_agent.session_monitor import SessionMonitor
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.ui.background_monitor_panel import BackgroundMonitorPanel


class FakeCompletedProcess:
    def __init__(self, returncode=0, stdout="", stderr="") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


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
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_root", lambda: runtime_base)
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_package_root", lambda: runtime_base / "mac_audit_agent")
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
    with patch("mac_audit_agent.launch_agent.runtime_root", lambda: runtime_base), patch(
        "mac_audit_agent.launch_agent.runtime_package_root", lambda: runtime_base / "mac_audit_agent"
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
    with patch("mac_audit_agent.launch_agent.runtime_root", lambda: runtime_base), patch(
        "mac_audit_agent.launch_agent.runtime_package_root", lambda: runtime_base / "mac_audit_agent"
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
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_root", lambda: runtime_base)
    monkeypatch.setattr("mac_audit_agent.launch_agent.runtime_package_root", lambda: runtime_base / "mac_audit_agent")
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
    with patch("mac_audit_agent.launch_agent.runtime_root", lambda: runtime_base), patch(
        "mac_audit_agent.launch_agent.runtime_package_root", lambda: runtime_base / "mac_audit_agent"
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
    db.set_background_monitor_state("notify:possible_lid_opened::Possible lid opened transition detected.", opened.timestamp)
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


def test_non_allowlisted_events_never_popup_by_default(tmp_path: Path) -> None:
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
    assert manager.should_notify(event) is False
    assert event.notification_reason == "event type is log-only by default"


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
            self.db.set_background_monitor_state("notification_status", "available via AppleScript")
            return {
                "success": True,
                "stderr": "",
                "osascript_exists": True,
                "notification_status": "available via AppleScript",
                "permission_note": "unknown",
                "event_id": "notification-test-1",
            }

    monkeypatch.setattr("mac_audit_agent.monitor.BackgroundMonitorService", FakeService)
    exit_code = monitor_main(["--db-path", str(tmp_path / "audit.sqlite"), "--test-notification"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"success": true' in captured.out
    assert '"notification_status": "available via AppleScript"' in captured.out


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


def test_enable_continuous_monitoring_installs_starts_and_verifies_updates(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    db = AuditDatabase(tmp_path / "audit.sqlite", tmp_path / "logs")
    panel = BackgroundMonitorPanel(db, FakeLaunchAgent(installed=False, running=False))
    calls = []
    states = iter(
        [
            type("Status", (), {"last_heartbeat": "", "detector_last_run_timestamp": ""})(),
            type("Status", (), {"last_heartbeat": "2026-04-25T00:00:05+00:00", "detector_last_run_timestamp": "2026-04-25T00:00:06+00:00"})(),
        ]
    )
    monkeypatch.setattr(panel.launch_agent, "install", lambda: calls.append("install") or Path(panel.launch_agent.plist_path))
    monkeypatch.setattr(panel.launch_agent, "start", lambda: calls.append("start"))
    monkeypatch.setattr(panel.db, "get_background_monitor_status", lambda: next(states))
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("mac_audit_agent.ui.background_monitor_panel.QMessageBox.warning", lambda *args, **kwargs: None)
    monkeypatch.setattr(panel, "refresh", lambda: None)

    panel.toggle_continuous_monitoring(True)

    assert calls == ["install", "start"]
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
