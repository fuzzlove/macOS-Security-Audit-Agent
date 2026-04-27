from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None
import getpass
import json
import logging
import os
import plistlib
import re
import subprocess
import time
import signal
import traceback
from datetime import datetime, timedelta, timezone

from mac_audit_agent.launch_agent import LAUNCH_AGENT_LABEL, PLUTIL_BIN, default_launch_agent_paths, launchctl_target, monitor_script_path, project_root, runtime_monitor_script_path, runtime_root
from mac_audit_agent.models import BackgroundMonitorEvent, utc_now_iso
from mac_audit_agent.notification_manager import NotificationManager
from mac_audit_agent.privacy_monitor import PrivacyMonitor, PrivacyMonitorSnapshot
from mac_audit_agent.session_monitor import SessionMonitor, SessionSnapshot
from mac_audit_agent.storage import AuditDatabase


LOGGER = logging.getLogger(__name__)
MONITOR_VERSION = "background-monitor-2026.04.25"
DISCLAIMER = (
    "This monitor records local security events and privacy indicators. "
    "It does not record camera, microphone, screen contents, keystrokes, or packet contents."
)
FALLBACK_MONITOR_LOG = Path.home() / "Library" / "Logs" / "MacAuditAgent" / "monitor.log"
STDOUT_MONITOR_LOG = default_launch_agent_paths().stdout_path
STDERR_MONITOR_LOG = default_launch_agent_paths().stderr_path
IMPORTANT_EVENT_TYPES = {
    "capture_capable_process_observed",
    "camera_activity_confirmed",
    "session_locked",
    "session_unlocked",
    "display_sleep",
    "display_wake",
    "possible_lid_closed",
    "possible_lid_opened",
    "screen_sharing_enabled",
    "remote_login_enabled",
    "suspicious_process_observed",
    "persistence_item_created",
    "major_security_event",
    "monitor_self_test",
}
SUSPICIOUS_PROCESS_PREFIXES = ("/tmp", "/var/tmp", "/private/tmp", "/Users/Shared")
SHARING_POLL_SECONDS = 15
HEARTBEAT_SECONDS = 30
DEDUPE_SECONDS = 60
PS_LINE_RE = re.compile(r"^\s*(\d+)\s+(.*?)\s{2,}(.*)$")


def is_pid_alive(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def is_heartbeat_fresh(last_heartbeat: str, max_age_seconds: int = 120) -> bool:
    if not last_heartbeat:
        return False
    try:
        heartbeat = datetime.fromisoformat(last_heartbeat)
    except ValueError:
        return False
    if heartbeat.tzinfo is None:
        heartbeat = heartbeat.replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - heartbeat.astimezone(timezone.utc)
    return age <= timedelta(seconds=max_age_seconds)


def _with_file_lock(handle) -> None:
    if fcntl is None:
        return
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


def _release_file_lock(handle) -> None:
    if fcntl is None:
        return
    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def ensure_monitor_log_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch()


def append_monitor_log_line(path: Path, message: str) -> None:
    ensure_monitor_log_file(path)
    with path.open("a", encoding="utf-8") as handle:
        _with_file_lock(handle)
        try:
            handle.write(message)
            handle.flush()
        finally:
            _release_file_lock(handle)


def truncate_monitor_log_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    original_mode = path.stat().st_mode if path.exists() else None
    ensure_monitor_log_file(path)
    with path.open("r+", encoding="utf-8") as handle:
        _with_file_lock(handle)
        try:
            handle.seek(0)
            handle.truncate(0)
            handle.flush()
        finally:
            _release_file_lock(handle)
    if original_mode is not None:
        os.chmod(path, original_mode & 0o777)


def clear_monitor_log_files() -> list[Path]:
    paths = [
        FALLBACK_MONITOR_LOG.expanduser(),
        STDOUT_MONITOR_LOG.expanduser(),
        STDERR_MONITOR_LOG.expanduser(),
    ]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    return paths


def tail_text_file(path: Path, lines: int = 30) -> str:
    try:
        if not path.exists():
            return ""
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if not content:
        return ""
    return "\n".join(content[-lines:])


class BackgroundMonitorService:
    def __init__(self, db_path: Path, poll_interval_seconds: int = 5, executor=None, record_startup: bool = True) -> None:
        self.db = AuditDatabase(db_path)
        self.poll_interval_seconds = max(3, min(5, poll_interval_seconds))
        self.executor = executor or self._run_command
        self.record_startup = record_startup
        self.privacy_monitor = PrivacyMonitor(executor=self.executor)
        self.session_monitor = SessionMonitor(executor=self.executor)
        self.notifications = NotificationManager(self.db)
        self.previous_privacy = None
        self.previous_session = None
        self.sharing_state: dict[str, bool | None] = {"remote_login": None, "screen_sharing": None, "file_sharing": None}
        self.latest_snapshot: dict[str, object] = {}
        self._last_heartbeat_written = 0.0
        self._last_sharing_poll = 0.0
        self.enabled_detectors = [
            "camera_process_detector",
            "screen_session_detector",
            "sharing_service_detector",
            "suspicious_process_detector",
        ]
        self._detector_enabled_flags = {
            "detector_enabled_camera": "1",
            "detector_enabled_session": "1",
            "detector_enabled_sharing": "1",
            "detector_enabled_process": "1",
        }
        self._ensure_log_paths()
        if self.record_startup:
            self._write_log_line(f"startup: monitor initialized | db_path={self.db.path}")
            self._record_startup_diagnostics()

    def run_forever(self) -> None:
        if not self.record_startup:
            self._write_log_line(f"startup: monitor initialized | db_path={self.db.path}")
            self._record_startup_diagnostics()
            self.record_startup = True
        while True:
            self.run_once()
            time.sleep(self.poll_interval_seconds)

    def run_once(self) -> list[BackgroundMonitorEvent]:
        self._update_runtime_state()
        all_events: list[BackgroundMonitorEvent] = []
        detector_errors: dict[str, str] = {}
        detector_counts: dict[str, dict[str, int]] = {}
        zero_reasons: list[str] = []
        detector_specs = [
            ("camera_process_detector", self._run_camera_detector),
            ("screen_session_detector", self._run_session_detector),
            ("sharing_service_detector", self._run_sharing_detector),
            ("suspicious_process_detector", self._run_suspicious_process_detector),
        ]
        zero_reason_map = {
            "camera_process_detector": "no capture-capable process found",
            "screen_session_detector": "no display state change",
            "sharing_service_detector": "no sharing state change",
            "suspicious_process_detector": "no suspicious process found",
        }
        for name, detector in detector_specs:
            self._write_log_line(f"detector started: {name}")
            try:
                events = detector()
                observed_count = self._detector_observed_count(name)
                detector_counts[name] = {"observed": observed_count, "emitted": len(events)}
                all_events.extend(events)
                if not events:
                    zero_reasons.append(zero_reason_map[name])
                self._write_log_line(f"detector completed: {name} observed={observed_count} emitted={len(events)}")
            except Exception as exc:
                detector_errors[name] = str(exc)
                detector_counts[name] = {"observed": 0, "emitted": 0}
                self._record_detector_error(name, exc)
        run_timestamp = utc_now_iso()
        self.db.set_background_monitor_state("detector_last_run_timestamp", run_timestamp)
        self.db.set_background_monitor_state("detector_last_run_counts", json.dumps(detector_counts, sort_keys=True))
        self.db.set_background_monitor_state("detector_last_emitted_events", str(len(all_events)))
        zero_reason_text = "; ".join(zero_reasons)
        self.db.set_background_monitor_state("detector_last_zero_reason", zero_reason_text)
        if zero_reason_text:
            self._write_log_line(f"detector zero events: {zero_reason_text}")
        self.db.set_background_monitor_state("detector_errors", json.dumps(detector_errors, sort_keys=True))
        if not detector_errors:
            self.db.set_background_monitor_state("last_error", "")
        return all_events

    def run_self_test(self) -> BackgroundMonitorEvent:
        self.record_heartbeat()
        event = self._build_event(
            "monitor_self_test",
            "User triggered monitor self-test.",
            severity="info",
            confidence="high",
            simulated=True,
            source="self_test",
        )
        self.record_monitor_event(event, notify_force=True)
        self._write_startup_like_log("self-test complete")
        return event

    def generate_test_event(self) -> BackgroundMonitorEvent:
        event = self._build_event(
            "monitor_test_event",
            "User generated a monitor test event.",
            severity="info",
            confidence="high",
            simulated=True,
            source="ui",
        )
        self.record_monitor_event(event)
        return event

    def test_dialog(self) -> dict[str, object]:
        event = self._build_event(
            "major_security_event",
            "User triggered a high-priority dialog test.",
            severity="high",
            confidence="high",
            simulated=True,
            source="dialog_test",
            process_name="FaceTime",
        )
        event.event_id = f"dialog-test-{utc_now_iso()}"
        self.record_monitor_event(event, notify_force=True)
        self._write_log_line(
            f"dialog test: event_id={event.event_id} sent={event.notification_sent} returncode={event.notification_returncode} error={event.notification_error}"
        )
        return {
            "success": event.notification_sent,
            "stderr": event.notification_error,
            "osascript_exists": Path("/usr/bin/osascript").exists(),
            "notification_status": self.db.get_background_monitor_state("notification_status", ""),
            "permission_note": "Permission status cannot be confirmed directly. Check System Settings > Notifications for Terminal/Python/osascript or the packaged app.",
            "event_id": event.event_id,
        }

    def test_notification(self) -> dict[str, object]:
        event = self._build_event(
            "monitor_test_notification",
            "User triggered a notification test.",
            severity="high",
            confidence="high",
            simulated=True,
            source="notification_test",
            process_name="FaceTime",
        )
        sent, error = self.notifications.notify(event)
        try:
            self.db.record_monitor_event(event, dedupe_window_seconds=0)
        except Exception as exc:
            self._write_log_line(f"notification test db write failed: {exc}")
        self._write_log_line(
            f"notification test: event_id={event.event_id} sent={sent} returncode={event.notification_returncode} error={error}"
        )
        return {
            "success": sent,
            "stderr": error,
            "osascript_exists": Path("/usr/bin/osascript").exists(),
            "notification_status": self.db.get_background_monitor_state("notification_status", ""),
            "permission_note": (
                "Permission status cannot be confirmed directly. Check System Settings > Notifications for Terminal/Python/osascript or the packaged app."
            ),
            "event_id": event.event_id,
        }

    def simulate_event(
        self,
        event_type: str,
        evidence: str,
        *,
        severity: str = "info",
        confidence: str = "high",
        source: str = "uat_simulator",
        process_name: str = "",
        pid: int | None = None,
        notify_force: bool = False,
    ) -> BackgroundMonitorEvent:
        detector_event = self._simulate_via_detector_path(
            event_type,
            source=source,
            process_name=process_name,
            pid=pid,
            notify_force=notify_force,
        )
        if detector_event is not None:
            return detector_event
        event = self._build_event(
            event_type,
            evidence,
            severity=severity,
            confidence=confidence,
            simulated=True,
            source=source,
            process_name=process_name,
            pid=pid,
        )
        self.record_monitor_event(event, notify_force=notify_force)
        return event

    def _simulate_via_detector_path(
        self,
        event_type: str,
        *,
        source: str,
        process_name: str,
        pid: int | None,
        notify_force: bool = False,
    ) -> BackgroundMonitorEvent | None:
        alias_map = {
            "lid_closed": "possible_lid_closed",
            "lid_opened": "possible_lid_opened",
            "session_locked": "screen_locked",
            "session_unlocked": "screen_unlocked",
        }
        target = alias_map.get(event_type, event_type)
        privacy_events = self._simulate_privacy_detector_events(target, source=source, process_name=process_name, pid=pid)
        if privacy_events:
            return self._record_simulated_detector_events(privacy_events, preferred_type=target, notify_force=notify_force)
        session_events = self._simulate_session_detector_events(target, source=source)
        if session_events:
            return self._record_simulated_detector_events(session_events, preferred_type=target, notify_force=notify_force)
        sharing_event = self._simulate_sharing_detector_event(target, source=source)
        if sharing_event is not None:
            sharing_event.simulated = True
            self.record_monitor_event(sharing_event, notify_force=notify_force)
            return sharing_event
        return None

    def _record_simulated_detector_events(self, events: list[BackgroundMonitorEvent], *, preferred_type: str, notify_force: bool = False) -> BackgroundMonitorEvent:
        chosen = events[0]
        for event in events:
            if event.event_type == preferred_type:
                chosen = event
                break
        chosen.simulated = True
        chosen.source = "uat_simulator"
        self.record_monitor_event(chosen, notify_force=notify_force)
        return chosen

    def _simulate_privacy_detector_events(self, event_type: str, *, source: str, process_name: str, pid: int | None) -> list[BackgroundMonitorEvent]:
        previous = PrivacyMonitorSnapshot()
        current = PrivacyMonitorSnapshot()
        if event_type in {"camera_activity_suspected", "capture_capable_process_observed"}:
            current.capture_capable_processes = [
                {
                    "pid": pid or 4242,
                    "name": process_name or "FaceTime",
                    "command": f"/Applications/{process_name or 'FaceTime'}.app/Contents/MacOS/{process_name or 'FaceTime'}",
                    "args": f"/Applications/{process_name or 'FaceTime'}.app/Contents/MacOS/{process_name or 'FaceTime'}",
                    "redacted_args": f"/Applications/{process_name or 'FaceTime'}.app/Contents/MacOS/{process_name or 'FaceTime'}",
                }
            ]
            current.camera_helper_processes = [
                {
                    "pid": (pid or 4242) + 1,
                    "name": "VDCAssistant",
                    "command": "/usr/libexec/VDCAssistant",
                    "args": "/usr/libexec/VDCAssistant",
                    "redacted_args": "/usr/libexec/VDCAssistant",
                }
            ]
        elif event_type == "capture_capable_process_closed":
            previous.capture_capable_processes = [
                {
                    "pid": pid or 4242,
                    "name": process_name or "FaceTime",
                    "command": f"/Applications/{process_name or 'FaceTime'}.app/Contents/MacOS/{process_name or 'FaceTime'}",
                    "args": f"/Applications/{process_name or 'FaceTime'}.app/Contents/MacOS/{process_name or 'FaceTime'}",
                    "redacted_args": f"/Applications/{process_name or 'FaceTime'}.app/Contents/MacOS/{process_name or 'FaceTime'}",
                }
            ]
        elif event_type == "microphone_activity_suspected":
            current.microphone_processes = [
                {
                    "pid": pid or 5151,
                    "name": process_name or "FaceTime",
                    "command": f"/Applications/{process_name or 'FaceTime'}.app/Contents/MacOS/{process_name or 'FaceTime'}",
                    "args": f"/Applications/{process_name or 'FaceTime'}.app/Contents/MacOS/{process_name or 'FaceTime'}",
                    "redacted_args": f"/Applications/{process_name or 'FaceTime'}.app/Contents/MacOS/{process_name or 'FaceTime'}",
                }
            ]
        else:
            return []
        return self.privacy_monitor.evaluate(previous, current)

    def _simulate_session_detector_events(self, event_type: str, *, source: str) -> list[BackgroundMonitorEvent]:
        previous = SessionSnapshot()
        current = SessionSnapshot()
        previous.display_state = "awake"
        previous.system_power_state = "awake"
        previous.session_locked = False
        previous.console_user = "m"
        previous.clamshell_state = "open"
        current.console_user = "m"
        if event_type == "possible_lid_closed":
            current.clamshell_state = "closed"
        elif event_type == "possible_lid_opened":
            previous.clamshell_state = "closed"
            current.clamshell_state = "open"
        elif event_type == "screen_locked":
            current.session_locked = True
        elif event_type == "screen_unlocked":
            previous.session_locked = True
            current.session_locked = False
        elif event_type == "display_sleep":
            current.display_state = "sleep"
        elif event_type == "display_wake":
            previous.display_state = "sleep"
            current.display_state = "awake"
        elif event_type == "system_sleep":
            current.system_power_state = "sleep"
        elif event_type == "system_wake":
            previous.system_power_state = "sleep"
            current.system_power_state = "awake"
        else:
            return []
        return self.session_monitor.evaluate(previous, current)

    def _simulate_sharing_detector_event(self, event_type: str, *, source: str) -> BackgroundMonitorEvent | None:
        if event_type == "screen_sharing_enabled":
            return self._build_event(
                "screen_sharing_enabled",
                "Screen Sharing is now enabled.",
                severity="medium",
                confidence="high",
                source=source,
            )
        if event_type == "remote_login_enabled":
            return self._build_event(
                "remote_login_enabled",
                "Remote Login is now enabled.",
                severity="medium",
                confidence="high",
                source=source,
            )
        return None

    def status_payload(self) -> dict[str, object]:
        status = self.db.get_background_monitor_status()
        pid_alive = is_pid_alive(status.process_pid)
        heartbeat_fresh = is_heartbeat_fresh(status.last_heartbeat, max_age_seconds=max(120, HEARTBEAT_SECONDS * 2))
        monitor_running = pid_alive or heartbeat_fresh
        orphan_process = bool(pid_alive and not status.loaded)
        status_text = self._status_text(loaded=status.loaded, launchctl_running=status.running, pid_alive=pid_alive, heartbeat_fresh=heartbeat_fresh)
        if status.loaded and heartbeat_fresh and status.detector_last_run_timestamp:
            status_text = "healthy"
        elif heartbeat_fresh and not status.detector_last_run_timestamp:
            status_text = "degraded: heartbeat without detector loop"
        return {
            "monitor_running": monitor_running,
            "launchagent_installed": status.installed,
            "launchagent_loaded": status.loaded,
            "pid_alive": pid_alive,
            "orphan_process": orphan_process,
            "heartbeat_fresh": heartbeat_fresh,
            "status_text": status_text,
            "last_heartbeat": status.last_heartbeat,
            "last_event": status.last_event_timestamp,
            "last_error": status.last_error,
            "detector_errors": status.detector_errors,
            "events_last_10_minutes": status.events_last_10_minutes,
            "db_path": status.db_path,
            "log_path": str(FALLBACK_MONITOR_LOG),
            "stderr_log_path": str(STDERR_MONITOR_LOG),
            "detector_last_run_timestamp": status.detector_last_run_timestamp,
            "detector_last_run_counts": status.detector_last_run_counts,
            "detector_enabled_camera": status.detector_enabled_camera,
            "detector_enabled_session": status.detector_enabled_session,
            "detector_enabled_sharing": status.detector_enabled_sharing,
            "detector_enabled_process": status.detector_enabled_process,
            "detector_last_zero_reason": status.detector_last_zero_reason,
            "current_snapshot": self._load_current_snapshot_state(),
            "current_snapshot_keys": sorted(self._load_current_snapshot_state().keys()),
            "recent_events": [event.to_dict() for event in self.db.latest_monitor_events(limit=5)],
        }

    def record_monitor_event(self, event: BackgroundMonitorEvent, *, notify_force: bool = False) -> str | None:
        preference = self.notifications.preference_for(event.event_type)
        if not bool(preference.get("enabled", True)):
            self.db.set_background_monitor_state(
                f"suppress_disabled:{event.event_type}",
                str(int(self.db.get_background_monitor_state(f"suppress_disabled:{event.event_type}", "0") or "0") + 1),
            )
            return None
        event.severity = str(preference.get("severity", event.severity))
        try:
            stored = self.db.record_monitor_event(event, dedupe_window_seconds=DEDUPE_SECONDS)
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", f"db write failed: {exc}")
            self._write_log_line(
                f"db write failed type={event.event_type} severity={event.severity} "
                f"process_name={event.process_name} pid={event.pid} error={exc}"
            )
            return None
        if not stored:
            return None
        if self._should_notify_event(event, notify_force=notify_force):
            sent, error = self._notify_event(event, notify_force=notify_force)
            event.notification_sent = sent
            event.notification_error = error
        else:
            event.notification_sent = False
            event.notification_error = ""
            event.notification_returncode = None
        self.db.update_monitor_event_notification(
            event.event_id,
            notification_sent=event.notification_sent,
            notification_error=event.notification_error,
            notification_returncode=event.notification_returncode,
            notification_decision=event.notification_decision,
            notification_reason=event.notification_reason,
            cooldown_remaining_seconds=event.cooldown_remaining_seconds,
            popup_allowed=event.popup_allowed,
        )
        self._write_log_line(
            f"event: type={event.event_type} severity={event.severity} confidence={event.confidence} "
            f"process_name={event.process_name} pid={event.pid} simulated={event.simulated} "
            f"notification_sent={event.notification_sent} notification_decision={event.notification_decision} "
            f"notification_reason={event.notification_reason} popup_allowed={event.popup_allowed} "
            f"cooldown_remaining_seconds={event.cooldown_remaining_seconds} "
            f"notification_returncode={event.notification_returncode} "
            f"notification_error={event.notification_error} evidence={event.evidence}"
        )
        return event.event_id

    def _should_notify_event(self, event: BackgroundMonitorEvent, *, notify_force: bool = False) -> bool:
        try:
            return bool(self.notifications.should_notify(event, force=notify_force))
        except TypeError:
            return bool(self.notifications.should_notify(event))

    def _notify_event(self, event: BackgroundMonitorEvent, *, notify_force: bool = False) -> tuple[bool, str]:
        try:
            return self.notifications.notify(event, force=notify_force)
        except TypeError:
            return self.notifications.notify(event)

    def record_event(self, event: BackgroundMonitorEvent, *, notify_force: bool = False) -> bool:
        return self.record_monitor_event(event, notify_force=notify_force) is not None

    def _persist_events(self, events: list[BackgroundMonitorEvent]) -> list[BackgroundMonitorEvent]:
        stored: list[BackgroundMonitorEvent] = []
        for event in events:
            if self.record_event(event):
                stored.append(event)
        return stored

    def record_heartbeat(self) -> None:
        timestamp = utc_now_iso()
        try:
            self.db.record_monitor_heartbeat(timestamp)
        except Exception as exc:
            self.db.set_background_monitor_state("last_error", f"heartbeat write failed: {exc}")
            self._write_log_line(f"heartbeat write failed: {exc}")
            return
        self._write_log_line(f"heartbeat: timestamp={timestamp}")

    def _update_runtime_state(self) -> None:
        launchctl_status = self._launchctl_service_status()
        launchctl_loaded = bool(launchctl_status.get("loaded"))
        self.db.set_background_monitor_state("enabled", "1")
        self.db.set_background_monitor_state("running", "1" if launchctl_loaded else "0")
        self.db.set_background_monitor_state("loaded", "1" if launchctl_loaded else "0")
        self.db.set_background_monitor_state("db_path", str(self.db.path))
        self.db.set_background_monitor_state("notification_status", self.notifications.status())
        self.db.set_background_monitor_state("process_pid", str(os.getpid()))
        self.db.set_background_monitor_state("current_launchctl_domain", launchctl_target())
        self.db.set_background_monitor_state("orphan_process", "1" if not launchctl_loaded else "0")
        self.db.set_background_monitor_state(
            "status_text",
            self._status_text(
                loaded=launchctl_loaded,
                launchctl_running=launchctl_loaded,
                pid_alive=True,
                heartbeat_fresh=True,
            ),
        )
        for key, value in self._detector_enabled_flags.items():
            self.db.set_background_monitor_state(key, value)
        now = time.monotonic()
        if self._last_heartbeat_written == 0.0 or now - self._last_heartbeat_written >= HEARTBEAT_SECONDS:
            self.record_heartbeat()
            self._last_heartbeat_written = now

    def _record_startup_diagnostics(self) -> None:
        self._update_runtime_state()
        diagnostics = {
            "monitor_version": MONITOR_VERSION,
            "pid": os.getpid(),
            "user": getpass.getuser(),
            "uid": os.getuid(),
            "launchctl_domain": launchctl_target(),
            "python_executable": sys.executable,
            "db_path": str(self.db.path),
            "notification_status": self.notifications.status(),
            "enabled_detectors": self.enabled_detectors,
            "polling_interval": self.poll_interval_seconds,
            "last_error": self.db.get_background_monitor_state("last_error", ""),
        }
        self.db.set_background_monitor_state("startup_diagnostics", json.dumps(diagnostics, sort_keys=True))
        self._write_startup_like_log("startup diagnostics", diagnostics)
        launchctl_loaded = bool(self._launchctl_service_status().get("loaded"))
        self.db.set_background_monitor_state(
            "status_text",
            self._status_text(loaded=launchctl_loaded, launchctl_running=launchctl_loaded, pid_alive=True, heartbeat_fresh=True),
        )

    def _write_startup_like_log(self, label: str, payload: dict | None = None) -> None:
        if payload is None:
            payload = {}
        parts = [label]
        for key, value in payload.items():
            parts.append(f"{key}={value}")
        self._write_log_line(" | ".join(parts))

    def _run_camera_detector(self) -> list[BackgroundMonitorEvent]:
        current = self.privacy_monitor.collect_snapshot()
        self.latest_snapshot.update(
            {
                "timestamp": utc_now_iso(),
                "capture_capable_processes": current.capture_capable_processes,
                "screen_sharing_enabled": current.screen_sharing_enabled,
            }
        )
        self._store_current_snapshot()
        events = self.privacy_monitor.evaluate(self.previous_privacy, current)
        if self.previous_privacy is None and current.capture_capable_processes:
            observed_keys = {
                (event.event_type, event.process_name, event.pid, event.evidence)
                for event in events
                if event.event_type == "capture_capable_process_observed"
            }
            for event in self.privacy_monitor.initial_capture_process_events(current):
                key = (event.event_type, event.process_name, event.pid, event.evidence)
                if key not in observed_keys:
                    events.append(event)
        self.previous_privacy = current
        recorded = []
        for event in events:
            if self.record_monitor_event(event):
                recorded.append(event)
        return recorded

    def _run_session_detector(self) -> list[BackgroundMonitorEvent]:
        current = self.session_monitor.collect_snapshot()
        self.latest_snapshot.update(
            {
                "display_state": current.display_state,
                "system_power_state": current.system_power_state,
                "session_locked": current.session_locked,
                "clamshell_state": current.clamshell_state,
            }
        )
        self._store_current_snapshot()
        events = self.session_monitor.evaluate(self.previous_session, current)
        self.previous_session = current
        recorded = []
        for event in events:
            if event.event_type not in IMPORTANT_EVENT_TYPES and event.event_type in {"display_sleep", "display_wake", "possible_lid_closed", "possible_lid_opened", "display_state_changed"}:
                event.confidence = "medium"
            if self.record_monitor_event(event):
                recorded.append(event)
        return recorded

    def _run_sharing_detector(self) -> list[BackgroundMonitorEvent]:
        now = time.monotonic()
        if now - self._last_sharing_poll < SHARING_POLL_SECONDS and self._last_sharing_poll != 0.0:
            return []
        self._last_sharing_poll = now
        current = {
            "remote_login": self._remote_login_enabled(),
            "screen_sharing": self._screen_sharing_enabled(),
            "file_sharing": self._file_sharing_enabled(),
        }
        self.latest_snapshot.update(
            {
                "screen_sharing_enabled": current["screen_sharing"],
                "remote_login_enabled": current["remote_login"],
                "file_sharing_enabled": current["file_sharing"],
            }
        )
        self._store_current_snapshot()
        events: list[BackgroundMonitorEvent] = []
        mapping = {
            "remote_login": ("remote_login_enabled", "remote_login_disabled", "Remote Login"),
            "screen_sharing": ("screen_sharing_enabled", "screen_sharing_disabled", "Screen Sharing"),
            "file_sharing": ("file_sharing_enabled", "file_sharing_disabled", "File Sharing"),
        }
        for key, value in current.items():
            previous = self.sharing_state.get(key)
            self.sharing_state[key] = value
            if previous is None or previous == value:
                continue
            enabled_type, disabled_type, label = mapping[key]
            event = self._build_event(
                enabled_type if value else disabled_type,
                f"{label} is now {'enabled' if value else 'disabled'}.",
                severity="medium" if value else "info",
                confidence="high",
                source="sharing_service_detector",
            )
            if self.record_monitor_event(event):
                events.append(event)
        return events

    def _run_suspicious_process_detector(self) -> list[BackgroundMonitorEvent]:
        events: list[BackgroundMonitorEvent] = []
        for process in self._list_processes():
            args = process.get("args", "")
            for prefix in SUSPICIOUS_PROCESS_PREFIXES:
                if args.startswith(prefix):
                    event = self._build_event(
                        "suspicious_process_observed",
                        f"Process running from suspicious path: {args}",
                        severity="high",
                        confidence="medium",
                        source="suspicious_process_detector",
                        process_name=process.get("name", ""),
                        pid=process.get("pid"),
                    )
                    if self.record_monitor_event(event):
                        events.append(event)
                    break
        return events

    def collect_detector_snapshot(self) -> dict[str, object]:
        snapshot = {
            "timestamp": utc_now_iso(),
            "capture_capable_processes": [],
            "capture_capable_matches": [],
            "display_state": "unknown",
            "system_power_state": "unknown",
            "session_locked": None,
            "screen_sharing_enabled": False,
            "remote_login_enabled": False,
            "clamshell_state": "unknown",
            "raw_ps_lines": [],
            "emitted_event_candidates": [],
            "db_path": str(self.db.path),
        }
        privacy = None
        try:
            privacy = self.privacy_monitor.collect_snapshot()
            snapshot["capture_capable_processes"] = privacy.capture_capable_processes
            snapshot["screen_sharing_enabled"] = privacy.screen_sharing_enabled
            snapshot["raw_ps_lines"] = privacy.raw_ps_lines
            snapshot["capture_capable_matches"] = privacy.capture_capable_processes
            snapshot["emitted_event_candidates"] = [event.to_dict() for event in self.privacy_monitor.evaluate(None, privacy)]
        except Exception as exc:
            self._write_log_line(f"snapshot privacy error: {exc}")
        session = None
        try:
            session = self.session_monitor.collect_snapshot()
            snapshot["display_state"] = session.display_state
            snapshot["system_power_state"] = session.system_power_state
            snapshot["session_locked"] = session.session_locked
            snapshot["clamshell_state"] = session.clamshell_state
        except Exception as exc:
            self._write_log_line(f"snapshot session error: {exc}")
        try:
            snapshot["remote_login_enabled"] = self._remote_login_enabled()
        except Exception as exc:
            self._write_log_line(f"snapshot sharing error: {exc}")
        if privacy is None:
            snapshot["capture_capable_processes"] = snapshot.get("capture_capable_processes", [])
            snapshot["screen_sharing_enabled"] = bool(snapshot.get("screen_sharing_enabled", False))
            snapshot["raw_ps_lines"] = snapshot.get("raw_ps_lines", [])
            snapshot["capture_capable_matches"] = snapshot.get("capture_capable_matches", [])
            snapshot["emitted_event_candidates"] = snapshot.get("emitted_event_candidates", [])
        if session is None:
            snapshot["display_state"] = snapshot.get("display_state", "unknown")
            snapshot["system_power_state"] = snapshot.get("system_power_state", "unknown")
            snapshot["session_locked"] = snapshot.get("session_locked")
            snapshot["clamshell_state"] = snapshot.get("clamshell_state", "unknown")
        self.latest_snapshot = snapshot
        self._store_current_snapshot()
        return snapshot

    def list_orphan_monitor_pids(self) -> list[int]:
        loaded_pid = None
        status = self._launchctl_service_status()
        if status:
            loaded_pid = status.get("pid")
        pids: list[int] = []
        code, stdout, _stderr = self.executor(["/bin/ps", "-axo", "pid=,args="])
        if code != 0:
            return []
        for line in stdout.splitlines():
            parts = line.strip().split(maxsplit=1)
            if len(parts) != 2:
                continue
            try:
                pid = int(parts[0])
            except ValueError:
                continue
            args = parts[1]
            if "--run" not in args:
                continue
            if (
                "mac_audit_agent.monitor" not in args
                and str(runtime_monitor_script_path()) not in args
                and "mac_audit_agent/monitor.py" not in args
            ):
                continue
            if pid == os.getpid() or pid == loaded_pid:
                continue
            if is_pid_alive(pid):
                pids.append(pid)
        return pids

    def stop_orphan_processes(self) -> list[int]:
        stopped: list[int] = []
        for pid in self.list_orphan_monitor_pids():
            try:
                os.kill(pid, signal.SIGTERM)
                stopped.append(pid)
                self._write_log_line(f"stopped orphan monitor pid={pid}")
            except OSError as exc:
                self._write_log_line(f"failed to stop orphan monitor pid={pid} error={exc}")
        return stopped

    def _launchctl_service_status(self) -> dict[str, object]:
        command = ["/bin/launchctl", "print", f"{launchctl_target()}/com.mac-audit-agent.monitor"]
        code, stdout, stderr = self.executor(command)
        if code != 0:
            return {"loaded": False, "error": stderr or stdout}
        match = re.search(r"\bpid = (\d+)\b", stdout)
        return {"loaded": True, "pid": int(match.group(1)) if match else None, "stdout": stdout}

    def _store_current_snapshot(self) -> None:
        if self.latest_snapshot:
            self.db.set_background_monitor_state("current_monitor_snapshot", json.dumps(self.latest_snapshot, sort_keys=True))

    def _load_current_snapshot_state(self) -> dict[str, object]:
        raw = self.db.get_background_monitor_state("current_monitor_snapshot", "")
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def _detector_observed_count(self, detector_name: str) -> int:
        if detector_name == "camera_process_detector" and self.previous_privacy is not None:
            return len(self.previous_privacy.capture_capable_processes)
        if detector_name == "screen_session_detector" and self.previous_session is not None:
            return len(self.previous_session.recent_markers)
        if detector_name == "sharing_service_detector":
            return sum(1 for value in self.sharing_state.values() if value is not None)
        if detector_name == "suspicious_process_detector":
            try:
                return sum(1 for item in self._list_processes() if any(str(item.get("args", "")).startswith(prefix) for prefix in SUSPICIOUS_PROCESS_PREFIXES))
            except Exception:
                return 0
        return 0

    def _list_processes(self) -> list[dict[str, object]]:
        code, stdout, stderr = self.executor(["/bin/ps", "-axo", "pid=,comm=,args="])
        if code != 0:
            raise RuntimeError(stderr or "ps failed")
        processes: list[dict[str, object]] = []
        for raw_line in stdout.splitlines():
            line = raw_line.rstrip()
            if not line.strip():
                continue
            match = PS_LINE_RE.match(line)
            if match:
                pid = int(match.group(1))
                comm = match.group(2).strip()
                args = match.group(3).strip()
            else:
                parts = line.strip().split(maxsplit=2)
                if len(parts) < 2:
                    continue
                try:
                    pid = int(parts[0])
                except ValueError:
                    continue
                comm = parts[1]
                args = parts[2] if len(parts) > 2 else ""
            processes.append({"pid": pid, "name": Path(comm).name, "command": comm, "args": args})
        return processes

    def _remote_login_enabled(self) -> bool:
        code, stdout, stderr = self.executor(["/usr/sbin/systemsetup", "-getremotelogin"])
        if code != 0:
            raise RuntimeError(stderr or stdout or "systemsetup failed")
        return "on" in stdout.lower()

    def _screen_sharing_enabled(self) -> bool:
        code, stdout, stderr = self.executor(["/bin/launchctl", "print", "system/com.apple.screensharing"])
        if code == 0:
            return True
        combined = f"{stdout}\n{stderr}".lower()
        if "could not find service" in combined or "not found" in combined:
            return False
        return self.privacy_monitor._screen_sharing_enabled()

    def _file_sharing_enabled(self) -> bool:
        code, stdout, stderr = self.executor(["/bin/launchctl", "print", "system/com.apple.smbd"])
        if code == 0:
            return True
        combined = f"{stdout}\n{stderr}".lower()
        if "could not find service" in combined or "not found" in combined:
            return False
        return False

    def _record_detector_error(self, detector_name: str, exc: Exception) -> None:
        message = f"run_once error: {exc} | detector={detector_name}"
        self.db.set_background_monitor_state("last_error", message)
        self._write_log_line(message)

    def _status_text(self, *, loaded: bool, launchctl_running: bool, pid_alive: bool, heartbeat_fresh: bool) -> str:
        if not loaded and pid_alive:
            return "orphan monitor process"
        if loaded and not pid_alive and not heartbeat_fresh:
            return "loaded but crashed or exited"
        if pid_alive and not launchctl_running:
            return "running; launchctl state parse uncertain"
        if pid_alive or heartbeat_fresh:
            return "running"
        return "stopped"

    def _build_event(
        self,
        event_type: str,
        evidence: str,
        *,
        severity: str,
        confidence: str,
        source: str,
        simulated: bool = False,
        process_name: str = "",
        pid: int | None = None,
    ) -> BackgroundMonitorEvent:
        return BackgroundMonitorEvent(
            event_id=f"{event_type}-{utc_now_iso()}-{process_name or source}",
            timestamp=utc_now_iso(),
            event_type=event_type,
            severity=severity,
            confidence=confidence,
            source=source,
            evidence=evidence,
            process_name=process_name,
            pid=pid,
            simulated=simulated,
            recommendation="Review the event context and verify whether the activity was expected.",
            metadata_json="{}",
        )

    def _ensure_log_paths(self) -> None:
        for path in [FALLBACK_MONITOR_LOG, STDOUT_MONITOR_LOG, STDERR_MONITOR_LOG]:
            try:
                ensure_monitor_log_file(path)
            except OSError:
                LOGGER.exception("Failed to create monitor log path: %s", path)

    def _ensure_fallback_log_path(self) -> None:
        self._ensure_log_paths()

    def _write_log_line(self, message: str) -> None:
        timestamped = f"{utc_now_iso()} {message}\n"
        for path in [FALLBACK_MONITOR_LOG, STDOUT_MONITOR_LOG]:
            try:
                append_monitor_log_line(path, timestamped)
            except OSError:
                LOGGER.exception("Failed to append monitor log line: %s", path)

    def _run_command(self, command: list[str]) -> tuple[int, str, str]:
        executable = Path(command[0])
        if not executable.exists():
            return 127, "", f"command not found: {command[0]}"
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            return result.returncode, result.stdout, result.stderr
        except FileNotFoundError:
            return 127, "", f"command not found: {command[0]}"
        except Exception as exc:
            return 1, "", str(exc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Background Privacy & Session Monitor")
    parser.add_argument("--db-path", type=Path, default=Path.home() / ".mac_audit_agent.sqlite3")
    parser.add_argument("--poll-interval", type=int, default=5)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--simulate", type=str, default="")
    parser.add_argument("--snapshot", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--stop-orphans", action="store_true")
    parser.add_argument("--doctor", action="store_true")
    parser.add_argument("--test-notification", action="store_true")
    parser.add_argument("--test-dialog", action="store_true")
    parser.add_argument("--notify-force", action="store_true")
    return parser


def _write_crash_details(db_path: Path, exc: BaseException) -> None:
    details = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    timestamped = f"{utc_now_iso()} fatal monitor error:\n{details}"
    for path in [FALLBACK_MONITOR_LOG, STDERR_MONITOR_LOG]:
        try:
            append_monitor_log_line(path, timestamped)
        except OSError:
            LOGGER.exception("Failed to append crash details: %s", path)
    try:
        sys.stderr.write(timestamped)
        sys.stderr.flush()
    except Exception:
        pass
    try:
        db = AuditDatabase(db_path)
        db.set_background_monitor_state("last_error", details.strip())
    except Exception:
        LOGGER.exception("Failed to record monitor crash to SQLite")


def _doctor_payload(service: BackgroundMonitorService) -> tuple[int, dict[str, object]]:
    root = runtime_root()
    monitor_path = runtime_monitor_script_path()
    self_test_command = ["/usr/bin/python3", str(monitor_path), "--self-test", "--db-path", str(service.db.path)]
    payload: dict[str, object] = {
        "plist_path": str(default_launch_agent_paths().plist_path),
        "stdout_log_path": str(STDOUT_MONITOR_LOG),
        "stderr_log_path": str(STDERR_MONITOR_LOG),
        "python_executable": sys.executable,
        "python_executable_exists": Path(sys.executable).exists(),
        "monitor_script_path": str(monitor_path),
        "monitor_script_exists": monitor_path.exists(),
        "working_directory": str(root),
        "working_directory_exists": root.exists(),
        "self_test_command": " ".join(self_test_command),
        "module_import_ok": False,
        "self_test_command_ok": False,
        "plist_valid": False,
        "db_writable": False,
        "detector_cycle_ok": False,
        "logs_directory_exists": STDOUT_MONITOR_LOG.parent.exists(),
        "failures": [],
    }
    failures = payload["failures"]
    assert isinstance(failures, list)
    plist_path = default_launch_agent_paths().plist_path
    if plist_path.exists():
        code, stdout, stderr = service.executor([PLUTIL_BIN, "-lint", str(plist_path)])
        payload["plist_valid"] = code == 0
        if code != 0:
            failures.append(f"plist validation failed: {stderr or stdout or 'plutil failed'}")
        else:
            try:
                plist_payload = plistlib.loads(plist_path.read_bytes())
                program_arguments = list(plist_payload.get("ProgramArguments", []))
                expected_program_arguments = ["/usr/bin/python3", str(monitor_path), "--run"]
                payload["plist_program_arguments"] = program_arguments
                if program_arguments != expected_program_arguments:
                    failures.append(
                        "plist ProgramArguments invalid: expected "
                        f"{expected_program_arguments}, got {program_arguments}"
                    )
                if "-m" in program_arguments or "mac_audit_agent.monitor" in program_arguments:
                    failures.append("plist ProgramArguments still uses -m mac_audit_agent.monitor")
                if any(part for part in program_arguments if "/Documents/" in str(part) or "/Desktop/" in str(part) or "/Downloads/" in str(part)):
                    failures.append("plist ProgramArguments still points to a protected folder path")
            except Exception as exc:
                failures.append(f"plist parse failed: {exc}")
    else:
        failures.append(f"plist missing: {plist_path}")
    if not payload["python_executable_exists"]:
        failures.append(f"python executable missing: {sys.executable}")
    if not payload["monitor_script_exists"]:
        failures.append(f"monitor script missing: {monitor_path}")
    if not payload["working_directory_exists"]:
        failures.append(f"working directory missing: {root}")
    if not payload["logs_directory_exists"]:
        failures.append(f"logs directory missing: {STDOUT_MONITOR_LOG.parent}")
    try:
        __import__("mac_audit_agent.monitor")
        payload["module_import_ok"] = True
    except Exception as exc:
        failures.append(f"module import failed: {exc}")
    if Path(self_test_command[0]).exists() and monitor_path.exists():
        try:
            result = subprocess.run(
                self_test_command,
                capture_output=True,
                text=True,
                cwd=str(root),
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            )
            payload["self_test_command_ok"] = result.returncode == 0
            if result.returncode != 0:
                failures.append(f"self-test command failed: {result.stderr or result.stdout or 'monitor self-test failed'}")
        except Exception as exc:
            failures.append(f"self-test command failed: {exc}")
    else:
        failures.append(f"python executable or monitor script missing: {self_test_command[0]} {monitor_path}")
    try:
        service.db.set_background_monitor_state("doctor_check", utc_now_iso())
        payload["db_writable"] = True
    except Exception as exc:
        failures.append(f"db write failed: {exc}")
    try:
        events = service.run_once()
        payload["detector_cycle_ok"] = True
        payload["detector_cycle_events"] = len(events)
        payload["detector_last_run_timestamp"] = service.db.get_background_monitor_status().detector_last_run_timestamp
    except Exception as exc:
        failures.append(f"detector cycle failed: {exc}")
    if failures:
        payload["failure_reason"] = failures[0]
    return (0 if not failures else 1), payload


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        try:
            service = BackgroundMonitorService(db_path=args.db_path, poll_interval_seconds=args.poll_interval, record_startup=bool(args.run))
        except TypeError:
            service = BackgroundMonitorService(db_path=args.db_path, poll_interval_seconds=args.poll_interval)
    except Exception as exc:
        if args.run:
            _write_crash_details(args.db_path, exc)
            return 1
        raise
    if args.self_test:
        event = service.run_self_test()
        print(f"self_test_event={event.event_type}")
        return 0
    if args.simulate:
        event = service.simulate_event(args.simulate, f"Simulated {args.simulate} from CLI.", severity="medium", notify_force=bool(args.notify_force))
        print(f"simulated_event={event.event_type}")
        return 0
    if args.status:
        print(json.dumps(service.status_payload(), indent=2))
        return 0
    if args.snapshot:
        print(json.dumps(service.collect_detector_snapshot(), indent=2))
        return 0
    if args.test_notification:
        print(json.dumps(service.test_notification(), indent=2))
        return 0
    if args.test_dialog:
        print(json.dumps(service.test_dialog(), indent=2))
        return 0
    if args.stop_orphans:
        print(json.dumps({"stopped_orphans": service.stop_orphan_processes()}, indent=2))
        return 0
    if args.doctor:
        exit_code, payload = _doctor_payload(service)
        print(json.dumps(payload, indent=2))
        return exit_code
    if args.once:
        events = service.run_once()
        payload = {"events_recorded": len(events), "heartbeat": service.db.latest_monitor_heartbeat()}
        if args.verbose:
            payload["snapshot"] = service._load_current_snapshot_state()
            payload["detector_last_run_counts"] = service.db.get_background_monitor_state("detector_last_run_counts", "")
        print(json.dumps(payload, indent=2))
        return 0
    if args.run:
        try:
            service.run_forever()
            return 0
        except Exception as exc:
            _write_crash_details(args.db_path, exc)
            return 1
    service.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
