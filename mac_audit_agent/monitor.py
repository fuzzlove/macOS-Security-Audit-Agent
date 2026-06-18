from __future__ import annotations

import argparse
import hashlib
import json
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
import stat
import traceback
from datetime import datetime, timedelta, timezone

from mac_audit_agent.launch_agent import (
    LAUNCH_AGENT_LABEL,
    MAC_AUDIT_AGENT_ENV_ROLE,
    MONITOR_ROLE_LEGACY,
    MONITOR_ROLE_SYSTEM,
    MONITOR_ROLE_USER,
    PLUTIL_BIN,
    default_launch_agent_paths,
    default_monitor_db_path,
    launchctl_target,
    launch_scope,
    monitor_log_root,
    monitor_script_path,
    project_root,
    verify_protected_monitor_integrity,
    runtime_monitor_script_path,
    runtime_root,
)
from mac_audit_agent.emergency_lockdown import enable_lockdown_with_user_policy
from mac_audit_agent.hardware_monitor import HardwareMonitor, USBReconnectObserver
from mac_audit_agent.models import BackgroundMonitorEvent, EventAlertTrace, utc_now_iso
from mac_audit_agent.rules import canonical_event_type, correlation_id_for, evidence_hash, normalized_signal, rule_for_event
from mac_audit_agent.persistence_monitor import PersistenceMonitor, PersistenceSnapshot
from mac_audit_agent.network_monitor import NetworkMonitor, NetworkStateObserver, NetworkMonitorSnapshot
from mac_audit_agent.notification_manager import ACTIVITY_OVERLAY_EVENT_TYPES, NotificationManager
from mac_audit_agent.models import NotificationCapabilities
from mac_audit_agent.privacy_monitor import PrivacyMonitor, PrivacyMonitorSnapshot
from mac_audit_agent.native_event_bridge import NativeEventBridge
from mac_audit_agent.session_monitor import SessionMonitor, SessionSnapshot, SessionStateObserver
from mac_audit_agent.self_impact_watchdog import MonitorSelfImpactWatchdog, SelfImpactMetrics
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.system_monitor_readiness import process_deployment_event_flow_request
from mac_audit_agent.version import APP_VERSION


LOGGER = logging.getLogger(__name__)
MONITOR_VERSION = APP_VERSION
TRUSTED_USB_DEVICES_STATE_KEY = "trusted_usb_devices_json"
DISCLAIMER = (
    "This monitor records local security events and privacy indicators. "
    "It does not record camera, microphone, screen contents, keystrokes, or packet contents."
)
FALLBACK_MONITOR_LOG = monitor_log_root() / "monitor.log"
STDOUT_MONITOR_LOG = default_launch_agent_paths().stdout_path
STDERR_MONITOR_LOG = default_launch_agent_paths().stderr_path
DEFAULT_FALLBACK_MONITOR_LOG = FALLBACK_MONITOR_LOG
DEFAULT_STDOUT_MONITOR_LOG = STDOUT_MONITOR_LOG
DEFAULT_STDERR_MONITOR_LOG = STDERR_MONITOR_LOG
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
    "launchdaemon_added",
    "launchagent_added",
    "persistence_item_created_high_risk",
    "persistence_item_created",
    "protected_monitor_tamper_detected",
    "major_security_event",
    "alert_storm_detected",
    "monitor_self_impact_warning",
    "monitor_self_test",
}
ALERT_STORM_THRESHOLD = 20
ALERT_STORM_WINDOW_SECONDS = 300
SUSPICIOUS_PROCESS_PREFIXES = ("/tmp", "/var/tmp", "/private/tmp", "/Users/Shared")
SHARING_POLL_SECONDS = 15
HEARTBEAT_SECONDS = 30
DEDUPE_SECONDS = 60
NETWORK_POLL_SECONDS = 2.0
PERSISTENCE_POLL_SECONDS = 10.0
INTEGRITY_POLL_SECONDS = 60.0
LOG_INTEGRITY_MANIFEST_STATE_KEY = "monitor_log_integrity_manifest_json"
LOG_INTEGRITY_CHAIN_STATE_KEY = "monitor_log_integrity_chain_head"
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


def _canonical_json_digest(payload: object) -> str:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _sha256_for_file_prefix(path: Path, byte_count: int | None = None) -> str:
    digest = hashlib.sha256()
    remaining = byte_count
    with path.open("rb") as handle:
        while True:
            if remaining is not None and remaining <= 0:
                break
            read_size = 1024 * 1024 if remaining is None else min(1024 * 1024, remaining)
            chunk = handle.read(read_size)
            if not chunk:
                break
            digest.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    return digest.hexdigest()


def _log_file_integrity_state(path: Path) -> dict[str, object]:
    expanded = path.expanduser()
    if not expanded.exists():
        return {
            "path": str(expanded),
            "exists": False,
            "size": 0,
            "sha256": "",
            "mode": "",
            "owner_uid": None,
            "group_gid": None,
            "world_writable": False,
        }
    stat_result = expanded.stat()
    return {
        "path": str(expanded),
        "exists": True,
        "size": int(stat_result.st_size),
        "sha256": _sha256_for_file_prefix(expanded),
        "mode": oct(stat.S_IMODE(stat_result.st_mode)),
        "owner_uid": int(stat_result.st_uid),
        "group_gid": int(stat_result.st_gid),
        "world_writable": bool(stat_result.st_mode & stat.S_IWOTH),
    }


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


class _DaemonNotificationManager:
    def __init__(self, db) -> None:
        self.db = db

    def settings(self) -> dict[str, object]:
        return {
            "event_preferences": {},
            "notify_min_severity": "info",
            "popup_only_severe_events": False,
            "browser_capture_process_popup": False,
        }

    def event_preferences(self) -> dict[str, dict[str, object]]:
        return {}

    def update_event_preferences(self, preferences: dict[str, dict[str, object]]) -> None:
        self.db.set_background_monitor_state("daemon_event_preferences_json", json.dumps(preferences, sort_keys=True))

    def preference_for(self, event_type: str) -> dict[str, object]:
        if event_type == "monitor_self_impact_warning":
            return {"enabled": True, "severity": "critical", "notify": False, "cooldown_seconds": 900, "notification_mode": "none"}
        return {"enabled": True, "notify": False, "cooldown_seconds": 0, "notification_mode": "none"}

    def status(self) -> str:
        return "system daemon: GUI notifications deferred to user notifier"

    def capabilities(self) -> NotificationCapabilities:
        return NotificationCapabilities(
            overlay_available=False,
            applescript_dialog_available=False,
            notification_center_available=False,
            osascript_exists=Path("/usr/bin/osascript").exists(),
            last_test_time=self.db.get_background_monitor_state("last_test_time", ""),
            last_test_result="system daemon defers GUI notifications to the user notifier",
        )

    def refresh_notification_capabilities(self) -> NotificationCapabilities:
        capabilities = self.capabilities()
        try:
            self.db.set_background_monitor_state("notification_capabilities_json", json.dumps(capabilities.to_dict(), sort_keys=True))
        except Exception:
            pass
        return capabilities

    def readiness_check(self) -> dict[str, object]:
        capabilities = self.refresh_notification_capabilities()
        result = {
            "updated_at": utc_now_iso(),
            "overlay": {"available": False, "attempted": False, "success": False, "error": "system daemon defers GUI notifications"},
            "dialog": {"available": False, "attempted": False, "success": False, "error": "system daemon defers GUI notifications"},
            "notification_center": {"available": False, "attempted": False, "success": False, "error": "system daemon defers GUI notifications"},
            "overall_status": "PASS",
            "reason": "System daemon does not render GUI alerts directly; user notifier handles delivery.",
            "security_alerting_ready": True,
            "notification_center_optional": True,
            "last_test_time": utc_now_iso(),
            "last_test_result": "PASS",
            "capabilities": capabilities.to_dict(),
        }
        self.db.set_background_monitor_state("notification_readiness_json", json.dumps(result, sort_keys=True))
        self.db.set_background_monitor_state("notification_status", self.status())
        return result

    def start_cfaa_login_acknowledgment(self) -> bool:
        return False

    def poll_cfaa_login_acknowledgment(self) -> bool:
        return False

    def reconcile_security_overlay(self) -> bool:
        return False

    def update_security_overlay(self, event: BackgroundMonitorEvent) -> None:
        return None

    def show_visible_security_alert(self, event: BackgroundMonitorEvent, reason: str = "") -> bool:
        self.db.set_background_monitor_state("last_notification_decision", "overlay_deferred")
        self.db.set_background_monitor_state("last_suppression_reason", reason or "system daemon defers GUI notifications")
        return False

    def should_notify(self, event: BackgroundMonitorEvent, *, force: bool = False) -> bool:
        return False

    def notify(self, event: BackgroundMonitorEvent, force: bool = False) -> tuple[bool, str]:
        return False, "system daemon does not show GUI notifications"


class BackgroundMonitorService:
    def __init__(self, db_path: Path, poll_interval_seconds: int = 5, executor=None, record_startup: bool = True, mode: str = MONITOR_ROLE_LEGACY) -> None:
        self.db = AuditDatabase(db_path)
        db_path = Path(db_path).expanduser()
        if db_path.parent not in {Path.home(), default_monitor_db_path("user").parent, default_monitor_db_path("system").parent}:
            local_log_dir = db_path.parent / "logs"
            self.log_paths = [
                local_log_dir / "monitor.log",
                local_log_dir / "background_monitor.stdout.log",
            ]
            self.error_log_paths = [local_log_dir / "background_monitor.stderr.log"]
        else:
            self.log_paths = [FALLBACK_MONITOR_LOG, STDOUT_MONITOR_LOG]
            self.error_log_paths = [STDERR_MONITOR_LOG]
        self.poll_interval_seconds = max(3, min(5, poll_interval_seconds))
        self.executor = executor or self._run_command
        self.record_startup = record_startup
        self.mode = (mode or MONITOR_ROLE_LEGACY).strip().lower()
        self.system_daemon_mode = self.mode == MONITOR_ROLE_SYSTEM
        self.user_notifier_mode = self.mode == MONITOR_ROLE_USER
        self.privacy_monitor = PrivacyMonitor(executor=self.executor)
        self.session_monitor = SessionMonitor(executor=self.executor)
        self.session_observer = SessionStateObserver(self.session_monitor)
        self.hardware_monitor = HardwareMonitor(executor=self.executor)
        self.usb_observer = USBReconnectObserver(self.hardware_monitor)
        self.network_monitor = NetworkMonitor(executor=self.executor)
        self.network_observer = NetworkStateObserver(self.network_monitor, poll_seconds=NETWORK_POLL_SECONDS)
        self.persistence_monitor = PersistenceMonitor(executor=self.executor)
        self.native_event_bridge = NativeEventBridge(self.db)
        self.notifications = NotificationManager(self.db) if not self.system_daemon_mode else _DaemonNotificationManager(self.db)
        self.self_impact_watchdog = MonitorSelfImpactWatchdog()
        self.previous_privacy = None
        self.previous_session = None
        self.previous_hardware = None
        self.previous_network: NetworkMonitorSnapshot | None = None
        self.previous_persistence: PersistenceSnapshot | None = None
        self.sharing_state: dict[str, bool | None] = {"remote_login": None, "screen_sharing": None, "file_sharing": None}
        self.latest_snapshot: dict[str, object] = {}
        self._last_heartbeat_written = 0.0
        self._last_sharing_poll = 0.0
        self._last_integrity_poll = 0.0
        self.enabled_detectors = [
            "camera_process_detector",
            "screen_session_detector",
            "network_state_detector",
            "persistence_detector",
            "sharing_service_detector",
            "suspicious_process_detector",
            "hardware_device_detector",
            "protected_monitor_integrity_detector",
        ]
        self._detector_enabled_flags = {
            "detector_enabled_camera": "1",
            "detector_enabled_session": "1",
            "detector_enabled_network": "1",
            "detector_enabled_persistence": "1",
            "detector_enabled_sharing": "1",
            "detector_enabled_process": "1",
            "detector_enabled_hardware": "1",
            "detector_enabled_integrity": "1",
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
        observers_started = False
        try:
            if self.user_notifier_mode:
                self.notifications.start_cfaa_login_acknowledgment()
            if not self.user_notifier_mode:
                self.session_observer.start()
                self.network_observer.start()
                self.usb_observer.start()
                observers_started = True
            while True:
                if self.user_notifier_mode:
                    self.record_heartbeat()
                    self.process_pending_notifications()
                else:
                    self.notifications.poll_cfaa_login_acknowledgment()
                    self.notifications.start_cfaa_login_acknowledgment()
                    self.notifications.reconcile_security_overlay()
                    self.run_once()
                time.sleep(self.self_impact_watchdog.effective_poll_interval(self.poll_interval_seconds))
        finally:
            if observers_started:
                self.stop_observers()

    def stop_observers(self) -> None:
        for name, observer in (
            ("session_observer", self.session_observer),
            ("network_observer", self.network_observer),
            ("usb_observer", self.usb_observer),
        ):
            try:
                observer.stop()
            except Exception as exc:
                self._write_log_line(f"observer stop failed: {name}: {exc}")
                self.db.set_background_monitor_state(f"{name}_stop_error", str(exc))

    def run_once(self) -> list[BackgroundMonitorEvent]:
        if self.user_notifier_mode:
            self.record_heartbeat()
            return self.process_pending_notifications()
        cycle_started = time.monotonic()
        self._update_runtime_state()
        all_events: list[BackgroundMonitorEvent] = []
        all_events.extend(self.native_event_bridge.drain())
        all_events.extend(process_deployment_event_flow_request(self.db))
        detector_errors: dict[str, str] = {}
        detector_counts: dict[str, dict[str, int]] = {}
        zero_reasons: list[str] = []
        detector_specs = [
            ("camera_process_detector", self._run_camera_detector),
            ("screen_session_detector", self._run_session_detector),
            ("network_state_detector", self._run_network_detector),
            ("persistence_detector", self._run_persistence_detector),
            ("sharing_service_detector", self._run_sharing_detector),
            ("suspicious_process_detector", self._run_suspicious_process_detector),
            ("hardware_device_detector", self._run_hardware_detector),
            ("protected_monitor_integrity_detector", self._run_integrity_detector),
        ]
        zero_reason_map = {
            "camera_process_detector": "no capture-capable process found",
            "screen_session_detector": "no display state change",
            "network_state_detector": "no network IP assignment or VPN state change",
            "persistence_detector": "no persistence inventory change",
            "sharing_service_detector": "no sharing state change",
            "suspicious_process_detector": "no suspicious process found",
            "hardware_device_detector": "no USB topology change or explicit moisture marker found",
            "protected_monitor_integrity_detector": "no protected monitor integrity change",
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
        warning = self._evaluate_self_impact(
            cycle_seconds=time.monotonic() - cycle_started,
            emitted_events=len(all_events),
            detector_errors=len(detector_errors),
        )
        if warning is not None:
            all_events.append(warning)
        return all_events

    def _evaluate_self_impact(
        self,
        *,
        cycle_seconds: float,
        emitted_events: int,
        detector_errors: int,
        metrics: SelfImpactMetrics | None = None,
    ) -> BackgroundMonitorEvent | None:
        metrics = metrics or self.self_impact_watchdog.collect_metrics(
            cycle_seconds=cycle_seconds,
            poll_interval_seconds=self.poll_interval_seconds,
            emitted_events=emitted_events,
            detector_errors=detector_errors,
        )
        assessment = self.self_impact_watchdog.evaluate(metrics)
        payload = assessment.to_dict()
        self.db.set_background_monitor_state("self_impact_last_check", utc_now_iso())
        self.db.set_background_monitor_state("self_impact_score", str(assessment.score))
        self.db.set_background_monitor_state("self_impact_level", assessment.level)
        self.db.set_background_monitor_state("self_impact_backoff_multiplier", str(assessment.backoff_multiplier))
        self.db.set_background_monitor_state("self_impact_metrics_json", json.dumps(payload, sort_keys=True))
        self._write_log_line(
            f"self-impact watchdog: score={assessment.score} level={assessment.level} "
            f"backoff={assessment.backoff_multiplier} metrics={json.dumps(payload['metrics'], sort_keys=True)}"
        )
        active = self.db.get_background_monitor_state("self_impact_warning_active", "0") == "1"
        if not assessment.sustained_warning:
            if assessment.score < 40:
                self.db.set_background_monitor_state("self_impact_warning_active", "0")
            return None
        if active:
            return None
        self.db.set_background_monitor_state("self_impact_warning_active", "1")
        evidence = (
            "The audit agent may be contributing to sustained system resource pressure. "
            f"Self-impact score={assessment.score}/100; detector cycle={metrics.cycle_seconds:.2f}s; "
            f"poll interval={metrics.poll_interval_seconds:.2f}s; CPU={metrics.cpu_percent:.1f}%; "
            f"RSS={metrics.rss_mb:.1f}MB; emitted events={metrics.emitted_events}; "
            f"detector errors={metrics.detector_errors}; bounded polling backoff={assessment.backoff_multiplier}x."
        )
        event = self._build_event(
            "monitor_self_impact_warning",
            evidence,
            severity="critical",
            confidence="high",
            source="self_impact_watchdog",
            trigger_subsource="monitor_cycle_resource_score",
            previous_state="resource pressure below sustained warning threshold",
            current_state=f"sustained self-impact score {assessment.score}/100",
        )
        event.metadata_json = json.dumps(payload, sort_keys=True)
        event.recommendation = (
            "Review monitor health metrics, pause intensive scans, and allow bounded polling backoff to reduce load. "
            "This warning does not claim a denial-of-service condition."
        )
        self.record_monitor_event(event, notify_force=True)
        return event

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
        readiness = self.notifications.readiness_check()
        self.db.set_background_monitor_state("notification_status", self.notifications.status())
        self.db.set_background_monitor_state("notification_readiness_json", json.dumps(readiness, sort_keys=True))
        self._write_log_line(
            "notification readiness: "
            f"overlay={readiness['overlay']['success']} "
            f"dialog={readiness['dialog']['success']} "
            f"notification_center={readiness['notification_center']['success']} "
            f"overall={readiness['overall_status']}"
        )
        return {
            "success": readiness["overall_status"] == "PASS",
            "overall_status": readiness["overall_status"],
            "overlay": readiness["overlay"],
            "dialog": readiness["dialog"],
            "notification_center": readiness["notification_center"],
            "security_alerting_ready": readiness["security_alerting_ready"],
            "notification_center_optional": readiness["notification_center_optional"],
            "last_test_time": readiness["last_test_time"],
            "last_test_result": readiness["last_test_result"],
            "notification_status": self.db.get_background_monitor_state("notification_status", ""),
            "readiness_json": readiness,
            "permission_note": "Notification Center is optional; overlay/dialog are sufficient for security alerting.",
            "event_id": f"notification-readiness-{utc_now_iso()}",
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
        network_event = self._simulate_network_detector_event(target, source=source)
        if network_event is not None:
            network_event.simulated = True
            self.record_monitor_event(network_event, notify_force=notify_force)
            return network_event
        persistence_event = self._simulate_persistence_detector_event(target, source=source)
        if persistence_event is not None:
            persistence_event.simulated = True
            self.record_monitor_event(persistence_event, notify_force=notify_force)
            return persistence_event
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

    def _simulate_network_detector_event(self, event_type: str, *, source: str) -> BackgroundMonitorEvent | None:
        if event_type == "network_ip_assigned":
            return self._build_event(
                "network_ip_assigned",
                "Simulated network IP assignment event.",
                severity="info",
                confidence="high",
                simulated=True,
                source=source,
            )
        if event_type == "new_network_connection_detected":
            return self._build_event(
                "new_network_connection_detected",
                "Simulated new network connection event.",
                severity="high",
                confidence="high",
                simulated=True,
                source=source,
            )
        if event_type == "new_outbound_connection_detected":
            return self._build_event(
                "new_outbound_connection_detected",
                "Simulated new outbound network connection event.",
                severity="high",
                confidence="high",
                simulated=True,
                source=source,
            )
        if event_type == "new_inbound_connection_detected":
            return self._build_event(
                "new_inbound_connection_detected",
                "Simulated new inbound network connection event.",
                severity="critical",
                confidence="high",
                simulated=True,
                source=source,
            )
        if event_type == "vpn_connected":
            return self._build_event(
                "vpn_connected",
                "Simulated VPN connection event.",
                severity="info",
                confidence="high",
                simulated=True,
                source=source,
            )
        return None

    def _simulate_persistence_detector_event(self, event_type: str, *, source: str) -> BackgroundMonitorEvent | None:
        if event_type == "launchdaemon_added":
            return self._build_event(
                "launchdaemon_added",
                "Simulated startup daemon added event.",
                severity="critical",
                confidence="high",
                simulated=True,
                source=source,
            )
        if event_type == "launchagent_added":
            return self._build_event(
                "launchagent_added",
                "Simulated launch agent added event.",
                severity="high",
                confidence="high",
                simulated=True,
                source=source,
            )
        if event_type in {"persistence_item_created", "persistence_item_created_high_risk"}:
            return self._build_event(
                "persistence_item_created_high_risk",
                "Simulated persistence item added event.",
                severity="critical",
                confidence="high",
                simulated=True,
                source=source,
            )
        return None

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
            "detector_enabled_network": status.detector_enabled_network,
            "detector_enabled_persistence": status.detector_enabled_persistence,
            "detector_enabled_sharing": status.detector_enabled_sharing,
            "detector_enabled_process": status.detector_enabled_process,
            "detector_enabled_hardware": status.detector_enabled_hardware,
            "detector_last_zero_reason": status.detector_last_zero_reason,
            "current_snapshot": self._load_current_snapshot_state(),
            "current_snapshot_keys": sorted(self._load_current_snapshot_state().keys()),
            "recent_events": [event.to_dict() for event in self.db.latest_monitor_events(limit=5)],
        }

    def record_monitor_event(self, event: BackgroundMonitorEvent, *, notify_force: bool = False, _skip_storm_detection: bool = False) -> str | None:
        original_event_type = getattr(event, "original_event_type", "") or event.event_type
        canonical_type = canonical_event_type(event.event_type)
        event.original_event_type = original_event_type
        event.normalized_event_type = canonical_type
        event.event_type = canonical_type
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
        trace_id = f"trace-{event.event_id}"
        try:
            self.db.record_event_alert_trace(
                EventAlertTrace(
                    trace_id=trace_id,
                    event_id=event.event_id,
                    event_type=event.event_type,
                    original_event_type=original_event_type,
                    normalized_event_type=canonical_type,
                    detector_source=getattr(event, "trigger_source", "") or event.source,
                    created_at=event.timestamp,
                    stored_db_path=str(self.db.path),
                    stored_success=bool(stored),
                    alert_queue_enqueued=bool(stored),
                    severity_before_policy=event.severity,
                    severity_after_policy=event.severity,
                )
            )
        except Exception as exc:
            self._write_log_line(f"alert trace write failed: event_id={event.event_id} error={exc}")
        if not stored:
            if hasattr(self.notifications, "update_security_overlay"):
                self.notifications.update_security_overlay(event)
            return None
        self._route_log_only_activity_overlay(event)
        force_visible_alert = False
        if not _skip_storm_detection:
            storm_event = self._maybe_build_alert_storm_event(event)
            if storm_event is not None:
                self.record_monitor_event(storm_event, notify_force=True, _skip_storm_detection=True)
        storm_active = self._alert_storm_active(event)
        if storm_active and event.event_type != "alert_storm_detected":
            event.suppression_reason = "alert storm active"
            event.notification_sent = False
            event.notification_error = ""
            event.notification_returncode = None
            event.notification_decision = "log_only"
            event.notification_reason = "alert_storm_active"
            event.popup_allowed = False
            self.db.update_monitor_event_notification(
                event.event_id,
                notification_sent=False,
                notification_error="",
                notification_returncode=None,
                notification_decision="log_only",
                notification_reason="alert_storm_active",
                cooldown_remaining_seconds=event.cooldown_remaining_seconds,
                popup_allowed=False,
                visible_alert_shown=bool(event.visible_alert_shown),
                alert_style=str(event.alert_style or "neutral_grey"),
                cooldown_suppressed=bool(event.cooldown_suppressed),
                last_suppression_reason=event.last_suppression_reason,
            )
        elif self._should_notify_event(event, notify_force=notify_force or force_visible_alert):
            sent, error = self._notify_event(event, notify_force=notify_force or force_visible_alert)
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
                visible_alert_shown=bool(event.visible_alert_shown),
                alert_style=str(event.alert_style or "neutral_grey"),
                cooldown_suppressed=bool(event.cooldown_suppressed),
                last_suppression_reason=event.last_suppression_reason,
            )
        if storm_active and event.event_type == "alert_storm_detected":
            event.popup_allowed = True
        if not storm_active or event.event_type == "alert_storm_detected":
            self.db.update_monitor_event_notification(
                event.event_id,
                notification_sent=event.notification_sent,
                notification_error=event.notification_error,
                notification_returncode=event.notification_returncode,
                notification_decision=event.notification_decision,
                notification_reason=event.notification_reason,
                cooldown_remaining_seconds=event.cooldown_remaining_seconds,
                popup_allowed=event.popup_allowed,
                visible_alert_shown=bool(event.visible_alert_shown),
                alert_style=str(event.alert_style or "neutral_grey"),
                cooldown_suppressed=bool(event.cooldown_suppressed),
                last_suppression_reason=event.last_suppression_reason,
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
        self._evaluate_emergency_lockdown_policy(event)
        return event.event_id

    def _evaluate_emergency_lockdown_policy(self, event: BackgroundMonitorEvent) -> None:
        try:
            action = enable_lockdown_with_user_policy(
                self.db,
                event,
                notice_callback=lambda reason: self.notifications.show_visible_security_alert(
                    event,
                    reason=f"Emergency Lockdown policy: {reason}",
                ),
            )
            ignored = "Event did not meet critical/high-confidence lockdown trigger policy."
            if action.action_attempted != "none" or action.error != ignored:
                self._write_log_line(
                    f"emergency_lockdown: event_id={event.event_id} mode={action.policy_mode} "
                    f"attempted={action.action_attempted} success={action.action_success} error={action.error}"
                )
            if action.action_attempted not in {"none", "recommend_only", "dry_run"} and not action.action_success:
                requires_user_action = bool(getattr(action, "requires_user_action", False))
                failure_event = BackgroundMonitorEvent(
                    event_id=f"lockdown-failed-{event.event_id}",
                    timestamp=utc_now_iso(),
                    event_type="lockdown_mode_requires_user_action" if requires_user_action else "emergency_lockdown_failed",
                    severity="critical",
                    source="emergency_lockdown",
                    evidence=(
                        "A critical security event triggered Emergency Lockdown policy, but macOS requires user confirmation to enable Lockdown Mode. "
                        "The settings panel has been opened. Complete Turn On & Restart to enable Lockdown Mode."
                        if requires_user_action
                        else "Automatic Lockdown Mode activation was requested but could not be verified. "
                        f"Reason: {action.error}"
                    ),
                    confidence="high",
                    recommendation=(
                        "Complete Turn On & Restart in Lockdown Mode settings, then re-check Lockdown Diagnostics."
                        if requires_user_action
                        else "View Lockdown Diagnostics, open the hardening center, and create or review the emergency evidence snapshot."
                    ),
                    metadata_json=json.dumps(action.to_dict(), sort_keys=True),
                )
                self.notifications.show_visible_security_alert(
                    failure_event,
                    reason="Lockdown Mode Requires User Action" if requires_user_action else "Emergency Lockdown Failed",
                    force=True,
                )
        except Exception as exc:
            self.db.set_background_monitor_state("emergency_lockdown_last_failure", str(exc))
            self._write_log_line(f"emergency_lockdown policy failed: event_id={event.event_id} error={exc}")

    def _storm_group_key(self, event: BackgroundMonitorEvent) -> str:
        return "|".join(
            [
                event.event_type,
                event.trigger_source or event.source,
                event.related_process,
                event.related_path,
                event.correlation_id,
            ]
        )

    def _alert_storm_active(self, event: BackgroundMonitorEvent) -> bool:
        raw_until = self.db.get_background_monitor_state("alert_storm_active_until", "")
        if not raw_until:
            return False
        try:
            return datetime.fromisoformat(raw_until) > datetime.fromisoformat(event.timestamp)
        except ValueError:
            return False

    def _maybe_build_alert_storm_event(self, event: BackgroundMonitorEvent) -> BackgroundMonitorEvent | None:
        if event.event_type == "alert_storm_detected":
            return None
        cutoff = datetime.fromisoformat(event.timestamp) - timedelta(seconds=ALERT_STORM_WINDOW_SECONDS)
        recent = [item for item in self.db.recent_background_monitor_events(limit=500) if self._event_time(item) >= cutoff]
        group_key = self._storm_group_key(event)
        grouped = [item for item in recent if self._storm_group_key(item) == group_key]
        if len(grouped) <= ALERT_STORM_THRESHOLD:
            return None
        active_until = self.db.get_background_monitor_state("alert_storm_active_until", "")
        if active_until:
            try:
                if datetime.fromisoformat(active_until) > datetime.fromisoformat(event.timestamp):
                    return None
            except ValueError:
                pass
        event_types = [item.event_type for item in grouped]
        sources = [item.trigger_source or item.source for item in grouped]
        top_event_types = ", ".join(sorted({item for item in event_types})[:5])
        top_sources = ", ".join(sorted({item for item in sources})[:5])
        summary = f"Alert storm detected from {top_sources or 'unknown source'}"
        storm_event = self._build_event(
            "alert_storm_detected",
            f"{summary}; {len(grouped)} events in the last {ALERT_STORM_WINDOW_SECONDS // 60} minutes. Top types: {top_event_types or 'unknown'}.",
            severity="high",
            confidence="medium",
            source="alert_storm_detector",
            rule=rule_for_event("alert_storm_detected"),
            trigger_subsource="alert_storm",
            previous_state="storm not active",
            current_state=f"storm active for {group_key}",
            related_process=event.related_process or event.process_name,
            related_path=event.related_path,
            related_user=event.related_user,
        )
        storm_event.recommendation = "Review the repeated source, verify whether the detector is noisy, and suppress or fix the underlying burst before relying on individual alerts."
        storm_event.raw_signal_summary = summary
        storm_event.source_trace = f"Storm grouping key={group_key}; count={len(grouped)}; top_sources={top_sources}; top_event_types={top_event_types}"
        storm_event.first_seen = min(item.first_seen or item.timestamp for item in grouped)
        storm_event.last_seen = max(item.last_seen or item.timestamp for item in grouped)
        storm_event.previous_state = "no storm"
        storm_event.current_state = f"{len(grouped)} events in {ALERT_STORM_WINDOW_SECONDS // 60} minutes"
        storm_event.false_positive_hints = ["benign noisy app", "broken detector", "automation or install churn"]
        storm_event.recommended_verification_steps = [
            "Check whether the repeated source matches an installer, updater, or looped detector.",
            "Review the event group and confirm whether a detector bug is producing duplicates.",
        ]
        self.db.set_background_monitor_state("alert_storm_active_until", (datetime.fromisoformat(event.timestamp) + timedelta(seconds=ALERT_STORM_WINDOW_SECONDS)).isoformat())
        self.db.set_background_monitor_state("alert_storm_group_key", group_key)
        return storm_event

    def _event_time(self, event: BackgroundMonitorEvent) -> datetime:
        try:
            return datetime.fromisoformat(event.timestamp)
        except ValueError:
            return datetime.fromtimestamp(0, tz=timezone.utc)

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

    def process_pending_notifications(self, limit: int = 200) -> list[BackgroundMonitorEvent]:
        pending = self.db.pending_background_monitor_events(limit=limit)
        now = utc_now_iso()
        self.db.set_background_monitor_state("user_notifier_db_path", str(self.db.path))
        self.db.set_background_monitor_state("notifier_db_path", str(self.db.path))
        self.db.set_background_monitor_state("user_notifier_last_poll", now)
        self.db.set_background_monitor_state("notifier_last_poll", now)
        self.db.set_background_monitor_state("alert_queue_length", str(len(pending)))
        self.db.set_background_monitor_state("queue_length", str(len(pending)))
        self.db.set_background_monitor_state("notifier_running", "1")
        self.db.set_background_monitor_state("notifier_pid", str(os.getpid()))
        self.db.set_background_monitor_state("notifier_loaded", "1")
        self.db.set_background_monitor_state("notifier_pid_alive", "1")
        notified: list[BackgroundMonitorEvent] = []
        seen_count = 0
        alerted_count = 0
        suppressed_count = 0
        pipeline_failure = False
        cursor_before = self.db.get_background_monitor_state("last_event_consumed", "")
        cursor_after = cursor_before
        queue_before = len(pending)
        for event in pending:
            seen_count += 1
            self.db.set_background_monitor_state("user_notifier_last_event_seen", event.timestamp)
            self.db.set_background_monitor_state("notifier_last_event_seen", event.timestamp)
            try:
                self.db.update_event_alert_trace(
                    f"trace-{event.event_id}",
                    notifier_db_path=str(self.db.path),
                    notifier_poll_seen=True,
                    notifier_poll_time=now,
                    notifier_cursor_before=cursor_before,
                    notifier_cursor_after=event.event_id,
                    notifier_seen=True,
                    notifier_seen_at=utc_now_iso(),
                )
            except Exception:
                pass
            if event.notification_sent:
                cursor_after = event.event_id
                self.db.set_background_monitor_state("last_event_consumed", cursor_after)
                self.db.set_background_monitor_state("last_event_consumed_at", event.timestamp)
                continue
            if self._route_log_only_activity_overlay(event, mark_processed=True):
                alerted_count += 1
                self.db.set_background_monitor_state("last_alert_generated", event.event_id)
                self.db.set_background_monitor_state("last_alert_displayed", event.event_id)
                self.db.set_background_monitor_state("notifier_last_alert_displayed", event.event_id)
                cursor_after = event.event_id
                self.db.set_background_monitor_state("last_event_consumed", cursor_after)
                self.db.set_background_monitor_state("last_event_consumed_at", event.timestamp)
                continue
            force_visible_alert = False
            if not self._should_notify_event(event, notify_force=force_visible_alert):
                suppressed_count += 1
                self.db.set_background_monitor_state("last_notification_decision", event.notification_decision or "log_only")
                self.db.set_background_monitor_state("last_suppression_reason", event.last_suppression_reason or event.notification_reason or "log_only")
                cursor_after = event.event_id
                self.db.set_background_monitor_state("last_event_consumed", cursor_after)
                self.db.set_background_monitor_state("last_event_consumed_at", event.timestamp)
                continue
            try:
                sent, error = self._notify_event(event, notify_force=force_visible_alert)
            except Exception as exc:  # noqa: BLE001
                sent = False
                error = str(exc)
                event.notification_sent = False
                event.notification_error = error
                event.notification_returncode = None
                event.notification_decision = event.notification_decision or "notification_error"
                event.notification_reason = event.notification_reason or "notification_pipeline_failure"
                event.last_suppression_reason = event.last_suppression_reason or "notification_pipeline_failure"
                pipeline_failure = True
                self.db.set_background_monitor_state("notification_pipeline_broken", "1")
                self.db.set_background_monitor_state("last_error", f"Notifier delivery failed for {event.event_type}: {error}")
                self._write_log_line(f"notification pipeline error: event_id={event.event_id} event_type={event.event_type} error={error}")
                self.db.update_monitor_event_notification(
                    event.event_id,
                    notification_sent=False,
                    notification_error=error,
                    notification_returncode=None,
                    notification_decision=event.notification_decision,
                    notification_reason=event.notification_reason,
                    cooldown_remaining_seconds=event.cooldown_remaining_seconds,
                    popup_allowed=event.popup_allowed,
                    visible_alert_shown=bool(event.visible_alert_shown),
                    alert_style=str(event.alert_style or "neutral_grey"),
                    cooldown_suppressed=bool(event.cooldown_suppressed),
                    last_suppression_reason=event.last_suppression_reason,
                )
                suppressed_count += 1
                cursor_after = event.event_id
                self.db.set_background_monitor_state("last_event_consumed", cursor_after)
                self.db.set_background_monitor_state("last_event_consumed_at", event.timestamp)
                continue
            event.notification_sent = sent
            event.notification_error = error
            if sent:
                alerted_count += 1
                self.db.set_background_monitor_state("last_alert_generated", event.event_id)
                if bool(event.visible_alert_shown):
                    self.db.set_background_monitor_state("last_alert_displayed", event.event_id)
                    self.db.set_background_monitor_state("notifier_last_alert_displayed", event.event_id)
                self.db.update_monitor_event_notification(
                    event.event_id,
                    notification_sent=event.notification_sent,
                    notification_error=event.notification_error,
                    notification_returncode=event.notification_returncode,
                    notification_decision=event.notification_decision,
                    notification_reason=event.notification_reason,
                    cooldown_remaining_seconds=event.cooldown_remaining_seconds,
                    popup_allowed=event.popup_allowed,
                    visible_alert_shown=bool(event.visible_alert_shown),
                    alert_style=str(event.alert_style or "neutral_grey"),
                    cooldown_suppressed=bool(event.cooldown_suppressed),
                    last_suppression_reason=event.last_suppression_reason,
                )
                notified.append(event)
            else:
                suppressed_count += 1
                self.db.set_background_monitor_state("last_notification_decision", event.notification_decision or "log_only")
                self.db.set_background_monitor_state("last_suppression_reason", event.last_suppression_reason or event.notification_reason or "notification failed")
            cursor_after = event.event_id
            self.db.set_background_monitor_state("last_event_consumed", cursor_after)
            self.db.set_background_monitor_state("last_event_consumed_at", event.timestamp)
        if notified:
            self.db.set_background_monitor_state("user_notifier_last_processed", utc_now_iso())
            self.db.set_background_monitor_state("user_notifier_pending_count", str(len(pending)))
        self.db.set_background_monitor_state("events_found_last_poll", str(seen_count))
        self.db.set_background_monitor_state("events_alerted_last_poll", str(alerted_count))
        self.db.set_background_monitor_state("events_suppressed_last_poll", str(suppressed_count))
        self.db.set_background_monitor_state("notifier_last_event_count", str(seen_count))
        self.db.set_background_monitor_state("notifier_last_alert_count", str(alerted_count))
        self.db.set_background_monitor_state("notifier_last_suppressed_count", str(suppressed_count))
        self.db.set_background_monitor_state("overlay_alive", self.db.get_background_monitor_state("overlay_manager_alive", "0"))
        self.db.set_background_monitor_state("notifier_cursor_before", cursor_before or "")
        self.db.set_background_monitor_state("notifier_cursor_after", cursor_after or cursor_before or "")
        self.db.set_background_monitor_state("alert_queue_length_before", str(queue_before))
        self.db.set_background_monitor_state("alert_queue_length_after", str(len(self.db.pending_background_monitor_events(limit=limit))))
        if pipeline_failure:
            self.db.set_background_monitor_state("notification_pipeline_broken", "1")
        else:
            self.db.set_background_monitor_state("notification_pipeline_broken", "1" if seen_count and not alerted_count and self.db.get_background_monitor_state("notifier_running", "0") != "1" else "0")
        return notified

    def _route_log_only_activity_overlay(self, event: BackgroundMonitorEvent, *, mark_processed: bool = False) -> bool:
        event.event_type = canonical_event_type(event.event_type)
        event.normalized_event_type = event.event_type
        if event.event_type not in ACTIVITY_OVERLAY_EVENT_TYPES:
            return False
        preference = self.notifications.preference_for(event.event_type)
        if bool(preference.get("notify", False)) or str(preference.get("notification_mode", "none")) != "none":
            return False
        if not hasattr(self.notifications, "update_security_overlay"):
            return False
        rendered = bool(self.notifications.update_security_overlay(event))
        if rendered and mark_processed:
            event.notification_sent = True
            event.notification_decision = "overlay_only"
            event.notification_reason = "activity_overlay_rendered"
            event.popup_allowed = False
            event.visible_alert_shown = True
            self.db.update_monitor_event_notification(
                event.event_id,
                notification_sent=True,
                notification_error="",
                notification_returncode=0,
                notification_decision="overlay_only",
                notification_reason="activity_overlay_rendered",
                cooldown_remaining_seconds=0,
                popup_allowed=False,
                visible_alert_shown=True,
                alert_style=str(getattr(event, "alert_style", "neutral_grey") or "neutral_grey"),
                cooldown_suppressed=bool(event.cooldown_suppressed),
                last_suppression_reason=event.last_suppression_reason,
            )
        return rendered

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
        self.db.set_background_monitor_state("monitor_mode", self.mode)
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
        integrity_scope = "system" if self.system_daemon_mode else launch_scope()
        integrity = verify_protected_monitor_integrity(scope=integrity_scope)
        self.db.set_background_monitor_state("monitor_protection_integrity_json", json.dumps(integrity, sort_keys=True))
        self.db.set_background_monitor_state("monitor_protection_integrity_fingerprint", evidence_hash(integrity))
        if integrity_scope == "system" and integrity.get("tamper_detected"):
            event = BackgroundMonitorEvent(
                event_id=f"protected-monitor-tamper-{utc_now_iso()}",
                timestamp=utc_now_iso(),
                event_type="protected_monitor_tamper_detected",
                severity=str(integrity.get("severity", "high")),
                source="integrity_check",
                evidence="; ".join(str(item) for item in integrity.get("evidence", [])),
                confidence=str(integrity.get("confidence", "high")),
                recommendation=str(integrity.get("recommendation", "")),
                metadata_json=json.dumps(integrity, sort_keys=True),
                process_name="com.mac-audit-agent.monitor",
                related_path=str(integrity.get("plist_path", "")),
                related_user="root" if integrity.get("scope") == "system" else getpass.getuser(),
                previous_state="installed and expected" if integrity.get("manifest_exists") else "manifest missing",
                current_state="tampered" if integrity.get("tamper_detected") else "verified",
                baseline_status="expected manifest comparison",
                source_trace=str(integrity.get("manifest_path", "")),
            )
            self.record_monitor_event(event, notify_force=True)
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
        if self.session_observer.running:
            current = self.session_observer.current_snapshot or self.session_monitor.collect_snapshot()
            events = self.session_observer.drain()
            self.latest_snapshot.update(
                {
                    "display_state": current.display_state,
                    "system_power_state": current.system_power_state,
                    "session_locked": current.session_locked,
                    "clamshell_state": current.clamshell_state,
                    "hid_idle_seconds": current.hid_idle_seconds,
                }
            )
            self._store_current_snapshot()
            recorded = []
            for event in events:
                if event.event_type not in IMPORTANT_EVENT_TYPES and event.event_type in {"display_sleep", "display_wake", "possible_lid_closed", "possible_lid_opened", "display_state_changed"}:
                    event.confidence = "medium"
                if self.record_monitor_event(event):
                    recorded.append(event)
            return recorded
        current = self.session_monitor.collect_snapshot()
        self.latest_snapshot.update(
            {
                "display_state": current.display_state,
                "system_power_state": current.system_power_state,
                "session_locked": current.session_locked,
                "clamshell_state": current.clamshell_state,
                "hid_idle_seconds": current.hid_idle_seconds,
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

    def _run_network_detector(self) -> list[BackgroundMonitorEvent]:
        if self.network_observer.running:
            current = self.network_observer.current_snapshot or self.network_monitor.collect_snapshot()
            events = self.network_observer.drain()
            self.latest_snapshot.update(
                {
                    "network_interface": current.interface,
                    "network_ip_address": current.ip_address,
                    "network_netmask": current.netmask,
                    "network_gateway": current.gateway,
                    "network_subnet": current.subnet,
                    "network_scope": current.scope,
                    "network_active_interfaces": current.active_interfaces,
                    "network_dns_servers": current.dns_servers,
                    "vpn_interfaces": current.vpn_interfaces,
                }
            )
            self._store_current_snapshot()
            recorded = []
            for event in events:
                if self.record_monitor_event(event):
                    recorded.append(event)
            self.previous_network = current
            return recorded
        current = self.network_monitor.collect_snapshot()
        self.latest_snapshot.update(
            {
                "network_interface": current.interface,
                "network_ip_address": current.ip_address,
                "network_netmask": current.netmask,
                "network_gateway": current.gateway,
                "network_subnet": current.subnet,
                "network_scope": current.scope,
                "network_active_interfaces": current.active_interfaces,
                "network_dns_servers": current.dns_servers,
                "vpn_interfaces": current.vpn_interfaces,
            }
        )
        self._store_current_snapshot()
        events = self.network_monitor.evaluate(self.previous_network, current)
        self.previous_network = current
        recorded = []
        for event in events:
            if self.record_monitor_event(event):
                recorded.append(event)
        return recorded

    def _run_persistence_detector(self) -> list[BackgroundMonitorEvent]:
        current = self.persistence_monitor.collect_snapshot()
        had_previous = self.previous_persistence is not None
        previous_inventory = self.persistence_monitor.summarize_inventory(self.previous_persistence) if self.previous_persistence else {"launch_daemons": [], "launch_agents": [], "login_items": []}
        current_inventory = self.persistence_monitor.summarize_inventory(current)
        self._write_log_line(f"persistence inventory previous: {json.dumps(previous_inventory, sort_keys=True)}")
        self._write_log_line(f"persistence inventory current: {json.dumps(current_inventory, sort_keys=True)}")
        self.latest_snapshot.update(
            {
                "launch_daemons": current_inventory["launch_daemons"],
                "launch_agents": current_inventory["launch_agents"],
                "login_items": current_inventory["login_items"],
            }
        )
        self._store_current_snapshot()
        events = self.persistence_monitor.evaluate(self.previous_persistence, current)
        self.previous_persistence = current
        recorded: list[BackgroundMonitorEvent] = []
        for event in events:
            if self.record_monitor_event(event):
                recorded.append(event)
        if not had_previous and not events:
            self._write_log_line("persistence baseline established")
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

    def _run_hardware_detector(self) -> list[BackgroundMonitorEvent]:
        current = self.hardware_monitor.collect_snapshot()
        self.latest_snapshot.update(
            {
                "usb_devices": current.usb_devices,
                "bluetooth_devices": current.bluetooth_devices,
                "moisture_detection_capability": current.moisture_capability,
                "moisture_markers": sorted(current.moisture_markers),
            }
        )
        self._store_current_snapshot()
        events = self.hardware_monitor.evaluate(self.previous_hardware, current, include_usb=not self.usb_observer.running)
        events.extend(self._classify_usb_observer_events(self.usb_observer.drain(), current.usb_devices))
        self.previous_hardware = current
        recorded = []
        for event in events:
            if self.record_monitor_event(event):
                recorded.append(event)
        return recorded

    def _run_integrity_detector(self) -> list[BackgroundMonitorEvent]:
        now = time.monotonic()
        if self._last_integrity_poll and now - self._last_integrity_poll < INTEGRITY_POLL_SECONDS:
            return []
        self._last_integrity_poll = now
        events: list[BackgroundMonitorEvent] = []
        integrity = verify_protected_monitor_integrity(scope="system") if self.system_daemon_mode else {"tamper_detected": False}
        log_integrity = self._evaluate_monitor_log_integrity()
        combined_integrity = {
            **integrity,
            "log_integrity": log_integrity,
            "tamper_detected": bool(integrity.get("tamper_detected")) or bool(log_integrity.get("tamper_detected")),
            "severity": "critical" if log_integrity.get("tamper_detected") else str(integrity.get("severity", "high")),
            "confidence": "high" if log_integrity.get("tamper_detected") else str(integrity.get("confidence", "high")),
            "evidence": [*list(integrity.get("evidence", []) or []), *list(log_integrity.get("evidence", []) or [])],
        }
        fingerprint = evidence_hash(combined_integrity)
        previous_fingerprint = self.db.get_background_monitor_state("monitor_protection_integrity_fingerprint", "")
        self.db.set_background_monitor_state("monitor_protection_integrity_json", json.dumps(combined_integrity, sort_keys=True))
        self.db.set_background_monitor_state("monitor_protection_integrity_fingerprint", fingerprint)
        self.latest_snapshot["monitor_protection_integrity"] = combined_integrity
        self._store_current_snapshot()
        if not combined_integrity.get("tamper_detected") or fingerprint == previous_fingerprint:
            return events
        evidence_items = [str(item) for item in combined_integrity.get("evidence", [])]
        event = self._build_event(
            "protected_monitor_tamper_detected",
            "; ".join(evidence_items) or "Protected monitor or log integrity changed from the installed manifest.",
            severity=str(combined_integrity.get("severity", "critical")),
            confidence=str(combined_integrity.get("confidence", "high")),
            source="integrity_check",
            process_name="com.mac-audit-agent.monitor",
            trigger_subsource="protected_runtime_and_log_integrity",
            previous_state="installed manifest expectation",
            current_state="protected monitor or log integrity drift observed",
            related_path=str(log_integrity.get("primary_tamper_path") or combined_integrity.get("plist_path", "")),
            related_user="root",
        )
        event.metadata_json = json.dumps(combined_integrity, sort_keys=True)
        event.recommendation = str(
            combined_integrity.get(
                "recommendation",
                "Review recent administrative activity, preserve evidence, and reinstall the protected monitor from a trusted source if the change was not approved.",
            )
        )
        if self.record_monitor_event(event, notify_force=True):
            events.append(event)
        return events

    def _monitor_log_integrity_paths(self) -> list[Path]:
        return [FALLBACK_MONITOR_LOG.expanduser(), STDOUT_MONITOR_LOG.expanduser(), STDERR_MONITOR_LOG.expanduser()]

    def _record_monitor_log_integrity_manifest(self, *, previous_chain: str = "", reason: str = "baseline") -> dict[str, object]:
        files = [_log_file_integrity_state(path) for path in self._monitor_log_integrity_paths()]
        manifest_body = {
            "schema": "mac-audit-agent-log-integrity-v1",
            "algorithm": "sha256-chain-prefix",
            "recorded_at": utc_now_iso(),
            "reason": reason,
            "files": files,
            "previous_chain_head": previous_chain,
        }
        chain_head = _canonical_json_digest({"previous": previous_chain, "manifest": manifest_body})
        manifest = {**manifest_body, "chain_head": chain_head}
        self.db.set_background_monitor_state(LOG_INTEGRITY_MANIFEST_STATE_KEY, json.dumps(manifest, sort_keys=True))
        self.db.set_background_monitor_state(LOG_INTEGRITY_CHAIN_STATE_KEY, chain_head)
        self.db.set_background_monitor_state("monitor_log_integrity_status", "tracked")
        return manifest

    def _evaluate_monitor_log_integrity(self) -> dict[str, object]:
        previous_raw = self.db.get_background_monitor_state(LOG_INTEGRITY_MANIFEST_STATE_KEY, "")
        previous_chain = self.db.get_background_monitor_state(LOG_INTEGRITY_CHAIN_STATE_KEY, "")
        if not previous_raw:
            manifest = self._record_monitor_log_integrity_manifest(previous_chain=previous_chain, reason="initial_baseline")
            return {
                "tamper_detected": False,
                "status": "baseline_created",
                "algorithm": manifest["algorithm"],
                "chain_head": manifest["chain_head"],
                "evidence": [],
            }
        try:
            previous_manifest = json.loads(previous_raw)
        except json.JSONDecodeError:
            manifest = self._record_monitor_log_integrity_manifest(previous_chain=previous_chain, reason="manifest_recovered_after_corruption")
            return {
                "tamper_detected": True,
                "status": "manifest_corrupt",
                "algorithm": manifest["algorithm"],
                "chain_head": manifest["chain_head"],
                "primary_tamper_path": str(default_monitor_db_path("system" if self.system_daemon_mode else "user")),
                "evidence": ["monitor log integrity manifest in SQLite was corrupt or unreadable"],
            }

        evidence: list[str] = []
        primary_tamper_path = ""
        previous_by_path = {str(item.get("path", "")): item for item in previous_manifest.get("files", []) if isinstance(item, dict)}
        current_files = [_log_file_integrity_state(path) for path in self._monitor_log_integrity_paths()]
        for current in current_files:
            path = str(current.get("path", ""))
            previous = previous_by_path.get(path)
            if previous is None:
                continue
            if bool(current.get("world_writable")):
                evidence.append(f"log file is world writable: {path}")
                primary_tamper_path = primary_tamper_path or path
            if bool(previous.get("exists")) and not bool(current.get("exists")):
                evidence.append(f"log file was deleted or destroyed: {path}")
                primary_tamper_path = primary_tamper_path or path
                continue
            if not bool(previous.get("exists")) and bool(current.get("exists")):
                continue
            if not bool(current.get("exists")):
                continue
            if previous.get("mode") and current.get("mode") != previous.get("mode"):
                evidence.append(f"log file mode changed: {path} {previous.get('mode')} -> {current.get('mode')}")
                primary_tamper_path = primary_tamper_path or path
            if previous.get("owner_uid") is not None and current.get("owner_uid") != previous.get("owner_uid"):
                evidence.append(f"log file owner changed: {path} uid {previous.get('owner_uid')} -> {current.get('owner_uid')}")
                primary_tamper_path = primary_tamper_path or path
            previous_size = int(previous.get("size", 0) or 0)
            current_size = int(current.get("size", 0) or 0)
            previous_sha = str(previous.get("sha256", "") or "")
            current_sha = str(current.get("sha256", "") or "")
            if current_size < previous_size:
                evidence.append(f"log file was truncated: {path} {previous_size} -> {current_size} bytes")
                primary_tamper_path = primary_tamper_path or path
            elif current_size == previous_size and previous_sha and current_sha != previous_sha:
                evidence.append(f"log file content changed in place: {path}")
                primary_tamper_path = primary_tamper_path or path
            elif current_size > previous_size and previous_sha:
                try:
                    prefix_sha = _sha256_for_file_prefix(Path(path), previous_size)
                except OSError:
                    prefix_sha = ""
                if prefix_sha != previous_sha:
                    evidence.append(f"log file earlier bytes changed before append: {path}")
                    primary_tamper_path = primary_tamper_path or path
        for path in self._monitor_log_integrity_paths():
            try:
                ensure_monitor_log_file(path)
            except OSError:
                pass
        reason = "tamper_rebaseline" if evidence else "append_only_update"
        manifest = self._record_monitor_log_integrity_manifest(previous_chain=previous_chain, reason=reason)
        status = "tamper_detected" if evidence else "verified_append_only"
        self.db.set_background_monitor_state("monitor_log_integrity_status", status)
        return {
            "tamper_detected": bool(evidence),
            "status": status,
            "algorithm": manifest["algorithm"],
            "chain_head": manifest["chain_head"],
            "previous_chain_head": previous_chain,
            "primary_tamper_path": primary_tamper_path,
            "evidence": evidence,
            "files": manifest["files"],
        }

    def _coalesce_usb_observer_events(self, events: list[BackgroundMonitorEvent]) -> list[BackgroundMonitorEvent]:
        if not events:
            return events
        labels = sorted({self._usb_observer_label(event) for event in events})
        summary = "; ".join(labels[:4])
        if len(labels) > 4:
            summary += f"; and {len(labels) - 4} more"
        return [
            self._build_event(
                "usb_device_connected",
                f"USB reconnect recognized {len(labels)} device(s): {summary}.",
                severity="info",
                confidence="high",
                source="ioreg_usb_observer",
            )
        ]

    def _classify_usb_observer_events(
        self,
        events: list[BackgroundMonitorEvent],
        current_devices: list[dict[str, str]],
    ) -> list[BackgroundMonitorEvent]:
        raw_trusted = self.db.get_background_monitor_state(TRUSTED_USB_DEVICES_STATE_KEY, "")
        current_identities = {self.hardware_monitor.usb_physical_key(item) for item in current_devices}
        if not raw_trusted:
            self._store_trusted_usb_identities(current_identities)
            return self._coalesce_usb_observer_events(events)
        try:
            trusted = set(json.loads(raw_trusted))
        except json.JSONDecodeError:
            trusted = set()
        new_events = [event for event in events if self._usb_event_physical_key(event) not in trusted]
        if not new_events:
            return self._coalesce_usb_observer_events(events)
        trusted.update(self._usb_event_physical_key(event) for event in new_events)
        self._store_trusted_usb_identities(trusted)
        labels = sorted({self._usb_observer_label(event) for event in new_events})
        summary = "; ".join(labels[:4])
        if len(labels) > 4:
            summary += f"; and {len(labels) - 4} more"
        return [
            self._build_event(
                "new_usb_device_detected",
                f"New USB device identity detected: {summary}.",
                severity="critical",
                confidence="high",
                source="ioreg_usb_observer",
            )
        ]

    def _usb_event_physical_key(self, event: BackgroundMonitorEvent) -> str:
        try:
            metadata = json.loads(event.metadata_json)
        except json.JSONDecodeError:
            metadata = {}
        return self.hardware_monitor.usb_physical_key(metadata)

    def _store_trusted_usb_identities(self, identities: set[str]) -> None:
        self.db.set_background_monitor_state(TRUSTED_USB_DEVICES_STATE_KEY, json.dumps(sorted(identities)))

    def _usb_observer_label(self, event: BackgroundMonitorEvent) -> str:
        try:
            metadata = json.loads(event.metadata_json)
        except json.JSONDecodeError:
            metadata = {}
        vendor = str(metadata.get("vendor", "")).strip()
        name = str(metadata.get("name", "")).strip()
        serial = str(metadata.get("serial", "")).strip()
        label = f"{vendor} {name}".strip()
        if label:
            return f"{label} (serial={serial})" if serial else label
        return event.evidence.removeprefix("USB device recognized: ").removesuffix(".")

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
        try:
            current_network = self.network_monitor.collect_snapshot()
            snapshot["network_interface"] = current_network.interface
            snapshot["network_ip_address"] = current_network.ip_address
            snapshot["network_netmask"] = current_network.netmask
            snapshot["network_gateway"] = current_network.gateway
            snapshot["network_subnet"] = current_network.subnet
            snapshot["network_scope"] = current_network.scope
            snapshot["vpn_interfaces"] = current_network.vpn_interfaces
        except Exception as exc:
            self._write_log_line(f"snapshot network error: {exc}")
        try:
            current_persistence = self.persistence_monitor.collect_snapshot()
            current_inventory = self.persistence_monitor.summarize_inventory(current_persistence)
            snapshot["launch_daemons"] = current_inventory["launch_daemons"]
            snapshot["launch_agents"] = current_inventory["launch_agents"]
            snapshot["login_items"] = current_inventory["login_items"]
        except Exception as exc:
            self._write_log_line(f"snapshot persistence error: {exc}")
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
        if detector_name == "persistence_detector" and self.previous_persistence is not None:
            return len(self.previous_persistence.launch_items) + len(self.previous_persistence.login_items)
        if detector_name == "sharing_service_detector":
            return sum(1 for value in self.sharing_state.values() if value is not None)
        if detector_name == "suspicious_process_detector":
            try:
                return sum(1 for item in self._list_processes() if any(str(item.get("args", "")).startswith(prefix) for prefix in SUSPICIOUS_PROCESS_PREFIXES))
            except Exception:
                return 0
        if detector_name == "hardware_device_detector" and self.previous_hardware is not None:
            return len(self.previous_hardware.usb_devices) + len(self.previous_hardware.bluetooth_devices) + len(self.previous_hardware.moisture_markers)
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
        rule=None,
        trigger_subsource: str = "",
        previous_state: str = "",
        current_state: str = "",
        related_path: str = "",
        related_user: str = "",
        related_network_endpoint: str = "",
        related_url: str = "",
        related_dom_selector: str = "",
        related_file_hash: str = "",
        related_parent_pid: int | None = None,
        related_process: str = "",
    ) -> BackgroundMonitorEvent:
        rule = rule or rule_for_event(event_type)
        raw_signal = evidence
        timestamp = utc_now_iso()
        event = BackgroundMonitorEvent(
            event_id=f"{event_type}-{timestamp}-{process_name or source}",
            timestamp=timestamp,
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
            rule_id=rule.rule_id,
            rule_name=rule.name,
            trigger_source=source,
            trigger_subsource=trigger_subsource or source,
            trigger_rule_id=rule.rule_id,
            trigger_rule_name=rule.name,
            raw_signal_summary=raw_signal,
            normalized_signal=normalized_signal(event_type, raw_signal, process_name, pid, related_path, related_user),
            evidence_hash=evidence_hash(event_type, raw_signal, process_name, pid, related_path, related_user),
            related_process=related_process or process_name,
            related_pid=pid,
            related_parent_pid=related_parent_pid,
            related_path=related_path,
            related_user=related_user,
            related_network_endpoint=related_network_endpoint,
            related_url=related_url,
            related_dom_selector=related_dom_selector,
            related_file_hash=related_file_hash,
            first_seen=timestamp,
            last_seen=timestamp,
            previous_state=previous_state,
            current_state=current_state,
            baseline_status="monitor observation",
            correlation_id=correlation_id_for(event_type, source, process_name, related_path, related_user, timestamp=timestamp),
            false_positive_hints=list(rule.false_positive_hints),
            recommended_verification_steps=list(rule.verification_steps),
            source_trace=f"Detector={rule.source_detector}; Rule={rule.rule_id}; Evidence={raw_signal}",
        )
        event.original_event_type = event_type
        event.normalized_event_type = canonical_event_type(event_type)
        return event

    def _ensure_log_paths(self) -> None:
        for path in [*self._active_log_paths(), *self._active_error_log_paths()]:
            try:
                ensure_monitor_log_file(path)
            except OSError:
                LOGGER.exception("Failed to create monitor log path: %s", path)

    def _ensure_fallback_log_path(self) -> None:
        self._ensure_log_paths()

    def _write_log_line(self, message: str) -> None:
        timestamped = f"{utc_now_iso()} {message}\n"
        for path in self._active_log_paths():
            try:
                append_monitor_log_line(path, timestamped)
            except OSError:
                LOGGER.exception("Failed to append monitor log line: %s", path)

    def _active_log_paths(self) -> list[Path]:
        paths = list(getattr(self, "log_paths", [FALLBACK_MONITOR_LOG, STDOUT_MONITOR_LOG]))
        for current, default in [(FALLBACK_MONITOR_LOG, DEFAULT_FALLBACK_MONITOR_LOG), (STDOUT_MONITOR_LOG, DEFAULT_STDOUT_MONITOR_LOG)]:
            if current != default and current not in paths:
                paths.append(current)
        return paths

    def _active_error_log_paths(self) -> list[Path]:
        paths = list(getattr(self, "error_log_paths", [STDERR_MONITOR_LOG]))
        if STDERR_MONITOR_LOG != DEFAULT_STDERR_MONITOR_LOG and STDERR_MONITOR_LOG not in paths:
            paths.append(STDERR_MONITOR_LOG)
        return paths

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
    parser.add_argument("--db-path", type=Path, default=None)
    parser.add_argument("--poll-interval", type=int, default=5)
    parser.add_argument("--mode", choices=[MONITOR_ROLE_LEGACY, MONITOR_ROLE_USER, MONITOR_ROLE_SYSTEM], default=os.environ.get(MAC_AUDIT_AGENT_ENV_ROLE, MONITOR_ROLE_LEGACY))
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


def _resolve_monitor_db_path(db_path: Path | None, mode: str) -> Path:
    if db_path is not None:
        return db_path
    if mode == MONITOR_ROLE_SYSTEM:
        return default_monitor_db_path("system")
    return default_monitor_db_path("user")


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
    args.db_path = _resolve_monitor_db_path(args.db_path, args.mode)
    try:
        try:
            service = BackgroundMonitorService(db_path=args.db_path, poll_interval_seconds=args.poll_interval, record_startup=bool(args.run), mode=args.mode)
        except TypeError:
            try:
                service = BackgroundMonitorService(db_path=args.db_path, poll_interval_seconds=args.poll_interval, record_startup=bool(args.run))
            except TypeError:
                try:
                    service = BackgroundMonitorService(db_path=args.db_path, poll_interval_seconds=args.poll_interval, mode=args.mode)
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
