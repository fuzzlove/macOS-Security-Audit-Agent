from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from mac_audit_agent.notification_manager import OVERLAY_STATE_PATH
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.models import utc_now_iso


VisibilityStatus = Literal["healthy", "degraded", "failing", "disabled", "unsupported"]
STATUS_POINTS = {"healthy": 10, "degraded": 6, "unsupported": 5, "disabled": 3, "failing": 0}
STALE_HEARTBEAT_SECONDS = 180
STALE_DETECTOR_SECONDS = 900
STALE_FORECAST_SECONDS = 24 * 60 * 60
BACKLOG_DEGRADED_COUNT = 25
BACKLOG_FAILING_COUNT = 100


def _parse_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _age_seconds(value: str) -> int | None:
    parsed = _parse_timestamp(value)
    if parsed is None:
        return None
    return max(0, int((datetime.now(timezone.utc) - parsed).total_seconds()))


@dataclass(frozen=True)
class VisibilityComponentStatus:
    component_name: str
    status: VisibilityStatus
    last_success: str = ""
    last_error: str = ""
    evidence: str = ""
    recommended_fix: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VisibilityIntegrityReport:
    generated_at: str
    score: int
    overall_status: VisibilityStatus
    components: list[VisibilityComponentStatus] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        degraded = [item.to_dict() for item in self.components if item.status == "degraded"]
        failing = [item.to_dict() for item in self.components if item.status == "failing"]
        return {
            "generated_at": self.generated_at,
            "VisibilityIntegrityScore": self.score,
            "score": self.score,
            "overall_status": self.overall_status,
            "components": [item.to_dict() for item in self.components],
            "degraded_components": degraded,
            "failing_components": failing,
            "recommended_fixes": [
                {"component_name": item.component_name, "recommended_fix": item.recommended_fix}
                for item in self.components
                if item.status in {"degraded", "failing", "disabled"} and item.recommended_fix
            ],
        }


class VisibilityIntegrityEngine:
    def __init__(
        self,
        db: AuditDatabase,
        *,
        reports_dir: Path | None = None,
        overlay_state_path: Path | None = None,
    ) -> None:
        self.db = db
        self.reports_dir = reports_dir or (Path.home() / "Library" / "Application Support" / "MacAuditAgent" / "reports")
        self.overlay_state_path = overlay_state_path or OVERLAY_STATE_PATH

    def build_report(self) -> VisibilityIntegrityReport:
        components = [
            self._monitor_heartbeat(),
            self._system_daemon_status(),
            self._user_notifier_status(),
            self._sqlite_health(),
            self._detector_freshness(),
            self._alert_overlay_health(),
            self._event_backlog(),
            self._last_successful_event_delivery(),
            self._apple_exposure_freshness(),
            self._report_export_health(),
        ]
        score = self._score(components)
        return VisibilityIntegrityReport(
            generated_at=utc_now_iso(),
            score=score,
            overall_status=self._overall_status(components),
            components=components,
        )

    def _monitor_status(self):
        return self.db.get_background_monitor_status()

    def _monitor_heartbeat(self) -> VisibilityComponentStatus:
        try:
            heartbeat = self.db.latest_monitor_heartbeat()
        except Exception as exc:
            return VisibilityComponentStatus("Monitor Heartbeat", "failing", last_error=str(exc), evidence="Unable to read heartbeat.", recommended_fix="Repair SQLite access and restart monitoring.")
        age = _age_seconds(heartbeat)
        if not heartbeat:
            return VisibilityComponentStatus("Monitor Heartbeat", "degraded", evidence="No heartbeat has been recorded.", recommended_fix="Start monitoring and verify heartbeat writes.")
        if age is None:
            return VisibilityComponentStatus("Monitor Heartbeat", "degraded", last_success=heartbeat, evidence="Heartbeat timestamp is unreadable.", recommended_fix="Restart monitoring to write a fresh timestamp.")
        if age > STALE_HEARTBEAT_SECONDS:
            return VisibilityComponentStatus("Monitor Heartbeat", "failing", last_success=heartbeat, evidence=f"Heartbeat age is {age}s.", recommended_fix="Restart the monitor and verify heartbeat writes.")
        return VisibilityComponentStatus("Monitor Heartbeat", "healthy", last_success=heartbeat, evidence=f"Heartbeat age is {age}s.", recommended_fix="No action required.")

    def _system_daemon_status(self) -> VisibilityComponentStatus:
        try:
            status = self._monitor_status()
        except Exception as exc:
            return VisibilityComponentStatus("System Daemon Status", "failing", last_error=str(exc), evidence="Unable to read monitor status.", recommended_fix="Repair monitor database access.")
        if not status.installed:
            return VisibilityComponentStatus("System Daemon Status", "disabled", evidence="System daemon is not installed.", recommended_fix="Install the system daemon only when continuous system monitoring is intended.")
        if not status.loaded and not status.running:
            return VisibilityComponentStatus("System Daemon Status", "failing", last_error=status.last_error, evidence=f"installed={status.installed} loaded={status.loaded} running={status.running}", recommended_fix="Start or repair the system daemon.")
        if status.last_error:
            return VisibilityComponentStatus("System Daemon Status", "degraded", last_error=status.last_error, evidence=f"pid={status.process_pid}", recommended_fix="Review daemon logs and clear the error only after verification.")
        return VisibilityComponentStatus("System Daemon Status", "healthy", last_success=status.last_heartbeat, evidence=f"loaded={status.loaded} running={status.running} pid={status.process_pid}", recommended_fix="No action required.")

    def _user_notifier_status(self) -> VisibilityComponentStatus:
        try:
            monitor_status = self._monitor_status()
            notification_status = (monitor_status.notification_status or self.db.get_background_monitor_state("notification_status", "unknown")).lower()
            notifier_running = self.db.get_background_monitor_state("notifier_running", "")
            notifier_installed = self.db.get_background_monitor_state("notifier_installed", "")
            notifier_loaded = self.db.get_background_monitor_state("notifier_loaded", "")
        except Exception as exc:
            return VisibilityComponentStatus("User Notifier Status", "failing", last_error=str(exc), evidence="Unable to read notifier state.", recommended_fix="Repair SQLite access and notifier state.")
        if "disabled" in notification_status or self.db.get_background_monitor_state("show_visible_alerts", "1") == "0":
            return VisibilityComponentStatus("User Notifier Status", "disabled", evidence=f"notification_status={notification_status}", recommended_fix="Re-enable visible alerts if user notifications are expected.")
        if "not running" in notification_status or notifier_running == "0" or (notifier_installed == "1" and notifier_loaded == "0"):
            return VisibilityComponentStatus("User Notifier Status", "failing", last_error=monitor_status.last_error, evidence=f"notification_status={notification_status} running={notifier_running} loaded={notifier_loaded}", recommended_fix="Start or repair the user notifier.")
        if notification_status in {"unknown", ""}:
            return VisibilityComponentStatus("User Notifier Status", "degraded", evidence="Notifier status is unknown.", recommended_fix="Run notification verification from Background Monitor.")
        return VisibilityComponentStatus("User Notifier Status", "healthy", last_success=self.db.get_background_monitor_state("notifier_last_poll", ""), evidence=f"notification_status={notification_status}", recommended_fix="No action required.")

    def _sqlite_health(self) -> VisibilityComponentStatus:
        try:
            quick = self.db.conn.execute("PRAGMA quick_check").fetchone()
            quick_value = str(quick[0] if quick else "")
            if quick_value.lower() != "ok":
                return VisibilityComponentStatus("SQLite Health", "failing", last_error=quick_value, evidence="PRAGMA quick_check failed.", recommended_fix="Inspect, restore, or rebuild the database.")
            self.db.conn.execute("SELECT COUNT(*) FROM background_monitor_state").fetchone()
            return VisibilityComponentStatus("SQLite Health", "healthy", last_success=utc_now_iso(), evidence=f"quick_check={quick_value}", recommended_fix="No action required.")
        except Exception as exc:
            return VisibilityComponentStatus("SQLite Health", "failing", last_error=str(exc), evidence="Unable to query required monitor tables.", recommended_fix="Fix database permissions, schema, or restore from backup.")

    def _detector_freshness(self) -> VisibilityComponentStatus:
        try:
            status = self._monitor_status()
            timestamp = status.detector_last_run_timestamp
            errors = status.detector_errors
        except Exception as exc:
            return VisibilityComponentStatus("Detector Freshness", "failing", last_error=str(exc), evidence="Unable to read detector state.", recommended_fix="Repair monitor state access.")
        age = _age_seconds(timestamp)
        if errors:
            return VisibilityComponentStatus("Detector Freshness", "degraded", last_success=timestamp, last_error=errors, evidence="Detector errors are present.", recommended_fix="Review detector errors and restart monitoring.")
        if not timestamp:
            return VisibilityComponentStatus("Detector Freshness", "degraded", evidence="No detector run timestamp is available.", recommended_fix="Start monitoring or run event flow verification.")
        if age is None:
            return VisibilityComponentStatus("Detector Freshness", "degraded", last_success=timestamp, evidence="Detector timestamp is unreadable.", recommended_fix="Restart monitoring.")
        if age > STALE_DETECTOR_SECONDS:
            return VisibilityComponentStatus("Detector Freshness", "degraded", last_success=timestamp, evidence=f"Detector last ran {age}s ago.", recommended_fix="Restart background monitoring and verify detector events.")
        enabled = {
            "camera": status.detector_enabled_camera,
            "session": status.detector_enabled_session,
            "network": status.detector_enabled_network,
            "persistence": status.detector_enabled_persistence,
            "sharing": status.detector_enabled_sharing,
            "process": status.detector_enabled_process,
            "hardware": status.detector_enabled_hardware,
        }
        disabled = [name for name, value in enabled.items() if not value]
        if disabled:
            return VisibilityComponentStatus("Detector Freshness", "degraded", last_success=timestamp, evidence=f"Detector age {age}s; disabled detectors: {', '.join(disabled)}", recommended_fix="Enable required detectors or document why they are disabled.")
        return VisibilityComponentStatus("Detector Freshness", "healthy", last_success=timestamp, evidence=f"Detector age {age}s.", recommended_fix="No action required.")

    def _alert_overlay_health(self) -> VisibilityComponentStatus:
        try:
            overlay_error = self.db.get_background_monitor_state("last_overlay_error", "")
            overlay_status = self.db.get_background_monitor_state("security_overlay_status", "")
            if overlay_error:
                return VisibilityComponentStatus("Alert Overlay Health", "degraded", last_error=overlay_error, evidence=f"overlay_status={overlay_status}", recommended_fix="Repair overlay launch or state file permissions.")
            self.overlay_state_path.parent.mkdir(parents=True, exist_ok=True)
            test_path = self.overlay_state_path.with_name(".visibility_overlay_write_test")
            test_path.write_text("ok", encoding="utf-8")
            test_path.unlink(missing_ok=True)
            return VisibilityComponentStatus("Alert Overlay Health", "healthy", last_success=utc_now_iso(), evidence=f"overlay_status={overlay_status or 'available'}", recommended_fix="No action required.")
        except Exception as exc:
            return VisibilityComponentStatus("Alert Overlay Health", "degraded", last_error=str(exc), evidence=f"overlay_path={self.overlay_state_path}", recommended_fix="Fix overlay state path permissions or use the fallback overlay path.")

    def _event_backlog(self) -> VisibilityComponentStatus:
        try:
            pending = self.db.pending_background_monitor_events(limit=BACKLOG_FAILING_COUNT + 1)
            count = len(pending)
        except Exception as exc:
            return VisibilityComponentStatus("Event Backlog", "failing", last_error=str(exc), evidence="Unable to read pending event queue.", recommended_fix="Repair database access and notifier cursor state.")
        if count > BACKLOG_FAILING_COUNT:
            return VisibilityComponentStatus("Event Backlog", "failing", evidence=f"Pending events exceed {BACKLOG_FAILING_COUNT}.", recommended_fix="Repair notifier consumption and inspect alert pipeline traces.")
        if count >= BACKLOG_DEGRADED_COUNT:
            return VisibilityComponentStatus("Event Backlog", "degraded", evidence=f"Pending events={count}.", recommended_fix="Check notifier status and event queue cursor.")
        return VisibilityComponentStatus("Event Backlog", "healthy", evidence=f"Pending events={count}.", recommended_fix="No action required.")

    def _last_successful_event_delivery(self) -> VisibilityComponentStatus:
        try:
            deliveries = self.db.latest_alert_delivery_records(limit=25)
            success = next((item for item in deliveries if item.overlay_success or item.dialog_success or item.notification_success), None)
            traces = self.db.latest_event_alert_traces(limit=25)
            failure = next((item for item in traces if item.alert_required and item.alert_suppressed), None)
        except Exception as exc:
            return VisibilityComponentStatus("Last Successful Event Delivery", "failing", last_error=str(exc), evidence="Unable to inspect delivery records.", recommended_fix="Repair alert delivery record storage.")
        if success:
            return VisibilityComponentStatus("Last Successful Event Delivery", "healthy", last_success=success.updated_at, evidence=f"event_id={success.event_id} method={success.delivery_method_used}", recommended_fix="No action required.")
        if failure:
            return VisibilityComponentStatus("Last Successful Event Delivery", "degraded", last_success=failure.created_at, last_error=failure.alert_suppression_reason, evidence=f"latest suppressed event={failure.event_id}", recommended_fix="Review notification policy and suppression reason.")
        return VisibilityComponentStatus("Last Successful Event Delivery", "degraded", evidence="No successful visible delivery record found.", recommended_fix="Run visible alert verification.")

    def _apple_exposure_freshness(self) -> VisibilityComponentStatus:
        try:
            forecast_json = self.db.get_background_monitor_state("apple_security_forecast_last_success", "")
            if not forecast_json:
                row = self.db.conn.execute("SELECT generated_at, level FROM apple_security_forecasts ORDER BY generated_at DESC LIMIT 1").fetchone()
                timestamp = str(row["generated_at"] if row else "")
                level = str(row["level"] if row else "")
            else:
                timestamp = forecast_json
                level = self.db.get_background_monitor_state("apple_security_forecast_level", "")
        except Exception as exc:
            return VisibilityComponentStatus("Apple Exposure Assessment Freshness", "degraded", last_error=str(exc), evidence="Unable to inspect Apple Exposure Assessment freshness.", recommended_fix="Refresh Apple Exposure Assessment.")
        if not timestamp:
            return VisibilityComponentStatus("Apple Exposure Assessment Freshness", "degraded", evidence="No Apple Exposure Assessment timestamp found.", recommended_fix="Run Apple Exposure Assessment.")
        age = _age_seconds(timestamp)
        if age is None:
            return VisibilityComponentStatus("Apple Exposure Assessment Freshness", "degraded", last_success=timestamp, evidence="Assessment timestamp is unreadable.", recommended_fix="Refresh Apple Exposure Assessment.")
        if age > STALE_FORECAST_SECONDS:
            return VisibilityComponentStatus("Apple Exposure Assessment Freshness", "degraded", last_success=timestamp, evidence=f"Assessment age is {age}s level={level}.", recommended_fix="Refresh Apple Exposure Assessment.")
        return VisibilityComponentStatus("Apple Exposure Assessment Freshness", "healthy", last_success=timestamp, evidence=f"Assessment age is {age}s level={level}.", recommended_fix="No action required.")

    def _report_export_health(self) -> VisibilityComponentStatus:
        try:
            self.reports_dir.mkdir(parents=True, exist_ok=True)
            test_path = self.reports_dir / ".visibility_report_write_test"
            test_path.write_text("ok", encoding="utf-8")
            test_path.unlink(missing_ok=True)
            writable = os.access(self.reports_dir, os.W_OK)
            if not writable:
                return VisibilityComponentStatus("Report Export Health", "degraded", evidence=f"reports_dir={self.reports_dir}", recommended_fix="Fix reports directory permissions.")
            return VisibilityComponentStatus("Report Export Health", "healthy", last_success=utc_now_iso(), evidence=f"reports_dir={self.reports_dir}", recommended_fix="No action required.")
        except Exception as exc:
            return VisibilityComponentStatus("Report Export Health", "failing", last_error=str(exc), evidence=f"reports_dir={self.reports_dir}", recommended_fix="Restore or recreate the reports directory with user write access.")

    def _score(self, components: list[VisibilityComponentStatus]) -> int:
        if not components:
            return 0
        return max(0, min(100, round(sum(STATUS_POINTS.get(item.status, 0) for item in components) / (len(components) * 10) * 100)))

    def _overall_status(self, components: list[VisibilityComponentStatus]) -> VisibilityStatus:
        statuses = {item.status for item in components}
        if "failing" in statuses:
            return "failing"
        if "degraded" in statuses:
            return "degraded"
        if "disabled" in statuses:
            return "degraded"
        if "unsupported" in statuses:
            return "degraded"
        return "healthy"
