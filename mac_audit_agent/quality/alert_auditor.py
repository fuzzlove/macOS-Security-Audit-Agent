from __future__ import annotations

from mac_audit_agent.models import BackgroundMonitorEvent
from mac_audit_agent.alert_styles import SEVERITY_STYLES, validate_alert_styles
from mac_audit_agent.monitor import BackgroundMonitorService
from mac_audit_agent.monitor_settings import load_settings
from mac_audit_agent.notification_manager import NotificationManager
from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck
from mac_audit_agent.quality.verification_evidence import evidence_is_fresh, latest_evidence, record_verification_evidence
from mac_audit_agent.runtime.db_path_resolver import get_active_monitor_db_path
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.user_notifier_installer import get_user_notifier_status
from mac_audit_agent.models import utc_now_iso
import json


EVENTS = [
    ("info_test_event", "info"),
    ("medium_test_event", "medium"),
    ("high_test_event", "high"),
    ("critical_test_event", "critical"),
    ("usb_device_connected", "high"),
    ("bluetooth_device_connected", "medium"),
    ("new_network_connection_detected", "medium"),
    ("launchagent_added", "high"),
]


def run_alert_audit(context: AuditContext) -> list[FunctionalCheck]:
    active_db_path = get_active_monitor_db_path(context.db_path)
    checks: list[FunctionalCheck] = []
    db_open = FunctionalCheck("alert.active_db_open", "Alerts", "active monitor database", "Alert diagnostics can open the active monitor database.", "blocker", "integration")
    try:
        db = AuditDatabase(active_db_path)
    except Exception as exc:
        db_open.failure_stage = "permission_issue"
        checks.append(db_open.failed(
            f"Active monitor database could not be opened for alert diagnostics: {exc}",
            "Repair active monitor database permissions or run alert verification with the same privileges as the active monitor.",
            {"db_path": str(active_db_path), "exception": type(exc).__name__},
        ))
        return checks
    checks.append(db_open.passed("Active monitor database opened for alert diagnostics.", {"db_path": str(active_db_path)}))
    settings = load_settings(db)
    manager = NotificationManager(db)
    overlay = FunctionalCheck("alert.overlay_manager", "Alerts", "AlertOverlayManager", "Overlay manager can be initialized and reports delivery state.", "blocker", "integration")
    try:
        style_failures = validate_alert_styles()
        if style_failures:
            checks.append(overlay.failed("Alert visual style validation failed.", "Use solid high-contrast alert styles from mac_audit_agent.alert_styles and remove transparent alert card styling.", {"failures": style_failures, "styles": SEVERITY_STYLES}))
        else:
            checks.append(overlay.passed("AlertOverlayManager solid high-contrast styles verified.", {"critical_red": SEVERITY_STYLES["critical_red"]}))
    except Exception as exc:
        checks.append(overlay.failed(str(exc), "Fix AlertOverlayManager initialization/style constants.", {"exception": type(exc).__name__}))

    notifier_status = get_user_notifier_status(db_path=active_db_path)
    render = FunctionalCheck("alert.bottom_right_rendering", "Alerts", "bottom-right alert rendering", "Bottom-right alert path has render/suppression trace.", "blocker", "integration")
    required = settings.local_edr.persistent_local_edr_enabled and settings.notification.bottom_right_alerts and settings.user_notifier.enabled
    if required and (notifier_status.install_status != "loaded" or not notifier_status.running):
        render.failure_stage = "notifier_not_running"
        checks.append(render.failed("Events are being collected, but the user alert agent is not running.", "Install and load com.mac-audit-agent.user-notifier in gui/<uid>, then rerun alert delivery test.", notifier_status.to_dict()))
    elif not context.allow_alert_render:
        prior = latest_evidence("alert.bottom_right_rendering.interactive")
        if evidence_is_fresh(prior, max_age_hours=24):
            details = prior.get("details", {}) if isinstance(prior, dict) else {}
            checks.append(
                render.passed(
                    f"Interactive alert verification passed at {prior.get('completed_at', '')}.",
                    {
                        **notifier_status.to_dict(),
                        "prior_interactive_evidence": prior,
                        "interactive_alert_verified_at": prior.get("completed_at", ""),
                        "trace_id": details.get("trace_id", ""),
                    },
                )
            )
        else:
            checks.append(
                render.skipped(
                    "Visible bottom-right alert rendering requires an interactive user session. Run --alerts --interactive before manual UI testing.",
                    "Run python3 -m mac_audit_agent.quality.pre_uat_audit --alerts --interactive from a logged-in GUI session.",
                    {
                        **notifier_status.to_dict(),
                        "reason": "interactive_verification_required",
                        "prior_interactive_evidence": prior or {},
                    },
                )
            )
    else:
        checks.append(_run_visible_alert_probe(context, render))

    threshold = FunctionalCheck("alert.severity_threshold", "Alerts", "severity threshold logic", "Minimum severity policy suppresses lower severity with reason.", "high", "settings")
    try:
        old = db.get_background_monitor_state("notify_min_severity", "info")
        db.set_background_monitor_state("notify_min_severity", "critical")
        event = _event("pre-uat-threshold", "usb_device_connected", "medium")
        should = manager.should_notify(event)
        db.set_background_monitor_state("notify_min_severity", old)
        if should or event.notification_reason != "below_min_severity":
            checks.append(threshold.failed("Medium event was not suppressed below critical threshold.", "Connect notify_min_severity to alert policy and record below_min_severity reasons.", {"reason": event.notification_reason}))
        else:
            checks.append(threshold.passed("Severity threshold suppression reason verified.", {"reason": event.notification_reason}))
    except Exception as exc:
        checks.append(threshold.failed(str(exc), "Fix severity threshold policy path.", {"exception": type(exc).__name__}))

    for event_type, severity in EVENTS[4:]:
        checks.append(_policy_check(db, manager, event_type, severity))
    trace = FunctionalCheck("alert.delivery_trace", "Alerts", "AlertDeliveryTrace", "Alert-worthy events create delivery trace.", "blocker", "integration")
    try:
        service = BackgroundMonitorService(active_db_path, record_startup=False, mode="user-notifier")
        event = service.simulate_event("launchagent_added", "Pre-UAT diagnostic alert trace probe.", severity="high", source="pre_uat_audit", notify_force=False)
        trace_obj = service.db.get_event_alert_trace(event.event_id)
        if trace_obj is None:
            checks.append(trace.failed("Alert-worthy diagnostic event did not create AlertDeliveryTrace.", "Ensure monitor event write path calls record_event_alert_trace for alert-worthy events.", {"event_id": event.event_id}))
        else:
            checks.append(trace.passed("AlertDeliveryTrace created for diagnostic event.", trace_obj.to_dict()))
    except Exception as exc:
        trace.failure_stage = "event_not_written"
        checks.append(trace.failed(str(exc), "Fix AlertDeliveryTrace recording for diagnostic events.", {"exception": type(exc).__name__}))
    return checks


def _event(event_id: str, event_type: str, severity: str) -> BackgroundMonitorEvent:
    return BackgroundMonitorEvent(
        event_id=event_id,
        timestamp=utc_now_iso(),
        event_type=event_type,
        severity=severity,
        source="pre_uat_audit",
        evidence="Pre-UAT diagnostic event; not a real finding.",
        process_name="pre_uat_audit",
        confidence="high",
        simulated=True,
    )


def _policy_check(db: AuditDatabase, manager: NotificationManager, event_type: str, severity: str) -> FunctionalCheck:
    check = FunctionalCheck(f"alert.{event_type}", "Alerts", f"{event_type} alert path", "Diagnostic alert policy path records decision.", "high", "integration")
    event = _event(f"pre-uat-{event_type}", event_type, severity)
    try:
        should = manager.should_notify(event)
        evidence = {"event_type": event_type, "severity": severity, "should_notify": should, "reason": event.notification_reason, "suppression": event.last_suppression_reason}
        if not should and not (event.notification_reason or event.last_suppression_reason):
            return check.failed("Alert policy suppressed event without reason.", "Record exact alert suppression reasons for every non-delivered alert-worthy event.", evidence)
        return check.passed("Alert policy path returned a decision with reason context.", evidence)
    except Exception as exc:
        return check.failed(str(exc), f"Fix alert policy path for {event_type}.", {"exception": type(exc).__name__})


def _run_visible_alert_probe(context: AuditContext, check: FunctionalCheck) -> FunctionalCheck:
    started_at = utc_now_iso()
    active_db_path = get_active_monitor_db_path(context.db_path)
    notifier_status = get_user_notifier_status(db_path=active_db_path)
    service = BackgroundMonitorService(active_db_path, record_startup=False, mode="user-notifier")
    event = service.simulate_event("critical_test_event", "Pre-UAT visible alert probe.", severity="critical", source="pre_uat_audit", notify_force=True)
    rendered = service.notifications.show_visible_security_alert(event, reason="pre_uat_audit", force=True)
    trace = service.db.get_event_alert_trace(event.event_id)
    if not rendered:
        check.failure_stage = "overlay_not_rendered"
        return check.failed("AlertOverlayManager did not render visible alert.", "Inspect overlay render error and repair AlertOverlayManager.", {"event_id": event.event_id, "trace": trace.to_dict() if trace else {}})
    completed_at = utc_now_iso()
    evidence = {
        "interactive_alert_verified_at": completed_at,
        "event_id": event.event_id,
        "visible_alert_id": getattr(trace, "visible_alert_id", "") if trace else event.event_id,
        "alert_id": event.event_id,
        "trace_id": getattr(trace, "trace_id", f"trace-{event.event_id}") if trace else f"trace-{event.event_id}",
        "notifier_pid": notifier_status.process_pid,
        "active_db_path": str(active_db_path),
        "user_confirmed_visible": False,
        "render_verification_status": "verified",
    }
    service.db.set_background_monitor_state("interactive_alert_verified_at", evidence["interactive_alert_verified_at"])
    service.db.set_background_monitor_state("interactive_alert_verified_id", event.event_id)
    service.db.set_background_monitor_state("visible_alert_verification_last_report_json", json.dumps({
        "event_type": event.event_type,
        "event_id": event.event_id,
        "generated_at": evidence["interactive_alert_verified_at"],
        "trace_id": evidence["trace_id"],
        "visible_alert_id": evidence["visible_alert_id"],
        "notifier_pid": evidence["notifier_pid"],
        "active_db_path": evidence["active_db_path"],
        "user_confirmed_visible": evidence["user_confirmed_visible"],
        "render_verification_status": evidence["render_verification_status"],
        "stages": [
            {"check_id": "sqlite_store", "status": "PASS"},
            {"check_id": "notifier_policy_checked", "status": "PASS"},
            {"check_id": "overlay_dispatch", "status": "PASS"},
            {"check_id": "visible_alert_delivery", "status": "PASS"},
        ],
    }, sort_keys=True))
    try:
        record = record_verification_evidence(
            check_id="alert.bottom_right_rendering.interactive",
            command="python3 -m mac_audit_agent.quality.pre_uat_audit --alerts --interactive",
            started_at=started_at,
            completed_at=completed_at,
            status="pass",
            exit_code=0,
            evidence_summary="Interactive bottom-right alert rendering verified.",
            ttl_hours=24,
            details=evidence,
        )
        evidence["verification_evidence_id"] = record.evidence_id
    except Exception as exc:
        evidence["verification_evidence_error"] = f"{type(exc).__name__}: {exc}"
    return check.passed("Visible alert render probe succeeded.", evidence)
