from __future__ import annotations

from pathlib import Path

from mac_audit_agent.launch_agent import LaunchAgentManager, default_monitor_db_path
from mac_audit_agent.monitor import is_heartbeat_fresh
from mac_audit_agent.monitor_settings import load_settings
from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.user_notifier_installer import get_user_notifier_status, update_db_notifier_status


def run_daemon_audit(context: AuditContext) -> list[FunctionalCheck]:
    db = AuditDatabase(context.db_path)
    settings = load_settings(db)
    checks: list[FunctionalCheck] = []
    notifier = FunctionalCheck("daemon.notifier_heartbeat", "Monitor/Daemon", "notifier heartbeat", "User notifier heartbeat and status are visible.", "blocker", "daemon")
    try:
        status = get_user_notifier_status(db_path=context.db_path)
        update_db_notifier_status(db, status)
        required = settings.local_edr.persistent_local_edr_enabled and settings.notification.bottom_right_alerts and settings.user_notifier.enabled
        evidence = status.to_dict()
        db_mismatch = status.db_path and str(Path(status.db_path).expanduser()) != str(Path(context.db_path).expanduser())
        if required and status.install_status != "loaded":
            notifier.failure_stage = "notifier_not_running"
            checks.append(notifier.failed("Bottom-right alerts are enabled but the user alert agent is not loaded.", "Install and load com.mac-audit-agent.user-notifier in gui/<uid>, then rerun alert delivery test.", evidence))
        elif required and db_mismatch:
            notifier.failure_stage = "db_path_mismatch"
            checks.append(notifier.failed("Bottom-right alerts are enabled but the user alert agent is reading a different database.", "Repair User Alert Agent so its MAC_AUDIT_AGENT_DB_PATH matches the active monitor database, then rerun notifier and alert pipeline audits.", evidence))
        elif status.install_status in {"missing", "unloaded"}:
            checks.append(notifier.warn(f"User notifier is {status.install_status}.", "Install or start User Alert Agent before alert-focused user testing.", evidence))
        elif status.install_status == "broken":
            notifier.failure_stage = "notifier_not_running"
            checks.append(notifier.failed(status.last_error, "Repair User Alert Agent and verify plist, ProgramArguments, runtime, and gui/<uid> launchctl domain.", evidence))
        else:
            checks.append(notifier.passed("User notifier installed/loaded status verified.", evidence))
    except Exception as exc:
        checks.append(notifier.failed(str(exc), "Fix user notifier status inspection and diagnostics.", {"exception": type(exc).__name__}))

    user_launch = FunctionalCheck("daemon.user_launch_agent", "Monitor/Daemon", "user LaunchAgent status", "User monitor LaunchAgent status is inspectable.", "high", "daemon")
    try:
        status = LaunchAgentManager(context.db_path).status()
        checks.append(user_launch.passed("User LaunchAgent status inspected.", status.to_dict()))
    except Exception as exc:
        checks.append(user_launch.warn(str(exc), "Repair user LaunchAgent status inspection or install path diagnostics.", {"exception": type(exc).__name__}))

    system_launch = FunctionalCheck("daemon.system_launch_daemon", "Monitor/Daemon", "system LaunchDaemon status", "System LaunchDaemon status is inspectable when enabled.", "critical", "daemon")
    try:
        if settings.installation.monitor_mode not in {"system", "protected"}:
            checks.append(system_launch.skipped("System LaunchDaemon not enabled by settings.", "No action required unless system monitor mode is selected."))
        else:
            status = LaunchAgentManager(default_monitor_db_path("system"), scope="system").status()
            if not status.installed or not status.loaded:
                system_launch.failure_stage = "daemon_not_running"
                checks.append(system_launch.failed("System mode is enabled but LaunchDaemon is not installed/loaded.", "Install or repair the system LaunchDaemon with administrator approval.", status.to_dict()))
            else:
                checks.append(system_launch.passed("System LaunchDaemon installed/loaded status verified.", status.to_dict()))
    except Exception as exc:
        checks.append(system_launch.failed(str(exc), "Fix system LaunchDaemon status inspection.", {"exception": type(exc).__name__}))

    heartbeat = FunctionalCheck("daemon.heartbeat", "Monitor/Daemon", "daemon heartbeat", "Daemon heartbeat freshness is visible.", "critical", "daemon")
    last_heartbeat = db.get_background_monitor_state("last_heartbeat", "")
    if not last_heartbeat:
        checks.append(heartbeat.warn("No daemon heartbeat recorded.", "Start the monitor or verify daemon startup before UAT.", {"last_heartbeat": last_heartbeat}))
    elif not is_heartbeat_fresh(last_heartbeat):
        heartbeat.failure_stage = "daemon_not_running"
        checks.append(heartbeat.failed(f"Stale daemon heartbeat: {last_heartbeat}", "Restart or repair the monitor and confirm heartbeat freshness.", {"last_heartbeat": last_heartbeat}))
    else:
        checks.append(heartbeat.passed("Daemon heartbeat is fresh.", {"last_heartbeat": last_heartbeat}))

    event_write = FunctionalCheck("daemon.event_db_writes", "Monitor/Daemon", "event database writes", "Monitor event database write path works.", "blocker", "daemon")
    try:
        db.set_background_monitor_state("pre_uat_event_write_probe", Path(context.db_path).name)
        from mac_audit_agent.models import utc_now_iso
        db.set_background_monitor_state("pre_uat_event_write_probe_at", utc_now_iso())
        observed = db.get_background_monitor_state("pre_uat_event_write_probe", "")
        if observed != Path(context.db_path).name:
            checks.append(event_write.failed("Background monitor state write/read mismatch.", "Repair SQLite state write path before UAT.", {"observed": observed}))
        else:
            checks.append(event_write.passed("Database write/read probe succeeded.", {"db_path": str(context.db_path)}))
    except Exception as exc:
        checks.append(event_write.failed(str(exc), "Repair monitor database permissions or schema.", {"exception": type(exc).__name__}))
    return checks
