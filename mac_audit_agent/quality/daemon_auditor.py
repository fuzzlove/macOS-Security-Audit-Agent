from __future__ import annotations

from pathlib import Path

from mac_audit_agent.launch_agent import LaunchAgentManager, default_monitor_db_path
from mac_audit_agent.monitor import is_heartbeat_fresh
from mac_audit_agent.monitor_settings import load_settings
from mac_audit_agent.quality.audit_models import AuditContext, FunctionalCheck
from mac_audit_agent.runtime.db_path_resolver import get_active_monitor_db_path, validate_db_path_alignment
from mac_audit_agent.runtime.topology import resolve_runtime_topology
from mac_audit_agent.storage import AuditDatabase
from mac_audit_agent.user_notifier_installer import get_user_notifier_status, update_db_notifier_status


def run_daemon_audit(context: AuditContext) -> list[FunctionalCheck]:
    active_db_path = get_active_monitor_db_path(context.db_path)
    checks: list[FunctionalCheck] = []
    db_open = FunctionalCheck("daemon.active_db_open", "Monitor/Daemon", "active monitor database", "Active monitor database is readable and writable for diagnostics.", "blocker", "daemon")
    try:
        db = AuditDatabase(active_db_path)
    except Exception as exc:
        db_open.failure_stage = "permission_issue"
        checks.append(db_open.failed(
            f"Active monitor database could not be opened for diagnostics: {exc}",
            "Repair active monitor database permissions or run the audit with the same privileges as the active monitor.",
            {"db_path": str(active_db_path), "exception": type(exc).__name__},
        ))
        return checks
    checks.append(db_open.passed("Active monitor database opened for diagnostics.", {"db_path": str(active_db_path)}))
    settings_db = AuditDatabase(context.db_path)
    settings = load_settings(settings_db)
    selected_mode = "system" if settings.installation.monitor_mode in {"system", "protected"} else "user"
    topology = resolve_runtime_topology(context.db_path, selected_mode=selected_mode)
    notifier = FunctionalCheck("daemon.notifier_heartbeat", "Monitor/Daemon", "notifier heartbeat", "User notifier heartbeat and status are visible.", "blocker", "daemon")
    try:
        status = get_user_notifier_status(db_path=active_db_path)
        update_db_notifier_status(db, status)
        required = settings.local_edr.persistent_local_edr_enabled and settings.notification.bottom_right_alerts and settings.user_notifier.enabled
        alignment = validate_db_path_alignment(settings_db_path=context.db_path, notifier_db_path=status.db_path, event_db_path=active_db_path)
        evidence = {**status.to_dict(), "db_path_alignment": alignment.to_dict()}
        db_mismatch = bool(status.db_path and not alignment.aligned)
        heartbeat_fresh = bool(status.active_db_heartbeat and is_heartbeat_fresh(status.active_db_heartbeat))
        if required and not status.live_launchctl_loaded:
            notifier.failure_stage = "notifier_not_running"
            checks.append(notifier.failed("Bottom-right alerts are enabled but the user alert agent is not loaded.", "Install and load com.mac-audit-agent.user-notifier in gui/<uid>, then rerun alert delivery test.", evidence))
        elif required and not status.live_launchctl_running:
            notifier.failure_stage = "notifier_not_running"
            checks.append(notifier.failed("Bottom-right alerts are enabled but the user alert agent is loaded without a running process.", "Restart or repair User Alert Agent, verify running PID, then rerun alert delivery test.", evidence))
        elif required and db_mismatch:
            notifier.failure_stage = "db_path_mismatch"
            checks.append(notifier.failed("Bottom-right alerts are enabled but the user alert agent is reading a different database.", "Repair User Alert Agent so its MAC_AUDIT_AGENT_DB_PATH matches the active monitor database, then rerun notifier and alert pipeline audits.", evidence))
        elif required and not heartbeat_fresh:
            notifier.failure_stage = "notifier_heartbeat_stale"
            checks.append(notifier.failed("Bottom-right alerts are enabled but the user alert agent heartbeat is missing or stale in the active DB.", "Repair User Alert Agent and verify it writes a fresh heartbeat to the active monitor database.", evidence))
        elif status.install_status in {"missing", "unloaded"}:
            checks.append(notifier.warn(f"User notifier is {status.install_status}.", "Install or start User Alert Agent before alert-focused user testing.", evidence))
        elif status.install_status == "broken":
            notifier.failure_stage = "notifier_not_running"
            checks.append(notifier.failed(status.last_error, "Repair User Alert Agent and verify plist, ProgramArguments, runtime, and gui/<uid> launchctl domain.", evidence))
        else:
            checks.append(notifier.passed("User notifier installed/loaded status verified.", evidence))
    except Exception as exc:
        checks.append(notifier.failed(str(exc), "Fix user notifier status inspection and diagnostics.", {"exception": type(exc).__name__}))

    user_launch = FunctionalCheck("daemon.user_launch_agent", "Monitor/Daemon", "user LaunchAgent mode health", "User monitor LaunchAgent state is healthy for the selected monitor mode.", "high", "daemon")
    conflict_check = FunctionalCheck("daemon.conflicting_monitor_deployment", "Monitor/Daemon", "conflicting monitor deployment", "Only the monitor service required by the selected mode is installed or loaded.", "blocker", "daemon")
    try:
        status = LaunchAgentManager(context.db_path).status()
        user_active = bool(status.installed or status.loaded or status.running)
        evidence = status.to_dict() | {"selected_mode": selected_mode, "healthy_for_selected_mode": (not user_active if selected_mode == "system" else bool(status.installed and status.loaded and status.running))}
        if selected_mode == "system":
            if user_active:
                checks.append(user_launch.failed("[MON005] System mode requires the obsolete user monitor to be absent or unloaded; detected installed=%s loaded=%s running=%s." % (status.installed, status.loaded, status.running), "Use the explicit Repair Monitor Deployment action to boot out and disable the user monitor LaunchAgent.", evidence))
                checks.append(conflict_check.failed("[MON005] Conflicting user monitor deployment detected while system mode is selected.", "Run the explicit monitor repair action; it will boot out and back up the obsolete user monitor plist.", evidence))
            else:
                checks.append(user_launch.passed("User monitor is correctly absent in system mode.", evidence))
                checks.append(conflict_check.passed("No conflicting user monitor deployment is active.", {"selected_mode": selected_mode, "conflict": False}))
        elif evidence["healthy_for_selected_mode"]:
            checks.append(user_launch.passed("User monitor is installed, loaded, and running for user mode.", evidence))
            checks.append(conflict_check.passed("No conflicting system monitor was detected for user mode.", {"selected_mode": selected_mode, "conflict": False}))
        else:
            checks.append(user_launch.failed("[MON003] User mode requires a running user monitor.", "Run Repair Background Monitor and verify the gui/<uid> launchctl service.", evidence))
            checks.append(conflict_check.passed("No cross-mode conflict was established by the user monitor check.", {"selected_mode": selected_mode, "conflict": False}))
    except Exception as exc:
        checks.append(user_launch.warn(str(exc), "Repair user LaunchAgent status inspection or install path diagnostics.", {"exception": type(exc).__name__}))
        checks.append(conflict_check.failed("[MON005] Conflicting deployment state could not be determined.", "Run --doctor --topology and inspect both system and gui/<uid> launchctl domains.", {"exception": type(exc).__name__}))

    system_launch = FunctionalCheck("daemon.system_launch_daemon", "Monitor/Daemon", "system LaunchDaemon status", "System LaunchDaemon status is inspectable when enabled.", "critical", "daemon")
    try:
        if selected_mode != "system":
            checks.append(system_launch.skipped("System LaunchDaemon not enabled by settings.", "No action required unless system monitor mode is selected."))
        else:
            status = LaunchAgentManager(default_monitor_db_path("system"), scope="system").status()
            system_evidence = status.to_dict() | {"selected_mode": selected_mode, "expected_database": topology.canonical_event_database, "expected_executable": topology.service_executable}
            if not status.installed:
                system_launch.failure_stage = "daemon_not_running"
                checks.append(system_launch.failed("[MON001] System mode is selected but the LaunchDaemon is not installed.", "Run the explicit system-monitor installation action with administrator approval.", system_evidence))
            elif not status.loaded:
                checks.append(system_launch.failed("[MON002] System LaunchDaemon is installed but not loaded.", "Run the explicit system-monitor repair action with administrator approval.", system_evidence))
            elif not status.running:
                checks.append(system_launch.failed("[MON003] System LaunchDaemon is loaded but not running.", "Inspect the bounded service log artifact, correct its executable or database arguments, and rerun repair.", system_evidence))
            else:
                checks.append(system_launch.passed("System LaunchDaemon is installed, loaded, and running.", system_evidence))
    except Exception as exc:
        checks.append(system_launch.failed(str(exc), "Fix system LaunchDaemon status inspection.", {"exception": type(exc).__name__}))

    heartbeat = FunctionalCheck("daemon.heartbeat", "Monitor/Daemon", "daemon heartbeat", "Daemon heartbeat freshness is visible.", "critical", "daemon")
    last_heartbeat = db.get_background_monitor_state("last_heartbeat", "")
    if not last_heartbeat:
        checks.append(heartbeat.warn("No daemon heartbeat recorded.", "Start the monitor or verify daemon startup before UAT.", {"last_heartbeat": last_heartbeat, "db_path": str(active_db_path)}))
    elif not is_heartbeat_fresh(last_heartbeat):
        heartbeat.failure_stage = "daemon_not_running"
        checks.append(heartbeat.failed(f"Stale daemon heartbeat: {last_heartbeat}", "Restart or repair the monitor and confirm heartbeat freshness.", {"last_heartbeat": last_heartbeat, "db_path": str(active_db_path)}))
    else:
        checks.append(heartbeat.passed("Daemon heartbeat is fresh.", {"last_heartbeat": last_heartbeat, "db_path": str(active_db_path)}))

    event_write = FunctionalCheck("daemon.event_db_writes", "Monitor/Daemon", "event database writes", "Monitor event database write path works.", "blocker", "daemon")
    try:
        active_name = Path(active_db_path).name
        db.set_background_monitor_state("pre_uat_event_write_probe", active_name)
        from mac_audit_agent.models import utc_now_iso
        db.set_background_monitor_state("pre_uat_event_write_probe_at", utc_now_iso())
        observed = db.get_background_monitor_state("pre_uat_event_write_probe", "")
        evidence = {
            "active_db_path": str(active_db_path),
            "context_db_path": str(context.db_path),
            "historical_user_db_path": str(context.db_path) if Path(context.db_path) != Path(active_db_path) else "",
            "active_only": True,
            "observed": observed,
        }
        if observed != active_name:
            checks.append(event_write.failed("Background monitor state write/read mismatch.", "Repair SQLite state write path before UAT.", evidence))
        else:
            checks.append(event_write.passed("Active monitor database write/read probe succeeded.", evidence))
    except Exception as exc:
        checks.append(event_write.failed(str(exc), "Repair monitor database permissions or schema.", {"exception": type(exc).__name__}))
    return checks
