from __future__ import annotations

from dataclasses import asdict, dataclass
from mac_audit_agent.compat.enum import StrEnum
from pathlib import Path

from mac_audit_agent.launch_agent import LAUNCH_AGENT_LABEL, SYSTEM_DB_PATH, SYSTEM_LAUNCH_DAEMON_PATH, SYSTEM_RUNTIME_ROOT
from mac_audit_agent.service_watchdog import WATCHDOG_LABEL, WATCHDOG_PLIST_PATH
from mac_audit_agent.sensor_health_service import SENSOR_HEALTH_LABEL, SENSOR_HEALTH_PLIST_PATH
from mac_audit_agent.user_notifier_installer import USER_NOTIFIER_LABEL


class ComponentStatus(StrEnum):
    INSTALLED = "installed"
    MISSING = "missing"
    LOADED = "loaded"
    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"
    STALE = "stale"
    PERMISSION_BLOCKED = "permission_blocked"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ActiveProtectionComponent:
    component_id: str
    display_name: str
    required: bool
    install_scope: str
    purpose: str
    plist_path: str = ""
    launchd_label: str = ""
    runtime_path: str = ""
    status: ComponentStatus = ComponentStatus.UNKNOWN
    required_permissions: tuple[str, ...] = ()
    repair_actions: tuple[str, ...] = ()
    verification_steps: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return asdict(self)


def active_protection_components(*, home: Path | None = None) -> tuple[ActiveProtectionComponent, ...]:
    home = Path(home or Path.home())
    notifier_plist = home / "Library/LaunchAgents" / f"{USER_NOTIFIER_LABEL}.plist"
    user_runtime = home / "Library/Application Support/MacAuditAgent/runtime"
    return (
        ActiveProtectionComponent("system_daemon", "System Monitor LaunchDaemon", True, "system", "Persistent protected monitoring and local event generation", str(SYSTEM_LAUNCH_DAEMON_PATH), LAUNCH_AGENT_LABEL, str(SYSTEM_RUNTIME_ROOT), required_permissions=("administrator approval",), repair_actions=("install_or_repair_system_daemon",), verification_steps=(f"launchctl print system/{LAUNCH_AGENT_LABEL}",)),
        ActiveProtectionComponent("development_ransomware_observer", "Development Ransomware Observer", True, "system", "Entitlement-free delayed metadata observation hosted inside the existing System Monitor; not Endpoint Security parity", str(SYSTEM_LAUNCH_DAEMON_PATH), LAUNCH_AGENT_LABEL, str(SYSTEM_RUNTIME_ROOT), required_permissions=("administrator approval for System Monitor installation", "Full Disk Access may be required for protected folders"), repair_actions=("install_or_repair_system_daemon",), verification_steps=("System daemon heartbeat is fresh", "anti_ransomware_prototype_status=running")),
        ActiveProtectionComponent("user_notifier", "User Notifier LaunchAgent", True, "user", "Visible user-level alerts from daemon events", str(notifier_plist), USER_NOTIFIER_LABEL, str(user_runtime), required_permissions=("logged-in user launchd session",), repair_actions=("install_or_repair_user_notifier",), verification_steps=(f"launchctl print gui/<uid>/{USER_NOTIFIER_LABEL}",)),
        ActiveProtectionComponent("service_watchdog", "Persistent Service Watchdog", True, "system", "Integrity-gated health verification and bounded automatic repair for every installed MSAA daemon, monitor, and notifier", str(WATCHDOG_PLIST_PATH), WATCHDOG_LABEL, str(SYSTEM_RUNTIME_ROOT), required_permissions=("administrator approval",), repair_actions=("install_or_repair_service_watchdog",), verification_steps=(f"launchctl print system/{WATCHDOG_LABEL}", "service-watchdog-health.json reports healthy")),
        ActiveProtectionComponent("sensor_health_manager", "Sensor Health Manager", True, "system", "Functional telemetry, dependency, permission, queue, loss, persistence, and coverage assurance distinct from process liveness", str(SENSOR_HEALTH_PLIST_PATH), SENSOR_HEALTH_LABEL, str(SYSTEM_RUNTIME_ROOT), required_permissions=("administrator approval",), repair_actions=("install_or_repair_sensor_health_manager",), verification_steps=(f"launchctl print system/{SENSOR_HEALTH_LABEL}", "sensor-health.json contains a fresh completed cycle")),
        ActiveProtectionComponent("system_runtime", "Active Runtime Directory", True, "runtime", "Root-owned runtime, settings, manifests and queues", runtime_path=str(SYSTEM_RUNTIME_ROOT.parent)),
        ActiveProtectionComponent("user_runtime", "User Runtime Directory", True, "runtime", "Notifier runtime and user-level UI support", runtime_path=str(user_runtime)),
        ActiveProtectionComponent("active_db", "Active Monitor Database", True, "system", "Shared events, settings and heartbeat database", runtime_path=str(SYSTEM_DB_PATH), verification_steps=("SQLite schema and path alignment",)),
        ActiveProtectionComponent("runtime_manifest", "Installed Runtime Manifest", True, "runtime", "Installed path, version and settings alignment evidence", runtime_path=str(SYSTEM_RUNTIME_ROOT / "install_manifest.json")),
    )


__all__ = ["ActiveProtectionComponent", "ComponentStatus", "active_protection_components"]
