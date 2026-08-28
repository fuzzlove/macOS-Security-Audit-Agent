from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from mac_audit_agent.launch_agent import default_monitor_db_path
from mac_audit_agent.runtime.path_alignment import classify_runtime_paths
from mac_audit_agent.runtime.topology import resolve_runtime_topology
from mac_audit_agent.storage import AuditDatabase


@dataclass(frozen=True)
class DbPathAlignment:
    active_monitor_mode: str
    active_monitor_db_path: str
    user_notifier_db_path: str
    system_daemon_db_path: str
    event_db_path: str
    alert_trace_db_path: str
    settings_storage_path: str
    ui_local_db_path: str
    legacy_user_db_path: str
    historical_user_db_path: str
    aligned: bool
    mismatches: dict[str, str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def get_active_monitor_mode(settings_db_path: Path | None = None) -> str:
    return resolve_runtime_topology(settings_db_path).selected_monitor_mode


def get_system_daemon_db_path() -> Path:
    return default_monitor_db_path("system").expanduser()


def get_user_monitor_db_path() -> Path:
    return default_monitor_db_path("user").expanduser()


def get_active_monitor_db_path(settings_db_path: Path | None = None) -> Path:
    return Path(resolve_runtime_topology(settings_db_path).canonical_event_database)


def get_user_notifier_db_path(settings_db_path: Path | None = None) -> Path:
    return Path(resolve_runtime_topology(settings_db_path).notifier_event_database)


def validate_db_path_alignment(
    *,
    settings_db_path: Path | None = None,
    notifier_db_path: str | Path | None = None,
    event_db_path: Path | None = None,
    alert_trace_db_path: Path | None = None,
) -> DbPathAlignment:
    settings_path = Path(settings_db_path or default_monitor_db_path("user")).expanduser()
    topology = resolve_runtime_topology(settings_path, notifier_event_database=Path(notifier_db_path).expanduser() if notifier_db_path else None)
    active = Path(topology.canonical_event_database)
    notifier = Path(notifier_db_path).expanduser() if notifier_db_path else active
    event = Path(event_db_path or active).expanduser()
    alert_trace = Path(alert_trace_db_path or topology.alert_trace_database).expanduser()
    system = get_system_daemon_db_path()
    mode = topology.selected_monitor_mode
    alignment = classify_runtime_paths(
        active_monitor_mode=mode,
        active_monitor_db_path=active,
        notifier_db_path=notifier,
        event_db_path=event,
        alert_trace_db_path=alert_trace,
        settings_storage_path=settings_path,
        ui_local_db_path=default_monitor_db_path("user"),
    )
    return DbPathAlignment(
        active_monitor_mode=mode,
        active_monitor_db_path=str(active),
        user_notifier_db_path=str(notifier),
        system_daemon_db_path=str(system),
        event_db_path=str(event),
        alert_trace_db_path=str(alert_trace),
        settings_storage_path=alignment.settings_storage_path,
        ui_local_db_path=alignment.ui_local_db_path,
        legacy_user_db_path=alignment.legacy_user_db_path,
        historical_user_db_path=alignment.historical_user_db_path,
        aligned=alignment.aligned,
        mismatches=alignment.mismatches,
    )


def repair_user_notifier_db_path(settings_db_path: Path | None = None):
    from mac_audit_agent.user_notifier_installer import repair_user_notifier

    return repair_user_notifier(db_path=get_user_notifier_db_path(settings_db_path))
