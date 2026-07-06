from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from mac_audit_agent.launch_agent import default_monitor_db_path
from mac_audit_agent.monitor_settings import load_settings
from mac_audit_agent.runtime.path_alignment import classify_runtime_paths
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
    db_path = Path(settings_db_path or default_monitor_db_path("user")).expanduser()
    system_db_path = default_monitor_db_path("system").expanduser()
    try:
        db = AuditDatabase(db_path)
        explicit_mode = db.get_background_monitor_state("monitor_mode", db.get_background_monitor_state("monitor_install_mode", "")).strip().lower()
        settings = load_settings(db)
        mode = str(settings.installation.monitor_mode or "user").strip().lower()
    except Exception:
        explicit_mode = ""
        mode = ""
    if explicit_mode in {"system", "protected"}:
        return "system"
    if explicit_mode == "user":
        return "user"
    if mode in {"system", "protected"}:
        return "system"
    if system_db_path.exists():
        try:
            system_db = AuditDatabase(system_db_path)
            system_mode = system_db.get_background_monitor_state("monitor_mode", system_db.get_background_monitor_state("monitor_install_mode", "")).strip().lower()
            if system_mode in {"system", "protected"} or system_db.latest_monitor_heartbeat():
                return "system"
        except Exception:
            return "system"
    return "system" if mode in {"system", "protected"} else "user"


def get_system_daemon_db_path() -> Path:
    return default_monitor_db_path("system").expanduser()


def get_user_monitor_db_path() -> Path:
    return default_monitor_db_path("user").expanduser()


def get_active_monitor_db_path(settings_db_path: Path | None = None) -> Path:
    mode = get_active_monitor_mode(settings_db_path)
    if mode == "system":
        return get_system_daemon_db_path()
    if settings_db_path is not None:
        settings_path = Path(settings_db_path).expanduser()
        try:
            configured = AuditDatabase(settings_path).get_background_monitor_state("db_path", "").strip()
            if configured:
                return Path(configured).expanduser()
        except Exception:
            return settings_path
        return settings_path
    return get_user_monitor_db_path()


def get_user_notifier_db_path(settings_db_path: Path | None = None) -> Path:
    return get_active_monitor_db_path(settings_db_path)


def validate_db_path_alignment(
    *,
    settings_db_path: Path | None = None,
    notifier_db_path: str | Path | None = None,
    event_db_path: Path | None = None,
    alert_trace_db_path: Path | None = None,
) -> DbPathAlignment:
    settings_path = Path(settings_db_path or default_monitor_db_path("user")).expanduser()
    active = get_active_monitor_db_path(settings_path)
    notifier = Path(notifier_db_path).expanduser() if notifier_db_path else active
    event = Path(event_db_path or alert_trace_db_path or active).expanduser()
    alert_trace = Path(alert_trace_db_path or event_db_path or active).expanduser()
    system = get_system_daemon_db_path()
    mode = get_active_monitor_mode(settings_path)
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
