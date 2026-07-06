from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from mac_audit_agent.launch_agent import default_monitor_db_path
from mac_audit_agent.storage import AuditDatabase


@dataclass(frozen=True)
class RuntimePathAlignment:
    active_monitor_mode: str
    active_monitor_db_path: str
    active_event_db_path: str
    active_system_db_path: str
    notifier_db_path: str
    alert_trace_db_path: str
    settings_storage_path: str
    ui_local_db_path: str
    legacy_user_db_path: str
    historical_user_db_path: str
    aligned: bool
    mismatches: dict[str, str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def classify_runtime_paths(
    *,
    active_monitor_mode: str,
    active_monitor_db_path: str | Path,
    notifier_db_path: str | Path | None = None,
    event_db_path: str | Path | None = None,
    alert_trace_db_path: str | Path | None = None,
    settings_storage_path: str | Path | None = None,
    ui_local_db_path: str | Path | None = None,
) -> RuntimePathAlignment:
    active = Path(active_monitor_db_path).expanduser()
    event = Path(event_db_path or active).expanduser()
    notifier = Path(notifier_db_path or active).expanduser()
    alert_trace = Path(alert_trace_db_path or event).expanduser()
    settings = Path(settings_storage_path or active).expanduser()
    ui_local = Path(ui_local_db_path or default_monitor_db_path("user")).expanduser()
    legacy_user = default_monitor_db_path("user").expanduser()
    system = default_monitor_db_path("system").expanduser()
    expected_active = str(active)
    observed = {
        "notifier_db_path": str(notifier),
        "active_event_db_path": str(event),
        "alert_trace_db_path": str(alert_trace),
    }
    mismatches = {
        key: f"expected {expected_active}, observed {value}"
        for key, value in observed.items()
        if value != expected_active
    }
    historical = str(legacy_user) if active_monitor_mode == "system" and legacy_user != active else ""
    return RuntimePathAlignment(
        active_monitor_mode=active_monitor_mode,
        active_monitor_db_path=str(active),
        active_event_db_path=str(event),
        active_system_db_path=str(system),
        notifier_db_path=str(notifier),
        alert_trace_db_path=str(alert_trace),
        settings_storage_path=str(settings),
        ui_local_db_path=str(ui_local),
        legacy_user_db_path=str(legacy_user),
        historical_user_db_path=historical,
        aligned=not mismatches,
        mismatches=mismatches,
    )


def persist_path_alignment(db: AuditDatabase, alignment: RuntimePathAlignment) -> None:
    db.set_background_monitor_state("runtime_path_alignment_json", __import__("json").dumps(alignment.to_dict(), sort_keys=True))


__all__ = ["RuntimePathAlignment", "classify_runtime_paths", "persist_path_alignment"]
