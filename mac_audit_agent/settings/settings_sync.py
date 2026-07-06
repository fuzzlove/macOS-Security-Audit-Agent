from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.monitor_settings import MonitorSettings, load_settings, save_settings
from mac_audit_agent.runtime.db_path_resolver import get_active_monitor_db_path
from mac_audit_agent.storage import AuditDatabase


@dataclass(frozen=True)
class SettingsSyncRepairResult:
    status: str
    settings_version: int
    ui_db_path: str
    runtime_db_path: str
    stages: list[dict[str, Any]]
    first_failure_stage: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def update_installed_settings_manifest(db: AuditDatabase, settings: MonitorSettings) -> dict[str, Any]:
    now = utc_now_iso()
    try:
        existing = json.loads(db.get_background_monitor_state("installed_monitor_settings_manifest_json", "{}"))
    except json.JSONDecodeError:
        existing = {}
    if not isinstance(existing, dict):
        existing = {}
    manifest = {
        **existing,
        "installed_at": existing.get("installed_at") or now,
        "last_settings_applied_at": now,
        "settings_version": settings.settings_version,
        "monitor_mode": settings.installation.monitor_mode,
        "db_path": str(db.path),
        "log_path": settings.installation.log_path,
        "notifier_enabled": settings.user_notifier.enabled,
        "persistent_local_edr_enabled": settings.local_edr.persistent_local_edr_enabled,
        "usb_monitoring_enabled": settings.event_categories.usb_monitoring_enabled,
        "bluetooth_monitoring_enabled": settings.event_categories.bluetooth_monitoring_enabled,
        "network_activity_monitoring_enabled": settings.event_categories.network_activity_monitoring_enabled,
        "admin_persistence_monitoring_enabled": settings.event_categories.admin_persistence_monitoring_enabled,
    }
    db.set_background_monitor_state("installed_monitor_settings_manifest_json", json.dumps(manifest, sort_keys=True))
    db.set_background_monitor_state("installed_settings_version", str(settings.settings_version))
    db.set_background_monitor_state("installed_monitor_settings_version", str(settings.settings_version))
    return manifest


def repair_settings_sync(ui_db: AuditDatabase, *, active_db_path: Path | None = None) -> SettingsSyncRepairResult:
    stages: list[dict[str, Any]] = []
    settings = load_settings(ui_db)
    try:
        save_settings(ui_db, settings, bump_version=False)
        stages.append({"stage": "save_current_settings", "status": "pass"})
        runtime_path = active_db_path or get_active_monitor_db_path(Path(ui_db.path))
        runtime_db = AuditDatabase(runtime_path)
        if Path(runtime_db.path) != Path(ui_db.path):
            save_settings(runtime_db, settings, bump_version=False)
        stages.append({"stage": "apply_settings_to_runtime_db", "status": "pass", "runtime_db_path": str(runtime_db.path)})
        runtime_db.set_background_monitor_state("settings_applied_event", json.dumps({"applied_at": utc_now_iso(), "settings_version": settings.settings_version, "repair_action": "repair_settings_sync"}, sort_keys=True))
        runtime_db.set_background_monitor_state("settings_last_reload_time", utc_now_iso())
        stages.append({"stage": "write_settings_applied_event", "status": "pass"})
        update_installed_settings_manifest(runtime_db, settings)
        if Path(runtime_db.path) != Path(ui_db.path):
            update_installed_settings_manifest(ui_db, settings)
        stages.append({"stage": "update_installed_manifest", "status": "pass"})
        return SettingsSyncRepairResult("repaired", int(settings.settings_version or 0), str(ui_db.path), str(runtime_db.path), stages)
    except Exception as exc:
        failed_stage = stages[-1]["stage"] if stages else "save_current_settings"
        stages.append({"stage": failed_stage, "status": "fail", "error": str(exc), "exception": type(exc).__name__})
        return SettingsSyncRepairResult("failed", int(settings.settings_version or 0), str(ui_db.path), str(active_db_path or ui_db.path), stages, first_failure_stage=failed_stage, error=str(exc))


__all__ = ["SettingsSyncRepairResult", "repair_settings_sync", "update_installed_settings_manifest"]
