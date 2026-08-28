from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

from mac_audit_agent.family_safety.config_change import FamilySafetyConfigChange
from mac_audit_agent.family_safety.reporting import (
    export_family_safety_configuration_excel,
    export_family_safety_configuration_html,
    export_family_safety_configuration_json,
    export_family_safety_configuration_markdown,
    export_family_safety_configuration_word,
)
from mac_audit_agent.models import utc_now_iso
from mac_audit_agent.monitor_settings import load_settings, save_settings
from mac_audit_agent.settings.settings_reconciliation import reconcile_settings
from mac_audit_agent.version import APP_VERSION, current_git_commit
from mac_audit_agent.launch_agent import project_root


SNAPSHOT_KEY = "family_safety_last_config_snapshot_json"
LAST_RECOMMENDATION_KEY = "family_safety_last_recommendation_json"
LAST_APPLY_REPORT_KEY = "family_safety_last_apply_report_json"
CURRENT_PROFILE_KEY = "family_safety_current_profile"
LAST_RUN_KEY = "family_safety_last_wizard_run"


@dataclass
class FamilySafetyConfigSnapshot:
    snapshot_id: str
    created_at: str
    profile_before: str
    settings_before: dict[str, Any]
    selected_changes: list[dict[str, Any]]
    user: str
    app_version: str
    git_commit: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _get_path(settings: Any, setting_path: str) -> Any:
    current = settings
    for part in setting_path.split("."):
        current = getattr(current, part)
    return current


def _set_path(settings: Any, setting_path: str, value: Any) -> None:
    parts = setting_path.split(".")
    current = settings
    for part in parts[:-1]:
        current = getattr(current, part)
    if not hasattr(current, parts[-1]):
        raise AttributeError(f"Unsupported setting path: {setting_path}")
    setattr(current, parts[-1], value)


def _selected_change_ids(selected_changes: list[str | FamilySafetyConfigChange]) -> set[str]:
    ids: set[str] = set()
    for item in selected_changes:
        ids.add(item.change_id if isinstance(item, FamilySafetyConfigChange) else str(item))
    return ids


def create_family_safety_snapshot(db: Any, recommendation: Any, selected_changes: list[FamilySafetyConfigChange]) -> FamilySafetyConfigSnapshot:
    settings = load_settings(db)
    snapshot = FamilySafetyConfigSnapshot(
        snapshot_id=f"family-safety-snapshot-{uuid4().hex[:12]}",
        created_at=utc_now_iso(),
        profile_before=db.get_background_monitor_state(CURRENT_PROFILE_KEY, ""),
        settings_before=settings.to_dict(),
        selected_changes=[item.to_dict() for item in selected_changes],
        user=__import__("getpass").getuser(),
        app_version=APP_VERSION,
        git_commit=current_git_commit(project_root()),
    )
    db.set_background_monitor_state(SNAPSHOT_KEY, json.dumps(snapshot.to_dict(), sort_keys=True, default=str))
    return snapshot


def apply_family_safety_recommendation(recommendation: Any, selected_changes: list[str | FamilySafetyConfigChange], db: Any) -> dict[str, Any]:
    selected_ids = _selected_change_ids(selected_changes)
    changes = [item for item in recommendation.proposed_changes if item.change_id in selected_ids or item.setting_path in selected_ids]
    snapshot = create_family_safety_snapshot(db, recommendation, changes)
    settings = load_settings(db)
    version_before = settings.settings_version
    applied: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []

    for change in recommendation.proposed_changes:
        if change not in changes:
            change.apply_status = "skipped"
            skipped.append(change.to_dict())
            continue
        try:
            before = _get_path(settings, change.setting_path)
            if before != change.current_value:
                change.current_value = before
            _set_path(settings, change.setting_path, change.proposed_value)
            change.apply_status = "applied"
            applied.append(change.to_dict())
        except Exception as exc:
            change.apply_status = "failed"
            change.failure_reason = str(exc)
            failed.append(change.to_dict())

    saved = save_settings(db, settings, bump_version=bool(applied))
    reconciliation = reconcile_settings(saved, runtime_values={"settings_version": saved.settings_version, "notifier_settings_version": saved.settings_version})
    result = {
        "status": "applied" if applied and not failed else ("partial" if applied else "failed"),
        "snapshot": snapshot.to_dict(),
        "settings_version_before": version_before,
        "settings_version_after": saved.settings_version,
        "applied_changes": applied,
        "skipped_changes": skipped,
        "failed_changes": failed,
        "settings_sync": reconciliation.to_dict(),
        "requires_restart": any(item.get("requires_restart") for item in applied),
        "requires_admin": any(item.get("requires_admin") for item in applied),
        "generated_reports": {},
    }
    report_paths: dict[str, Any] = {}
    report_errors: dict[str, str] = {}
    exporters = {
        "json": export_family_safety_configuration_json,
        "markdown": export_family_safety_configuration_markdown,
        "html": export_family_safety_configuration_html,
        "docx": export_family_safety_configuration_word,
        "xlsx": export_family_safety_configuration_excel,
    }
    for format_name, exporter in exporters.items():
        try:
            report_paths[format_name] = exporter(recommendation, apply_result=result)
        except Exception as exc:
            report_errors[format_name] = f"{type(exc).__name__}: {exc}"
    result["generated_reports"] = {key: str(path) for key, path in report_paths.items()}
    result["report_export_errors"] = report_errors
    db.set_background_monitor_state(CURRENT_PROFILE_KEY, recommendation.selected_profile.display_name)
    db.set_background_monitor_state(LAST_RUN_KEY, utc_now_iso())
    db.set_background_monitor_state(LAST_RECOMMENDATION_KEY, json.dumps(recommendation.to_dict(), sort_keys=True, default=str))
    db.set_background_monitor_state(LAST_APPLY_REPORT_KEY, json.dumps(result, sort_keys=True, default=str))
    return result


def latest_family_safety_snapshot(db: Any) -> FamilySafetyConfigSnapshot | None:
    raw = db.get_background_monitor_state(SNAPSHOT_KEY, "")
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return FamilySafetyConfigSnapshot(**payload)


def restore_family_safety_snapshot(db: Any, snapshot: FamilySafetyConfigSnapshot | None = None, *, preview_only: bool = False) -> dict[str, Any]:
    snapshot = snapshot or latest_family_safety_snapshot(db)
    if snapshot is None:
        return {"status": "no_snapshot", "restore_changes": [], "message": "No wizard snapshot is available."}
    current = load_settings(db)
    before_payload = snapshot.settings_before
    restore_changes: list[dict[str, Any]] = []
    for item in snapshot.selected_changes:
        path = str(item.get("setting_path", ""))
        if not path:
            continue
        try:
            current_value = _get_path(current, path)
            before_value = _dict_path(before_payload, path)
        except Exception as exc:
            restore_changes.append({"setting_path": path, "status": "failed", "failure_reason": str(exc)})
            continue
        restore_changes.append({"setting_path": path, "current_value": current_value, "restore_value": before_value, "status": "pending"})
    if preview_only:
        return {"status": "preview", "snapshot": snapshot.to_dict(), "restore_changes": restore_changes}
    for item in restore_changes:
        if item.get("status") == "pending":
            try:
                _set_path(current, str(item["setting_path"]), item.get("restore_value"))
                item["status"] = "restored"
            except Exception as exc:
                item["status"] = "failed"
                item["failure_reason"] = str(exc)
    saved = save_settings(db, current, bump_version=any(item.get("status") == "restored" for item in restore_changes))
    result = {
        "status": "restored",
        "snapshot": snapshot.to_dict(),
        "restore_changes": restore_changes,
        "settings_version_after": saved.settings_version,
        "settings_sync": reconcile_settings(saved, runtime_values={"settings_version": saved.settings_version, "notifier_settings_version": saved.settings_version}).to_dict(),
        "restored_at": utc_now_iso(),
    }
    db.set_background_monitor_state(LAST_APPLY_REPORT_KEY, json.dumps(result, sort_keys=True, default=str))
    return result


def _dict_path(payload: dict[str, Any], setting_path: str) -> Any:
    current: Any = payload
    for part in setting_path.split("."):
        if not isinstance(current, dict):
            raise KeyError(setting_path)
        current = current[part]
    return current


__all__ = [
    "FamilySafetyConfigSnapshot",
    "SNAPSHOT_KEY",
    "LAST_RECOMMENDATION_KEY",
    "LAST_APPLY_REPORT_KEY",
    "CURRENT_PROFILE_KEY",
    "LAST_RUN_KEY",
    "apply_family_safety_recommendation",
    "create_family_safety_snapshot",
    "latest_family_safety_snapshot",
    "restore_family_safety_snapshot",
]
