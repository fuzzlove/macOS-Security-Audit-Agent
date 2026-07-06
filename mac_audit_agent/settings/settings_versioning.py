from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class SettingsVersions:
    ui_settings_version: int | None = None
    runtime_settings_version: int | None = None
    installed_manifest_settings_version: int | None = None
    notifier_settings_version: int | None = None
    effective_settings_version: int | None = None
    monitor_mode_internal: str = ""
    monitor_mode_display: str = ""
    active_runtime_domain: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _int_or_none(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _installed_manifest_version(installed_values: dict[str, Any]) -> int | None:
    raw = installed_values.get("installed_manifest")
    if isinstance(raw, str) and raw:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict):
            version = _int_or_none(payload.get("settings_version"))
            if version is not None:
                return version
    return _int_or_none(installed_values.get("settings_version_installed"))


def monitor_mode_display(mode: str) -> str:
    return {
        "protected": "Protected System Daemon",
        "system": "Protected System Daemon",
        "user": "User LaunchAgent",
        "disabled": "Disabled",
    }.get(str(mode or "user"), str(mode or "User LaunchAgent"))


def build_settings_versions(
    settings: Any,
    *,
    runtime_values: dict[str, Any] | None = None,
    installed_values: dict[str, Any] | None = None,
) -> SettingsVersions:
    runtime_values = runtime_values or {}
    installed_values = installed_values or {}
    ui_version = _int_or_none(getattr(settings, "settings_version", None))
    runtime_version = _int_or_none(runtime_values.get("settings_version") or runtime_values.get("daemon_settings_version"))
    notifier_version = _int_or_none(runtime_values.get("notifier_settings_version"))
    installed_version = _installed_manifest_version(installed_values)
    effective_candidates = [runtime_version, notifier_version]
    effective_version = min(item for item in effective_candidates if item is not None) if any(item is not None for item in effective_candidates) else runtime_version
    mode = str(getattr(getattr(settings, "installation", object()), "monitor_mode", "") or runtime_values.get("monitor_mode") or installed_values.get("monitor_mode") or "user")
    return SettingsVersions(
        ui_settings_version=ui_version,
        runtime_settings_version=runtime_version,
        installed_manifest_settings_version=installed_version,
        notifier_settings_version=notifier_version,
        effective_settings_version=effective_version,
        monitor_mode_internal=mode,
        monitor_mode_display=monitor_mode_display(mode),
        active_runtime_domain="system" if mode in {"system", "protected"} else mode,
    )


__all__ = ["SettingsVersions", "build_settings_versions", "monitor_mode_display"]
