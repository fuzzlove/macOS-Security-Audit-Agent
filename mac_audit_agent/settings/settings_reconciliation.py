from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from mac_audit_agent.settings.settings_versioning import SettingsVersions, build_settings_versions


@dataclass(frozen=True)
class SettingsMismatch:
    component: str
    expected: int | str | None
    observed: int | str | None
    source: str
    impact: str
    repair_action: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SettingsReconciliationResult:
    status: str
    ui_settings_version: int | None = None
    runtime_settings_version: int | None = None
    installed_manifest_settings_version: int | None = None
    notifier_settings_version: int | None = None
    effective_settings_version: int | None = None
    mismatches: list[SettingsMismatch] = field(default_factory=list)
    stale_components: list[str] = field(default_factory=list)
    repair_actions: list[str] = field(default_factory=list)
    safe_to_manual_test: bool = False
    requires_daemon_restart: bool = False
    requires_notifier_restart: bool = False
    requires_reinstall: bool = False
    monitor_mode_internal: str = ""
    monitor_mode_display: str = ""
    active_runtime_domain: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["mismatches"] = [item.to_dict() for item in self.mismatches]
        return payload


def _add_action(actions: list[str], action: str) -> None:
    if action and action not in actions:
        actions.append(action)


def _status_for(stale_components: list[str]) -> str:
    stale = set(stale_components)
    if not stale:
        return "synced"
    if stale == {"installed_manifest"}:
        return "installed_manifest_stale"
    if stale == {"runtime"}:
        return "runtime_stale"
    if stale == {"notifier"}:
        return "notifier_stale"
    if "runtime" in stale or "notifier" in stale:
        return "partially_applied"
    return "mismatch"


def reconcile_settings(
    settings: Any,
    *,
    runtime_values: dict[str, Any] | None = None,
    installed_values: dict[str, Any] | None = None,
) -> SettingsReconciliationResult:
    runtime_values = runtime_values or {}
    installed_values = installed_values or {}
    versions: SettingsVersions = build_settings_versions(settings, runtime_values=runtime_values, installed_values=installed_values)
    expected = versions.ui_settings_version
    mismatches: list[SettingsMismatch] = []
    stale_components: list[str] = []
    actions: list[str] = []

    if expected is None:
        return SettingsReconciliationResult(status="error", repair_actions=["Save settings again to create a valid settings version."], monitor_mode_internal=versions.monitor_mode_internal, monitor_mode_display=versions.monitor_mode_display, active_runtime_domain=versions.active_runtime_domain)

    runtime_present = "settings_version" in runtime_values or "daemon_settings_version" in runtime_values
    notifier_present = "notifier_settings_version" in runtime_values
    installed_present = "installed_manifest" in installed_values or "settings_version_installed" in installed_values

    if runtime_present and versions.runtime_settings_version != expected:
        stale_components.append("runtime")
        _add_action(actions, "Apply Settings to Runtime")
        _add_action(actions, "Restart Background Monitor")
        mismatches.append(
            SettingsMismatch(
                component="System Daemon Runtime",
                expected=expected,
                observed=versions.runtime_settings_version,
                source="current_runtime_values.settings_version",
                impact="The active monitor may still enforce older alert, detector, or persistence settings.",
                repair_action="Apply Settings to Runtime, then restart the background monitor if the version does not update.",
            )
        )

    if notifier_present and versions.notifier_settings_version != expected:
        stale_components.append("notifier")
        _add_action(actions, "Restart User Notifier")
        mismatches.append(
            SettingsMismatch(
                component="User Notifier Runtime",
                expected=expected,
                observed=versions.notifier_settings_version,
                source="current_runtime_values.notifier_settings_version",
                impact="Bottom-right alert delivery may use stale severity or notification policy.",
                repair_action="Restart User Notifier after applying settings.",
            )
        )

    if installed_present and versions.installed_manifest_settings_version != expected:
        stale_components.append("installed_manifest")
        _add_action(actions, "Rebuild Installed Manifest")
        _add_action(actions, "Repair Background Monitor")
        mismatches.append(
            SettingsMismatch(
                component="Installed Monitor Manifest",
                expected=expected,
                observed=versions.installed_manifest_settings_version,
                source="installed_monitor_values.installed_manifest.settings_version",
                impact="The install manifest is stale and should not be treated as live runtime truth.",
                repair_action="Repair Background Monitor or rebuild the installed manifest after runtime confirms the latest settings.",
            )
        )

    status = _status_for(stale_components)
    return SettingsReconciliationResult(
        status=status,
        ui_settings_version=versions.ui_settings_version,
        runtime_settings_version=versions.runtime_settings_version,
        installed_manifest_settings_version=versions.installed_manifest_settings_version,
        notifier_settings_version=versions.notifier_settings_version,
        effective_settings_version=versions.effective_settings_version,
        mismatches=mismatches,
        stale_components=stale_components,
        repair_actions=actions or ["No settings sync repair required."],
        safe_to_manual_test=status in {"synced", "installed_manifest_stale"},
        requires_daemon_restart="runtime" in stale_components,
        requires_notifier_restart="notifier" in stale_components,
        requires_reinstall="installed_manifest" in stale_components and ("runtime" not in stale_components and "notifier" not in stale_components),
        monitor_mode_internal=versions.monitor_mode_internal,
        monitor_mode_display=versions.monitor_mode_display,
        active_runtime_domain=versions.active_runtime_domain,
    )


__all__ = ["SettingsMismatch", "SettingsReconciliationResult", "reconcile_settings"]
