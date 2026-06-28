from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mac_audit_agent.storage import json_safe


FLEET_BASELINE_FILENAME = "fleet_baseline.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _artifacts(payload: Any) -> dict[str, Any]:
    if hasattr(payload, "collected_artifacts"):
        return getattr(payload, "collected_artifacts")
    if hasattr(payload, "artifacts"):
        return getattr(payload, "artifacts")
    if hasattr(payload, "to_dict"):
        payload = payload.to_dict()
    if not isinstance(payload, dict):
        return {}
    return payload.get("collected_artifacts", payload)


def _as_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    if isinstance(value, dict):
        return value
    return {"value": str(value)}


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _redact_text(value: str) -> str:
    if not value:
        return value
    parts = value.split("/")
    for index, part in enumerate(parts):
        if index > 0 and parts[index - 1] == "Users" and part:
            parts[index] = f"[redacted-user-{_stable_hash(part)}]"
    redacted = "/".join(parts)
    return redacted


def _maybe_redact(value: Any, redact: bool) -> Any:
    if not redact:
        return json_safe(value)
    if isinstance(value, dict):
        return {str(key): _maybe_redact(item, redact) for key, item in value.items()}
    if isinstance(value, list):
        return [_maybe_redact(item, redact) for item in value]
    if isinstance(value, tuple):
        return [_maybe_redact(item, redact) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return json_safe(value)


def _security_settings(artifacts: dict[str, Any]) -> dict[str, str]:
    system_info = artifacts.get("system_info", {}) if isinstance(artifacts.get("system_info"), dict) else {}
    network_info = artifacts.get("network_info", {}) if isinstance(artifacts.get("network_info"), dict) else {}
    return {
        "firewall": _text(system_info.get("security.firewall_status", artifacts.get("firewall", artifacts.get("firewall_status", "")))),
        "filevault": _text(system_info.get("security.filevault", artifacts.get("filevault", artifacts.get("filevault_status", "")))),
        "ssh_remote_login": _text(system_info.get("remote_login", network_info.get("remote_login", artifacts.get("ssh_remote_login", artifacts.get("remote_login", ""))))),
    }


def _macos_version(artifacts: dict[str, Any]) -> str:
    system_info = artifacts.get("system_info", {}) if isinstance(artifacts.get("system_info"), dict) else {}
    for key in ("macos_version", "os_version", "productVersion", "sw_vers"):
        value = _text(system_info.get(key, artifacts.get(key, "")))
        if value:
            return value
    return ""


def _hostname(artifacts: dict[str, Any]) -> str:
    system_info = artifacts.get("system_info", {}) if isinstance(artifacts.get("system_info"), dict) else {}
    return _text(system_info.get("hostname", artifacts.get("hostname", "")))


def _launch_items(artifacts: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    agents: list[dict[str, Any]] = []
    daemons: list[dict[str, Any]] = []
    for raw_item in artifacts.get("launch_snapshots", []):
        item = _as_dict(raw_item)
        path = _text(item.get("path"))
        normalized = {
            "path": path,
            "label": _text(item.get("label")),
            "program": _text(item.get("program")),
        }
        if "LaunchDaemons" in path:
            daemons.append(normalized)
        else:
            agents.append(normalized)
    for raw_item in artifacts.get("launchagents", []):
        agents.append(_as_dict(raw_item))
    for raw_item in artifacts.get("launchdaemons", []):
        daemons.append(_as_dict(raw_item))
    return _dedupe_dicts(agents), _dedupe_dicts(daemons)


def _apps(artifacts: dict[str, Any]) -> list[str]:
    values = artifacts.get("installed_apps", artifacts.get("applications", []))
    apps: list[str] = []
    if isinstance(values, dict):
        values = values.values()
    for raw_item in values if isinstance(values, (list, tuple, set, dict)) else [values]:
        item = _as_dict(raw_item)
        name = _text(item.get("name") or item.get("path") or item.get("bundle_id") or item.get("value"))
        if name:
            apps.append(name)
    return sorted(set(apps))


def _admin_users(artifacts: dict[str, Any]) -> list[str]:
    admins: list[str] = []
    for raw_item in artifacts.get("users", artifacts.get("admin_users", [])):
        item = _as_dict(raw_item)
        username = _text(item.get("username") or item.get("name") or item.get("value"))
        if username and (bool(item.get("admin")) or raw_item in artifacts.get("admin_users", [])):
            admins.append(username)
    for raw_item in artifacts.get("admin_users", []):
        username = _text(raw_item.get("username") if isinstance(raw_item, dict) else raw_item)
        if username:
            admins.append(username)
    return sorted(set(admins))


def _dedupe_dicts(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for item in items:
        key = json.dumps(json_safe(item), sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _item_keys(items: list[dict[str, Any]]) -> set[str]:
    keys: set[str] = set()
    for item in items:
        for key in ("path", "label", "program", "name"):
            value = _text(item.get(key))
            if value:
                keys.add(value)
    return keys


@dataclass
class FleetBaseline:
    baseline_id: str
    created_at: str
    macos_version: str
    expected_security_settings: dict[str, str]
    allowed_launchagents: list[dict[str, Any]] = field(default_factory=list)
    allowed_launchdaemons: list[dict[str, Any]] = field(default_factory=list)
    allowed_apps: list[str] = field(default_factory=list)
    expected_firewall_state: str = ""
    expected_filevault_state: str = ""
    expected_ssh_state: str = ""
    allowed_admin_users: list[str] = field(default_factory=list)
    source_hostname: str = ""
    include_admin_users: bool = False
    redacted: bool = True
    notes: str = ""
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FleetBaselineDeviation:
    category: str
    item: str
    expected: Any
    observed: Any
    severity: str
    confidence: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FleetBaselineComparison:
    baseline_id: str
    compared_at: str
    deviations: list[FleetBaselineDeviation]
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "compared_at": self.compared_at,
            "deviations": [item.to_dict() for item in self.deviations],
            "summary": self.summary,
        }


def build_fleet_baseline(
    payload: Any,
    *,
    baseline_id: str = "fleet-baseline",
    include_admin_users: bool = False,
    redact: bool = True,
    notes: str = "",
) -> FleetBaseline:
    artifacts = _artifacts(payload)
    settings = _security_settings(artifacts)
    agents, daemons = _launch_items(artifacts)
    admins = _admin_users(artifacts) if include_admin_users else []
    if redact:
        admins = [f"[redacted-admin-{index + 1}]" for index, _ in enumerate(admins)]
    baseline = FleetBaseline(
        baseline_id=baseline_id,
        created_at=_now(),
        macos_version=_text(_maybe_redact(_macos_version(artifacts), redact)),
        source_hostname="[redacted-hostname]" if redact and _hostname(artifacts) else _hostname(artifacts),
        expected_security_settings={key: _text(_maybe_redact(value, redact)) for key, value in settings.items()},
        expected_firewall_state=_text(_maybe_redact(settings.get("firewall", ""), redact)),
        expected_filevault_state=_text(_maybe_redact(settings.get("filevault", ""), redact)),
        expected_ssh_state=_text(_maybe_redact(settings.get("ssh_remote_login", ""), redact)),
        allowed_launchagents=_maybe_redact(agents, redact),
        allowed_launchdaemons=_maybe_redact(daemons, redact),
        allowed_apps=[_text(_maybe_redact(item, redact)) for item in _apps(artifacts)],
        allowed_admin_users=admins,
        include_admin_users=include_admin_users,
        redacted=redact,
        notes=_text(_maybe_redact(notes, redact)),
    )
    return baseline


def export_fleet_baseline(baseline: FleetBaseline | dict[str, Any], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = baseline.to_dict() if hasattr(baseline, "to_dict") else dict(baseline)
    output_path.write_text(json.dumps(json_safe(payload), indent=2, sort_keys=True), encoding="utf-8")
    return output_path


def import_fleet_baseline(path: Path) -> FleetBaseline:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return FleetBaseline(
        baseline_id=_text(payload.get("baseline_id", "fleet-baseline")),
        created_at=_text(payload.get("created_at", "")),
        macos_version=_text(payload.get("macos_version", "")),
        expected_security_settings=dict(payload.get("expected_security_settings", {})),
        allowed_launchagents=[_as_dict(item) for item in payload.get("allowed_launchagents", [])],
        allowed_launchdaemons=[_as_dict(item) for item in payload.get("allowed_launchdaemons", [])],
        allowed_apps=[_text(item) for item in payload.get("allowed_apps", [])],
        expected_firewall_state=_text(payload.get("expected_firewall_state", "")),
        expected_filevault_state=_text(payload.get("expected_filevault_state", "")),
        expected_ssh_state=_text(payload.get("expected_ssh_state", "")),
        allowed_admin_users=[_text(item) for item in payload.get("allowed_admin_users", [])],
        source_hostname=_text(payload.get("source_hostname", "")),
        include_admin_users=bool(payload.get("include_admin_users", False)),
        redacted=bool(payload.get("redacted", True)),
        notes=_text(payload.get("notes", "")),
        schema_version=int(payload.get("schema_version", 1)),
    )


def _add_deviation(deviations: list[FleetBaselineDeviation], category: str, item: str, expected: Any, observed: Any, severity: str, recommendation: str) -> None:
    deviations.append(
        FleetBaselineDeviation(
            category=category,
            item=item,
            expected=json_safe(expected),
            observed=json_safe(observed),
            severity=severity,
            confidence="medium",
            recommendation=recommendation,
        )
    )


def compare_to_fleet_baseline(payload: Any, baseline: FleetBaseline | dict[str, Any]) -> FleetBaselineComparison:
    if isinstance(baseline, dict):
        baseline = import_fleet_baseline_from_dict(baseline)
    artifacts = _artifacts(payload)
    settings = _security_settings(artifacts)
    agents, daemons = _launch_items(artifacts)
    apps = set(_apps(artifacts))
    admins = set(_admin_users(artifacts))
    deviations: list[FleetBaselineDeviation] = []

    current_macos = _macos_version(artifacts)
    if baseline.macos_version and current_macos and current_macos != baseline.macos_version:
        _add_deviation(deviations, "macos_version", "macOS version", baseline.macos_version, current_macos, "low", "Confirm whether this Mac should match the fleet baseline OS version.")

    setting_expectations = {
        "firewall": baseline.expected_firewall_state or baseline.expected_security_settings.get("firewall", ""),
        "filevault": baseline.expected_filevault_state or baseline.expected_security_settings.get("filevault", ""),
        "ssh_remote_login": baseline.expected_ssh_state or baseline.expected_security_settings.get("ssh_remote_login", ""),
    }
    for key, expected in setting_expectations.items():
        observed = settings.get(key, "")
        if expected and observed and observed != expected:
            severity = "medium" if key in {"firewall", "ssh_remote_login"} else "high"
            _add_deviation(deviations, "security_settings", key, expected, observed, severity, "Review the setting against the known-good fleet policy.")

    allowed_agents = _item_keys(baseline.allowed_launchagents)
    for item in agents:
        keys = _item_keys([item])
        if allowed_agents and keys.isdisjoint(allowed_agents):
            _add_deviation(deviations, "launchagents", _text(item.get("path") or item.get("label")), "allowed LaunchAgent", item, "medium", "Verify this LaunchAgent is expected for this lab or school fleet.")

    allowed_daemons = _item_keys(baseline.allowed_launchdaemons)
    for item in daemons:
        keys = _item_keys([item])
        if allowed_daemons and keys.isdisjoint(allowed_daemons):
            _add_deviation(deviations, "launchdaemons", _text(item.get("path") or item.get("label")), "allowed LaunchDaemon", item, "high", "Verify this LaunchDaemon owner, signature, and deployment source.")

    allowed_apps = set(baseline.allowed_apps)
    for app in sorted(apps - allowed_apps) if allowed_apps else []:
        _add_deviation(deviations, "installed_apps", app, "allowed app", app, "low", "Confirm whether this app should be part of the fleet image.")

    if baseline.include_admin_users and baseline.allowed_admin_users and not baseline.redacted:
        allowed_admins = set(baseline.allowed_admin_users)
        for username in sorted(admins - allowed_admins):
            _add_deviation(deviations, "admin_users", username, "allowed admin user", username, "high", "Confirm this admin account is authorized for the fleet.")

    summary = {
        "deviation_count": len(deviations),
        "high": sum(1 for item in deviations if item.severity == "high"),
        "medium": sum(1 for item in deviations if item.severity == "medium"),
        "low": sum(1 for item in deviations if item.severity == "low"),
        "redacted_baseline": baseline.redacted,
        "admin_user_comparison_enabled": baseline.include_admin_users and not baseline.redacted,
    }
    return FleetBaselineComparison(baseline_id=baseline.baseline_id, compared_at=_now(), deviations=deviations, summary=summary)


def import_fleet_baseline_from_dict(payload: dict[str, Any]) -> FleetBaseline:
    return FleetBaseline(
        baseline_id=_text(payload.get("baseline_id", "fleet-baseline")),
        created_at=_text(payload.get("created_at", "")),
        macos_version=_text(payload.get("macos_version", "")),
        expected_security_settings=dict(payload.get("expected_security_settings", {})),
        allowed_launchagents=[_as_dict(item) for item in payload.get("allowed_launchagents", [])],
        allowed_launchdaemons=[_as_dict(item) for item in payload.get("allowed_launchdaemons", [])],
        allowed_apps=[_text(item) for item in payload.get("allowed_apps", [])],
        expected_firewall_state=_text(payload.get("expected_firewall_state", "")),
        expected_filevault_state=_text(payload.get("expected_filevault_state", "")),
        expected_ssh_state=_text(payload.get("expected_ssh_state", "")),
        allowed_admin_users=[_text(item) for item in payload.get("allowed_admin_users", [])],
        source_hostname=_text(payload.get("source_hostname", "")),
        include_admin_users=bool(payload.get("include_admin_users", False)),
        redacted=bool(payload.get("redacted", True)),
        notes=_text(payload.get("notes", "")),
        schema_version=int(payload.get("schema_version", 1)),
    )


def export_fleet_drift_report(comparison: FleetBaselineComparison | dict[str, Any], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = comparison.to_dict() if hasattr(comparison, "to_dict") else dict(comparison)
    output_path.write_text(json.dumps(json_safe(payload), indent=2, sort_keys=True), encoding="utf-8")
    return output_path
