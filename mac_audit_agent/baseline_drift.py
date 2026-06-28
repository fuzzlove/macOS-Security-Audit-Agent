from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from mac_audit_agent.frameworks import mapping_dicts, mappings_for_finding
from mac_audit_agent.storage import AuditDatabase, json_safe


TRACKED_CATEGORIES = [
    "launchagents",
    "launchdaemons",
    "login_items",
    "users_admins",
    "sudoers",
    "installed_apps",
    "running_services",
    "listening_ports",
    "dns_servers",
    "vpn_state",
    "firewall_status",
    "filevault_status",
    "ssh_remote_login",
    "screen_sharing",
    "profiles_mdm",
    "hosts_file",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class BaselineSnapshot:
    snapshot_id: str
    created_at: str
    trusted: bool
    source: str
    state: dict[str, dict[str, Any]]
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BaselineDriftFinding:
    drift_id: str
    category: str
    item_key: str
    change_type: str
    previous_state: Any
    current_state: Any
    first_seen: str
    last_seen: str
    severity: str
    confidence: str
    why_it_matters: str
    recommended_verification: str
    framework_mappings: list[dict[str, Any]] = field(default_factory=list)
    expected: bool = False
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _stable_json(value: Any) -> str:
    return json.dumps(json_safe(value), sort_keys=True, default=str)


def _normalize_map(values: Any) -> dict[str, Any]:
    if isinstance(values, dict):
        if all(not isinstance(value, (dict, list, tuple, set)) for value in values.values()):
            return {str(key): str(value) for key, value in values.items()}
        return {str(key): json_safe(value) for key, value in values.items()}
    if isinstance(values, (list, tuple, set)):
        mapped: dict[str, Any] = {}
        for item in values:
            if isinstance(item, dict):
                key = str(item.get("path") or item.get("label") or item.get("username") or item.get("name") or item.get("port") or item.get("id") or _stable_json(item))
                mapped[key] = json_safe(item)
            elif hasattr(item, "to_dict"):
                payload = item.to_dict()
                key = str(payload.get("path") or payload.get("label") or payload.get("username") or payload.get("name") or payload.get("port") or payload.get("local_address") or _stable_json(payload))
                mapped[key] = json_safe(payload)
            else:
                mapped[str(item)] = str(item)
        return mapped
    if values in (None, ""):
        return {}
    return {str(values): str(values)}


def state_from_payload(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    artifacts = payload.get("collected_artifacts", payload)
    ports = artifacts.get("ports", {}) if isinstance(artifacts.get("ports", {}), dict) else {}
    processes = artifacts.get("processes", {}) if isinstance(artifacts.get("processes", {}), dict) else {}
    network_info = artifacts.get("network_info", {}) if isinstance(artifacts.get("network_info", {}), dict) else {}
    network_discovery = artifacts.get("network_discovery", {}) if isinstance(artifacts.get("network_discovery", {}), dict) else {}
    system_info = artifacts.get("system_info", {}) if isinstance(artifacts.get("system_info", {}), dict) else {}
    launch_snapshots = artifacts.get("launch_snapshots", [])
    launchagents = []
    launchdaemons = []
    login_items = artifacts.get("login_items", [])
    for item in launch_snapshots:
        payload_item = item.to_dict() if hasattr(item, "to_dict") else dict(item) if isinstance(item, dict) else {"path": str(item)}
        path = str(payload_item.get("path", ""))
        if "LaunchDaemons" in path:
            launchdaemons.append(payload_item)
        elif "LaunchAgents" in path:
            launchagents.append(payload_item)
        else:
            launchagents.append(payload_item)
    users = []
    for item in artifacts.get("users", []):
        user = item.to_dict() if hasattr(item, "to_dict") else dict(item) if isinstance(item, dict) else {"username": str(item)}
        if bool(user.get("admin")):
            users.append(user)
    state = {
        "launchagents": _normalize_map(launchagents or artifacts.get("launchagents", [])),
        "launchdaemons": _normalize_map(launchdaemons or artifacts.get("launchdaemons", [])),
        "login_items": _normalize_map(login_items),
        "users_admins": _normalize_map(users or artifacts.get("admin_users", [])),
        "sudoers": _normalize_map(artifacts.get("sudoers_findings", artifacts.get("sudoers", []))),
        "installed_apps": _normalize_map(artifacts.get("installed_apps", artifacts.get("applications", []))),
        "running_services": _normalize_map(processes.get("all", artifacts.get("process_snapshots", []))),
        "listening_ports": _normalize_map(ports.get("listening", [])),
        "dns_servers": _normalize_map(network_info.get("dns_servers", network_discovery.get("dns_servers", artifacts.get("dns_servers", [])))),
        "vpn_state": _normalize_map(network_info.get("vpn_state", artifacts.get("vpn_state", ""))),
        "firewall_status": _normalize_map(system_info.get("security.firewall_status", artifacts.get("firewall", artifacts.get("firewall_status", "")))),
        "filevault_status": _normalize_map(system_info.get("security.filevault", artifacts.get("filevault", artifacts.get("filevault_status", "")))),
        "ssh_remote_login": _normalize_map(system_info.get("remote_login", artifacts.get("ssh_remote_login", artifacts.get("remote_login", "")))),
        "screen_sharing": _normalize_map(system_info.get("screen_sharing", artifacts.get("screen_sharing", ""))),
        "profiles_mdm": _normalize_map(artifacts.get("profiles_mdm", artifacts.get("configuration_profiles", []))),
        "hosts_file": _normalize_map(artifacts.get("hosts_file", "")),
    }
    return {category: state.get(category, {}) for category in TRACKED_CATEGORIES}


def snapshot_from_payload(payload: dict[str, Any], *, snapshot_id: str = "trusted-baseline", trusted: bool = True, source: str = "manual", note: str = "") -> BaselineSnapshot:
    return BaselineSnapshot(snapshot_id=snapshot_id, created_at=_now(), trusted=trusted, source=source, state=state_from_payload(payload), note=note)


class BaselineDriftEngine:
    def __init__(self, db: AuditDatabase | None = None) -> None:
        self.db = db

    def create_trusted_baseline(self, payload: dict[str, Any], *, baseline_id: str = "default", note: str = "") -> BaselineSnapshot:
        snapshot = snapshot_from_payload(payload, snapshot_id=baseline_id, trusted=True, source="trusted_baseline", note=note)
        if self.db is not None:
            self.db.record_baseline_drift_snapshot(snapshot.to_dict())
        return snapshot

    def load_trusted_baseline(self, baseline_id: str = "default") -> BaselineSnapshot | None:
        if self.db is None:
            return None
        payload = self.db.latest_baseline_drift_snapshot(baseline_id)
        if not payload:
            return None
        return BaselineSnapshot(
            snapshot_id=str(payload.get("snapshot_id", baseline_id)),
            created_at=str(payload.get("created_at", "")),
            trusted=bool(payload.get("trusted", True)),
            source=str(payload.get("source", "")),
            state={str(key): dict(value) for key, value in payload.get("state", {}).items() if isinstance(value, dict)},
            note=str(payload.get("note", "")),
        )

    def compare_current_state(self, current_payload: dict[str, Any], *, baseline: BaselineSnapshot | None = None, baseline_id: str = "default") -> dict[str, Any]:
        baseline = baseline or self.load_trusted_baseline(baseline_id)
        current = snapshot_from_payload(current_payload, snapshot_id="current", trusted=False, source="current_state")
        if baseline is None:
            return {"baseline_available": False, "current_snapshot": current.to_dict(), "findings": [], "summary": {"total": 0, "suppressed_expected": 0}}
        expected = self._expected_keys()
        findings, suppressed_expected = self._diff(baseline, current, expected)
        return {
            "baseline_available": True,
            "baseline_snapshot": baseline.to_dict(),
            "current_snapshot": current.to_dict(),
            "findings": [finding.to_dict() for finding in findings],
            "summary": {
                "total": len(findings),
                "review_recommended": sum(1 for item in findings if not item.expected),
                "suppressed_expected": suppressed_expected,
                "categories": sorted({item.category for item in findings}),
            },
        }

    def mark_expected(self, drift_id: str, *, note: str = "") -> None:
        if self.db is None:
            return
        self.db.record_expected_baseline_drift(drift_id, note=note)

    def add_note(self, drift_id: str, note: str) -> None:
        if self.db is None:
            return
        self.db.record_expected_baseline_drift(drift_id, note=note)

    def _expected_keys(self) -> set[str]:
        if self.db is None:
            return set()
        return set(self.db.list_expected_baseline_drift_ids())

    def _diff(self, baseline: BaselineSnapshot, current: BaselineSnapshot, expected: set[str]) -> tuple[list[BaselineDriftFinding], int]:
        findings: list[BaselineDriftFinding] = []
        suppressed_expected = 0
        for category in TRACKED_CATEGORIES:
            previous_items = baseline.state.get(category, {})
            current_items = current.state.get(category, {})
            keys = sorted(set(previous_items) | set(current_items))
            for key in keys:
                previous = previous_items.get(key)
                now = current_items.get(key)
                if _stable_json(previous) == _stable_json(now):
                    continue
                if previous is None:
                    change_type = "added"
                elif now is None:
                    change_type = "removed"
                else:
                    change_type = "changed"
                drift_id = self._drift_id(category, key, change_type)
                is_expected = drift_id in expected
                if is_expected:
                    suppressed_expected += 1
                    continue
                findings.append(self._finding(category, key, change_type, previous, now, baseline.created_at, current.created_at, drift_id))
        return findings, suppressed_expected

    def _finding(self, category: str, key: str, change_type: str, previous: Any, current: Any, first_seen: str, last_seen: str, drift_id: str) -> BaselineDriftFinding:
        severity = "high" if category in {"launchdaemons", "users_admins", "sudoers", "ssh_remote_login", "screen_sharing"} else "medium" if category in {"dns_servers", "listening_ports", "profiles_mdm", "hosts_file"} else "low"
        title = f"{category.replace('_', ' ').title()} changed"
        mapping_payload = {"category": self._framework_category(category), "title": title, "severity": severity, "rule_id": self._rule_id(category)}
        mappings = mapping_dicts(mappings_for_finding(mapping_payload))
        return BaselineDriftFinding(
            drift_id=drift_id,
            category=category,
            item_key=key,
            change_type=change_type,
            previous_state=previous,
            current_state=current,
            first_seen=first_seen,
            last_seen=last_seen,
            severity=severity,
            confidence="medium",
            why_it_matters=self._why_it_matters(category, change_type),
            recommended_verification=self._recommended_verification(category),
            framework_mappings=mappings,
            expected=False,
            note="",
        )

    def _drift_id(self, category: str, key: str, change_type: str) -> str:
        return f"{category}:{change_type}:{key}"

    def _framework_category(self, category: str) -> str:
        if category in {"launchagents", "launchdaemons", "login_items", "profiles_mdm"}:
            return "Persistence"
        if category in {"users_admins", "sudoers"}:
            return "Accounts & Privileges"
        if category in {"listening_ports", "dns_servers", "vpn_state", "ssh_remote_login", "screen_sharing"}:
            return "Network"
        return "Baseline Comparison"

    def _rule_id(self, category: str) -> str:
        return {
            "launchdaemons": "launchdaemon_added",
            "launchagents": "launchagent_added",
            "login_items": "login_item_added",
            "users_admins": "new_admin_user_detected",
            "dns_servers": "new_dns_server_detected",
            "listening_ports": "new_listener_detected",
        }.get(category, "baseline_drift")

    def _why_it_matters(self, category: str, change_type: str) -> str:
        labels = {
            "launchagents": "LaunchAgent changes can alter user login behavior and persistence.",
            "launchdaemons": "LaunchDaemon changes can alter privileged startup behavior and persistence.",
            "login_items": "Login item changes can start applications automatically after login.",
            "users_admins": "Administrator membership changes affect local privilege and account risk.",
            "sudoers": "Sudoers changes can alter privilege escalation paths.",
            "dns_servers": "DNS changes can redirect name resolution and affect trust decisions.",
            "listening_ports": "Listening port changes can expose new local services.",
            "ssh_remote_login": "Remote Login changes can affect remote administration exposure.",
            "screen_sharing": "Screen Sharing changes can affect remote interactive access.",
            "profiles_mdm": "Profile or MDM changes can alter system policy.",
            "hosts_file": "Hosts file changes can redirect local name resolution.",
        }
        return labels.get(category, f"{category.replace('_', ' ').title()} {change_type}; review recommended.")

    def _recommended_verification(self, category: str) -> str:
        return {
            "launchagents": "Inspect the plist path, owner, signature, package receipt, and creation time.",
            "launchdaemons": "Inspect the LaunchDaemon plist, referenced executable, owner, mode, and signature.",
            "login_items": "Verify the item in Login Items and confirm the source application.",
            "users_admins": "Confirm the account owner, admin group membership, and approval trail.",
            "sudoers": "Review sudoers files with syntax-safe tooling and confirm the change was approved.",
            "dns_servers": "Compare DNS servers against expected network, VPN, or MDM configuration.",
            "listening_ports": "Identify the owning process and confirm whether the listener is expected.",
            "hosts_file": "Review /etc/hosts contents and preserve a copy before editing.",
        }.get(category, "Preserve evidence, compare against the trusted baseline, and document whether the change is expected.")
