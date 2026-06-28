from __future__ import annotations

import json
from pathlib import Path

from mac_audit_agent.fleet_baseline import (
    FLEET_BASELINE_FILENAME,
    build_fleet_baseline,
    compare_to_fleet_baseline,
    export_fleet_baseline,
    export_fleet_drift_report,
    import_fleet_baseline,
)


def _payload() -> dict:
    return {
        "system_info": {
            "macos_version": "macOS-14.5-arm64",
            "hostname": "lab-mac-01",
            "security.firewall_status": "enabled",
            "security.filevault": "on",
            "remote_login": "off",
        },
        "launch_snapshots": [
            {
                "path": "/Library/LaunchDaemons/com.school.agent.plist",
                "label": "com.school.agent",
                "program": "/Applications/School.app/Contents/MacOS/agent",
            },
            {
                "path": "/Users/alice/Library/LaunchAgents/com.user.agent.plist",
                "label": "com.user.agent",
                "program": "/Users/alice/bin/agent",
            },
        ],
        "installed_apps": [{"name": "Safari.app"}, {"name": "School.app"}],
        "users": [
            {"username": "alice", "admin": True},
            {"username": "student", "admin": False},
        ],
    }


def test_export_baseline(tmp_path: Path) -> None:
    baseline = build_fleet_baseline(_payload(), include_admin_users=True, redact=False)
    output = export_fleet_baseline(baseline, tmp_path / FLEET_BASELINE_FILENAME)
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert output.name == "fleet_baseline.json"
    assert payload["macos_version"] == "macOS-14.5-arm64"
    assert payload["expected_firewall_state"] == "enabled"
    assert payload["expected_filevault_state"] == "on"
    assert payload["expected_ssh_state"] == "off"
    assert "alice" in payload["allowed_admin_users"]


def test_import_baseline_round_trip(tmp_path: Path) -> None:
    baseline = build_fleet_baseline(_payload(), include_admin_users=True, redact=False)
    output = export_fleet_baseline(baseline, tmp_path / "fleet_baseline.json")
    imported = import_fleet_baseline(output)

    assert imported.baseline_id == baseline.baseline_id
    assert imported.allowed_apps == ["Safari.app", "School.app"]
    assert imported.allowed_launchdaemons[0]["label"] == "com.school.agent"


def test_compare_detects_drift() -> None:
    baseline = build_fleet_baseline(_payload(), include_admin_users=True, redact=False)
    current = _payload()
    current["system_info"]["security.firewall_status"] = "disabled"
    current["launch_snapshots"].append(
        {
            "path": "/Library/LaunchDaemons/com.unexpected.agent.plist",
            "label": "com.unexpected.agent",
            "program": "/tmp/unexpected",
        }
    )
    current["installed_apps"].append({"name": "Unexpected.app"})
    current["users"].append({"username": "tempadmin", "admin": True})

    comparison = compare_to_fleet_baseline(current, baseline)
    categories = {item.category for item in comparison.deviations}

    assert comparison.summary["deviation_count"] >= 4
    assert "security_settings" in categories
    assert "launchdaemons" in categories
    assert "installed_apps" in categories
    assert "admin_users" in categories


def test_redaction_works(tmp_path: Path) -> None:
    baseline = build_fleet_baseline(_payload(), include_admin_users=True, redact=True, notes="review /Users/alice/bin/agent")
    output = export_fleet_baseline(baseline, tmp_path / "fleet_baseline.json")
    text = output.read_text(encoding="utf-8")

    assert "alice" not in text
    assert "lab-mac-01" not in text
    assert "/Users/alice" not in text
    assert "[redacted-hostname]" in text
    assert "[redacted-admin-1]" in text
    assert "[redacted-user-" in text


def test_export_fleet_drift_report(tmp_path: Path) -> None:
    baseline = build_fleet_baseline(_payload(), redact=False)
    current = _payload()
    current["installed_apps"].append({"name": "Unexpected.app"})
    comparison = compare_to_fleet_baseline(current, baseline)

    output = export_fleet_drift_report(comparison, tmp_path / "fleet_drift.json")
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert payload["summary"]["deviation_count"] == 1
    assert payload["deviations"][0]["category"] == "installed_apps"
