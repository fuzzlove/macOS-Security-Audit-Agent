from __future__ import annotations

import json
from pathlib import Path

from mac_audit_agent.protection.__main__ import main
from mac_audit_agent.protection.installer import ActiveProtectionInstallOptions, install_active_protection


def test_isolated_install_writes_and_verifies_required_components(tmp_path: Path) -> None:
    result = install_active_protection(ActiveProtectionInstallOptions(test_root=tmp_path))
    assert result.status == "test_root_verified"
    assert result.verification["daemon_plist_valid"] is True
    assert result.verification["notifier_plist_valid"] is True
    assert result.verification["database_schema_ok"] is True
    assert result.verification["live_launchctl_not_claimed"] is True
    assert result.evidence_path
    assert Path(result.evidence_path).is_file()


def test_plan_is_non_mutating_and_lists_components(capsys) -> None:
    assert main(["plan", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["destructive"] is False
    assert payload["administrator_approval_required"] is True
    assert payload["components"]
