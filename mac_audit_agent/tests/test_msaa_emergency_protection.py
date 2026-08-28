from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from mac_audit_agent.security.lockdown.lockdown_manager import LockdownManager
from mac_audit_agent.security.lockdown.lockdown_permissions import ActivationAuthorization, CONFIRMATION_PHRASE
from mac_audit_agent.security.lockdown.lockdown_policy import APPLE_DISCLAIMER, PRODUCT_NAME, load_profile, profile_impact_summary


class FakeRunner:
    def __init__(self, fail_command: str = "") -> None:
        self.calls: list[list[str]] = []
        self.fail_command = fail_command

    def __call__(self, command, **_kwargs):
        command = list(command); self.calls.append(command)
        joined = " ".join(command)
        stdout = ""
        if "-getremotelogin" in joined: stdout = "Remote Login: Off"
        elif "--getglobalstate" in joined: stdout = "Firewall is enabled. (State = 1)"
        return subprocess.CompletedProcess(command, 1 if self.fail_command and self.fail_command in joined else 0, stdout, "injected failure" if self.fail_command and self.fail_command in joined else "")


def _auth() -> ActivationAuthorization:
    return ActivationAuthorization("Security Administrator", "Active ransomware containment", "INC-2026-0717", True, CONFIRMATION_PHRASE, 0)


def test_profiles_never_claim_apple_lockdown_mode() -> None:
    profile = load_profile("critical_zero_day")
    payload = profile.to_dict()
    assert payload["product_name"] == PRODUCT_NAME
    assert payload["apple_lockdown_mode"] is False
    assert "does not enable" in payload["disclaimer"]


def test_profile_impact_summary_matches_enforced_controls_and_network_limit() -> None:
    emergency = profile_impact_summary(load_profile("emergency"))
    investigation = profile_impact_summary(load_profile("investigation_mode"))
    assert any("Remote Login" in item for item in emergency["system_changes"])
    assert any("SSH" in item for item in emergency["negative_impacts"])
    assert "does not apply PF isolation" in emergency["network_effect"]
    assert not any("Remote Login" in item for item in investigation["system_changes"])
    assert "No PF network isolation" in investigation["network_effect"]
    assert any("guarantee containment" in item for item in emergency["not_performed"])


def test_preflight_writes_hash_verified_report(tmp_path: Path) -> None:
    manager = LockdownManager(tmp_path, runner=FakeRunner(), require_root=False)
    report = manager.preflight("emergency")
    written = json.loads((tmp_path / "lockdown_preflight_report.json").read_text())
    assert report["ready"] is True
    assert written["integrity"]["algorithm"] == "sha256"
    assert written["apple_lockdown_mode"] is False


def test_preflight_uses_desktop_uid_and_valid_kmutil_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runner = FakeRunner()
    monkeypatch.setattr("mac_audit_agent.security.lockdown.lockdown_manager.user_launchctl_uid", lambda: 501)

    LockdownManager(tmp_path, runner=runner, require_root=False).preflight("emergency")

    assert ["/bin/launchctl", "print", "gui/501"] in runner.calls
    assert ["/usr/bin/kmutil", "showloaded"] in runner.calls
    assert ["/usr/sbin/kmutil", "showloaded"] not in runner.calls


def test_activation_requires_complete_explicit_authorization(tmp_path: Path) -> None:
    manager = LockdownManager(tmp_path, runner=FakeRunner(), require_root=False)
    invalid = ActivationAuthorization("", "", "", False, "", 0)
    with pytest.raises(PermissionError): manager.enable("emergency", invalid)
    assert not (tmp_path / "active_state.json").exists()


def test_enable_disable_restores_observed_original_state(tmp_path: Path) -> None:
    runner = FakeRunner()
    manager = LockdownManager(tmp_path, runner=runner, require_root=False)
    active = manager.enable("emergency", _auth())
    restored = manager.disable(_auth(), restore=True)
    assert active["active"] is True
    assert restored["restored"] is True
    assert ["/usr/sbin/systemsetup", "-setremotelogin", "off"] in runner.calls
    assert ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"] in runner.calls
    assert ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"] in runner.calls[-2:]
    assert ["/usr/sbin/systemsetup", "-setremotelogin", "off"] in runner.calls[-2:]
    assert not manager.status()["active"]


def test_partial_activation_rolls_back_and_preserves_evidence(tmp_path: Path) -> None:
    runner = FakeRunner(fail_command="--setglobalstate on")
    manager = LockdownManager(tmp_path, runner=runner, require_root=False)
    with pytest.raises(RuntimeError): manager.enable("emergency", _auth())
    reports = list((tmp_path / "activations").glob("*/partial_activation.json"))
    assert reports
    assert not (tmp_path / "active_state.json").exists()


def test_persistent_status_and_exception_are_audit_ready(tmp_path: Path) -> None:
    manager = LockdownManager(tmp_path, runner=FakeRunner(), require_root=False)
    manager.enable("investigation_mode", _auth())
    exception = manager.add_exception("Xcode.app", 15, "Deploy security patch", _auth())
    status = manager.status()
    assert status["persistent_banner"] is True
    assert status["rollback_available"] is True
    assert status["exceptions"][0]["expires_at"] == exception["expires_at"]
    assert APPLE_DISCLAIMER in status["disclaimer"]


def test_modified_active_state_is_reported_as_tampering(tmp_path: Path) -> None:
    manager = LockdownManager(tmp_path, runner=FakeRunner(), require_root=False)
    manager.enable("investigation_mode", _auth())
    path = tmp_path / "active_state.json"
    payload = json.loads(path.read_text())
    payload["active"] = False
    path.write_text(json.dumps(payload))
    status = manager.status()
    assert status["tamper_detected"] is True
    assert status["error"] == "LOCKDOWN_STATE_INTEGRITY_MISMATCH"
