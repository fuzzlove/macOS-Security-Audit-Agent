from __future__ import annotations

import json
import plistlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from mac_audit_agent.persistence_intelligence.models import PersistenceItem
from mac_audit_agent.persistence_intelligence.remediation import RemovalPlan, plan_removal, quarantine_removal


def test_apple_and_msaa_services_are_never_removable() -> None:
    apple = PersistenceItem.create("launchd", "/Library/LaunchDaemons/com.apple.example.plist", label="com.apple.example")
    msaa = PersistenceItem.create("launchd", "/Library/LaunchDaemons/com.mac-audit-agent.monitor.plist", label="com.mac-audit-agent.monitor")
    assert not plan_removal(apple).allowed
    assert not plan_removal(msaa).allowed


def test_user_launchagent_is_backed_up_unloaded_and_quarantined(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    plist = tmp_path / "Library/LaunchAgents/com.example.test.plist"
    plist.parent.mkdir(parents=True)
    plist.write_bytes(plistlib.dumps({"Label": "com.example.test", "ProgramArguments": ["/bin/echo"]}))
    item = PersistenceItem.create("launchd", str(plist), label="com.example.test", plist_path=str(plist), loaded=True)
    monkeypatch.setattr("mac_audit_agent.persistence_intelligence.remediation.require_permission", lambda _: None)
    commands: list[list[str]] = []
    monkeypatch.setattr(
        "mac_audit_agent.persistence_intelligence.remediation.subprocess.run",
        lambda command, **kwargs: commands.append(command) or SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    result = quarantine_removal(item)

    assert not plist.exists()
    assert Path(result["backup_path"]).exists()
    assert Path(result["quarantined_original"]).exists()
    assert json.loads(Path(result["manifest_path"]).read_text())["deleted"] is False
    assert commands[0][2].endswith("/com.example.test")


def test_system_removal_requires_administrator(tmp_path: Path, monkeypatch) -> None:
    item = PersistenceItem.create("launchd", "/Library/LaunchDaemons/com.example.test.plist", label="com.example.test", plist_path="/Library/LaunchDaemons/com.example.test.plist")
    monkeypatch.setattr("mac_audit_agent.persistence_intelligence.remediation.require_permission", lambda _: None)
    monkeypatch.setattr("mac_audit_agent.persistence_intelligence.remediation.os.geteuid", lambda: 501)
    with pytest.raises(PermissionError, match="ADMINISTRATOR_REQUIRED"):
        quarantine_removal(item)


def test_third_party_kext_system_and_driver_extensions_have_guarded_removal_plans() -> None:
    for mechanism, path in (
        ("kernel_extension", "/Library/Extensions/com.example.suspect.kext"),
        ("system_extension", "/Library/SystemExtensions/com.example.suspect.systemextension"),
        ("driver_extension", "/Library/DriverExtensions/com.example.suspect.dext"),
    ):
        plan = plan_removal(PersistenceItem.create(mechanism, path, label="com.example.suspect"))
        assert plan.allowed is True
        assert plan.administrator_required is True
        assert "System-wide removal" in plan.impact


def test_third_party_persistence_plists_across_library_are_removable() -> None:
    for path in (
        "/Library/Preferences/com.vendor.login-hook.plist",
        "/Library/Security/SecurityAgentPlugins/Vendor.bundle/Contents/Info.plist",
    ):
        plan = plan_removal(PersistenceItem.create("login_hook", path, label="com.vendor.persistence", plist_path=path))
        assert plan.allowed is True
        assert plan.administrator_required is True


def test_extension_suffix_enables_unload_even_when_scanner_mechanism_is_generic(tmp_path: Path, monkeypatch) -> None:
    kext = tmp_path / "Generic.KEXT"
    kext.mkdir()
    (kext / "payload").write_bytes(b"inert-test-kext")
    item = PersistenceItem.create("rootkit_artifact", str(kext), label="com.example.generic")
    plan = RemovalPlan(True, str(kext), item.label, "test", True, forced_removal_available=True)
    monkeypatch.setattr("mac_audit_agent.persistence_intelligence.remediation.plan_removal", lambda _: plan)
    monkeypatch.setattr("mac_audit_agent.persistence_intelligence.remediation.require_permission", lambda _: None)
    monkeypatch.setattr("mac_audit_agent.persistence_intelligence.remediation.os.geteuid", lambda: 0)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    commands: list[list[str]] = []
    monkeypatch.setattr(
        "mac_audit_agent.persistence_intelligence.remediation.subprocess.run",
        lambda command, **kwargs: commands.append(command) or SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    quarantine_removal(item, force_unload_extension=True, incident_reference="INC-1")

    assert commands == [["/usr/bin/kmutil", "unload", "-b", "com.example.generic"]]


def test_confirmed_malicious_kext_force_unload_is_identity_bound_and_audited(tmp_path: Path, monkeypatch) -> None:
    kext = tmp_path / "Suspect.kext"
    kext.mkdir()
    (kext / "payload").write_bytes(b"inert-test-kext")
    item = PersistenceItem.create("kernel_extension", str(kext), label="com.example.suspect")
    plan = RemovalPlan(True, str(kext), item.label, "test system-wide impact", True, forced_removal_available=True)
    monkeypatch.setattr("mac_audit_agent.persistence_intelligence.remediation.plan_removal", lambda _: plan)
    monkeypatch.setattr("mac_audit_agent.persistence_intelligence.remediation.require_permission", lambda _: None)
    monkeypatch.setattr("mac_audit_agent.persistence_intelligence.remediation.os.geteuid", lambda: 0)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    commands: list[list[str]] = []
    monkeypatch.setattr(
        "mac_audit_agent.persistence_intelligence.remediation.subprocess.run",
        lambda command, **kwargs: commands.append(command) or SimpleNamespace(returncode=1, stdout="", stderr="still loaded"),
    )

    result = quarantine_removal(item, force_unload_extension=True, incident_reference="INC-2026-0042")

    assert commands == [["/usr/bin/kmutil", "unload", "-b", "com.example.suspect"]]
    assert result["extension_unload"]["restart_required"] is True
    assert result["incident_reference"] == "INC-2026-0042"
    assert not kext.exists()
    assert Path(result["backup_path"]).is_dir()


def test_referenced_payload_can_be_separately_quarantined(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    payload = tmp_path / "Library/Application Support/Example/agent"
    payload.parent.mkdir(parents=True)
    payload.write_bytes(b"inert persistence test payload")
    plist = tmp_path / "Library/LaunchAgents/com.example.payload.plist"
    plist.parent.mkdir(parents=True)
    plist.write_bytes(plistlib.dumps({"Label": "com.example.payload", "Program": str(payload)}))
    import hashlib

    item = PersistenceItem.create(
        "launch_agent", str(plist), label="com.example.payload", plist_path=str(plist),
        executable_path=str(payload), target_hash_sha256=hashlib.sha256(payload.read_bytes()).hexdigest(),
    )
    monkeypatch.setattr("mac_audit_agent.persistence_intelligence.remediation.require_permission", lambda _: None)
    monkeypatch.setattr(
        "mac_audit_agent.persistence_intelligence.remediation.subprocess.run",
        lambda command, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    result = quarantine_removal(item, include_referenced_payload=True)
    assert result["payload"]["quarantined"] is True
    assert not payload.exists()
    assert Path(result["payload"]["backup_path"]).exists()


def test_system_and_symlink_payloads_are_refused(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    plist = tmp_path / "Library/LaunchAgents/com.example.system.plist"
    plist.parent.mkdir(parents=True)
    plist.write_bytes(plistlib.dumps({"Label": "com.example.system", "Program": "/bin/sh"}))
    item = PersistenceItem.create("launch_agent", str(plist), label="com.example.system", plist_path=str(plist))
    monkeypatch.setattr("mac_audit_agent.persistence_intelligence.remediation.require_permission", lambda _: None)
    monkeypatch.setattr(
        "mac_audit_agent.persistence_intelligence.remediation.subprocess.run",
        lambda command, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    with pytest.raises(RuntimeError, match="operating-system paths"):
        quarantine_removal(item, include_referenced_payload=True)


def test_force_stop_is_launchd_identity_bound_and_requires_opt_in(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    plist = tmp_path / "Library/LaunchAgents/com.example.stubborn.plist"
    plist.parent.mkdir(parents=True)
    plist.write_bytes(plistlib.dumps({"Label": "com.example.stubborn", "Program": str(tmp_path / "agent")}))
    item = PersistenceItem.create("launch_agent", str(plist), label="com.example.stubborn", plist_path=str(plist))
    monkeypatch.setattr("mac_audit_agent.persistence_intelligence.remediation.require_permission", lambda _: None)
    monkeypatch.setattr("mac_audit_agent.persistence_intelligence.remediation.os.getuid", lambda: 501)
    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[1] == "kill":
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        bootout_count = sum(candidate[1] == "bootout" for candidate in commands)
        return SimpleNamespace(returncode=1 if bootout_count == 1 else 0, stdout="", stderr="busy")

    monkeypatch.setattr("mac_audit_agent.persistence_intelligence.remediation.subprocess.run", fake_run)
    result = quarantine_removal(item, force_stop_launchd_job=True)
    assert commands[1] == ["/bin/launchctl", "kill", "SIGKILL", "gui/501/com.example.stubborn"]
    assert result["unload"]["force_stop_success"] is True
