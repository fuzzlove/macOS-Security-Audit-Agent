from __future__ import annotations

import os
import plistlib
from pathlib import Path
from types import SimpleNamespace

from mac_audit_agent.service_watchdog import (
    MAX_ATTEMPTS_PER_WINDOW,
    ServiceSpec,
    ServiceWatchdog,
    WATCHDOG_LABEL,
    build_watchdog_plist,
    known_service_specs,
)


class FakeLaunchctl:
    def __init__(self, *, loaded: bool = False, running: bool = False, repair_succeeds: bool = True) -> None:
        self.loaded = loaded
        self.running = running
        self.repair_succeeds = repair_succeeds
        self.commands: list[list[str]] = []

    def __call__(self, command, **_kwargs):
        argv = list(command)
        self.commands.append(argv)
        if argv[1] == "print":
            if not self.loaded:
                return SimpleNamespace(returncode=113, stdout="", stderr="service not found")
            state = "running" if self.running else "exited"
            pid = "\n\tpid = 4242" if self.running else ""
            return SimpleNamespace(returncode=0, stdout=f"state = {state}{pid}\n", stderr="")
        if argv[1] == "bootstrap":
            self.loaded = True
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if argv[1] == "kickstart":
            if self.repair_succeeds:
                self.loaded = True
                self.running = True
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(f"unexpected command: {argv}")


def _write_plist(path: Path, label: str, arguments: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps({"Label": label, "ProgramArguments": arguments}))
    path.chmod(0o644)


def _spec(path: Path) -> ServiceSpec:
    return ServiceSpec(
        label="com.mac-audit-agent.test-monitor",
        display_name="Test Monitor",
        domain="system",
        plist_path=path,
        expected_uid=os.getuid(),
        kind="native",
        expected_executable="/opt/msaa/test-monitor",
    )


def _watchdog(tmp_path: Path, spec: ServiceSpec, runner: FakeLaunchctl, *, now=lambda: 1_800_000_000.0) -> ServiceWatchdog:
    return ServiceWatchdog(
        uid=os.getuid(),
        home=tmp_path,
        specs=[spec],
        runner=runner,
        integrity_checker=lambda _spec, _args: (True, "test integrity verified"),
        state_path=tmp_path / "state.json",
        health_path=tmp_path / "health.json",
        audit_path=tmp_path / "audit.jsonl",
        lock_path=tmp_path / "watchdog.lock",
        db_path=tmp_path / "monitor.sqlite3",
        now=now,
    )


def test_watchdog_plist_is_periodic_one_shot_and_supports_source_runtime() -> None:
    payload = build_watchdog_plist("/usr/local/bin/python3", 501, interval_seconds=60)
    assert payload["Label"] == WATCHDOG_LABEL
    assert payload["RunAtLoad"] is True
    assert payload["StartInterval"] == 60
    assert "KeepAlive" not in payload
    assert payload["ProgramArguments"] == [
        "/usr/local/bin/python3",
        "-m",
        "mac_audit_agent.service_watchdog",
        "run-once",
        "--uid",
        "501",
    ]
    assert payload["EnvironmentVariables"]["PYTHONPATH"] == "/Library/Application Support/MacAuditAgent/runtime"


def test_watchdog_plist_supports_frozen_executable() -> None:
    payload = build_watchdog_plist("/Applications/MSAA.app/Contents/MacOS/MSAA", 501, frozen=True)
    assert payload["ProgramArguments"] == [
        "/Applications/MSAA.app/Contents/MacOS/MSAA",
        "--service-watchdog",
        "--uid",
        "501",
    ]
    assert "PYTHONPATH" not in payload["EnvironmentVariables"]


def test_fixed_inventory_contains_only_known_msaa_services(tmp_path: Path) -> None:
    labels = {item.label for item in known_service_specs(501, tmp_path)}
    assert labels == {
        "com.mac-audit-agent.monitor",
        "com.mac-audit-agent.sensor-health",
        "com.mac-audit-agent.user-notifier",
        "com.fuzzlove.MacAuditAgent.EndpointSecuritySensor",
        "com.fuzzlove.MacAuditAgent.ContainmentHelper",
        "com.macos-security-audit-agent.monitor",
        "com.macos-security-audit-agent.clickfix-guard",
    }


def test_healthy_service_is_verified_without_restart(tmp_path: Path) -> None:
    spec = _spec(tmp_path / "test.plist")
    _write_plist(spec.plist_path, spec.label, [spec.expected_executable])
    runner = FakeLaunchctl(loaded=True, running=True)
    payload = _watchdog(tmp_path, spec, runner).run_once()
    assert payload["healthy"] is True
    assert payload["services"][0]["integrity_verified"] is True
    assert payload["services"][0]["action"] == "none"
    assert not any(command[1] in {"bootstrap", "kickstart"} for command in runner.commands)


def test_unloaded_service_is_bootstrapped_and_restarted(tmp_path: Path) -> None:
    spec = _spec(tmp_path / "test.plist")
    _write_plist(spec.plist_path, spec.label, [spec.expected_executable])
    runner = FakeLaunchctl()
    payload = _watchdog(tmp_path, spec, runner).run_once()
    report = payload["services"][0]
    assert payload["healthy"] is True
    assert report["after"]["running"] is True
    assert "bootstrap" in report["action"]
    assert "kickstart" in report["action"]
    assert (tmp_path / "health.json").is_file()
    assert (tmp_path / "audit.jsonl").is_file()
    assert (tmp_path / "health.json").stat().st_mode & 0o777 == 0o644
    assert (tmp_path / "state.json").stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "audit.jsonl").stat().st_mode & 0o777 == 0o600


def test_tampered_plist_blocks_repair(tmp_path: Path) -> None:
    spec = _spec(tmp_path / "test.plist")
    _write_plist(spec.plist_path, "com.attacker.replaced", [spec.expected_executable])
    runner = FakeLaunchctl()
    payload = _watchdog(tmp_path, spec, runner).run_once()
    report = payload["services"][0]
    assert payload["healthy"] is False
    assert report["action"] == "blocked"
    assert "Label" in report["reason"]
    assert not any(command[1] in {"bootstrap", "kickstart"} for command in runner.commands)


def test_failed_integrity_blocks_repair(tmp_path: Path) -> None:
    spec = _spec(tmp_path / "test.plist")
    _write_plist(spec.plist_path, spec.label, [spec.expected_executable])
    runner = FakeLaunchctl()
    watchdog = _watchdog(tmp_path, spec, runner)
    watchdog.integrity_checker = lambda _spec, _args: (False, "signature rejected")
    payload = watchdog.run_once()
    assert payload["services"][0]["action"] == "blocked"
    assert payload["services"][0]["reason"] == "signature rejected"
    assert not any(command[1] in {"bootstrap", "kickstart"} for command in runner.commands)


def test_native_integrity_requires_expected_identifier_and_entitlement(tmp_path: Path) -> None:
    executable = tmp_path / "sensor"
    executable.write_bytes(b"signed fixture")
    spec = ServiceSpec(
        "com.fuzzlove.MacAuditAgent.EndpointSecuritySensor",
        "Endpoint Security Sensor",
        "system",
        tmp_path / "sensor.plist",
        os.getuid(),
        "native",
        str(executable),
        "com.fuzzlove.MacAuditAgent.EndpointSecuritySensor",
        "com.apple.developer.endpoint-security.client",
        None,
    )

    def codesign_runner(command, **_kwargs):
        if "--verify" in command:
            return SimpleNamespace(returncode=0, stdout="", stderr="valid on disk")
        if "--entitlements" in command:
            entitlements = plistlib.dumps({"com.apple.developer.endpoint-security.client": True}).decode()
            return SimpleNamespace(returncode=0, stdout=entitlements, stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout="",
            stderr="Identifier=com.fuzzlove.MacAuditAgent.EndpointSecuritySensor\nTeamIdentifier=QPWZZT9ZZK\n",
        )

    watchdog = ServiceWatchdog(
        uid=os.getuid(),
        home=tmp_path,
        specs=[spec],
        runner=codesign_runner,
        state_path=tmp_path / "state.json",
        health_path=tmp_path / "health.json",
        audit_path=tmp_path / "audit.jsonl",
        lock_path=tmp_path / "watchdog.lock",
    )
    assert watchdog._default_integrity_check(spec, [str(executable)]) == (True, "strict code signature verified")


def test_crash_loop_is_suppressed_after_bounded_repairs(tmp_path: Path) -> None:
    spec = _spec(tmp_path / "test.plist")
    _write_plist(spec.plist_path, spec.label, [spec.expected_executable])
    runner = FakeLaunchctl(repair_succeeds=False)
    clock = [1_800_000_000.0]
    watchdog = _watchdog(tmp_path, spec, runner, now=lambda: clock[0])
    for _ in range(MAX_ATTEMPTS_PER_WINDOW):
        payload = watchdog.run_once()
        assert payload["services"][0]["action"] != "suppressed"
        clock[0] += 30
    payload = watchdog.run_once()
    report = payload["services"][0]
    assert report["action"] == "suppressed"
    assert report["repair_suppressed"] is True
    kickstarts = [command for command in runner.commands if command[1] == "kickstart"]
    assert len(kickstarts) == MAX_ATTEMPTS_PER_WINDOW


def test_uninstalled_optional_service_is_not_adopted(tmp_path: Path) -> None:
    spec = _spec(tmp_path / "missing.plist")
    runner = FakeLaunchctl()
    payload = _watchdog(tmp_path, spec, runner).run_once()
    assert payload["installed_service_count"] == 0
    assert runner.commands == []
