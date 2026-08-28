from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

from mac_audit_agent.anti_ransomware.health import ESClientResult
from mac_audit_agent.anti_ransomware.sensor_inspector import inspect_runtime_environment


class Runner:
    def __init__(self, sensor: Path, running: bool = False):
        self.sensor = sensor
        self.running = running

    def __call__(self, argv):
        command = " ".join(argv)
        if "kern.boottime" in command:
            return SimpleNamespace(returncode=0, stdout="{ sec = 100, usec = 0 }\n", stderr="")
        if argv[0].endswith("codesign") and "--verify" in argv:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if argv[0].endswith("codesign") and "--entitlements" in argv:
            return SimpleNamespace(returncode=0, stdout='<?xml version="1.0"?><plist version="1.0"><dict><key>com.apple.developer.endpoint-security.client</key><true/></dict></plist>', stderr=f"Executable={self.sensor}\n")
        if argv[0].endswith("codesign"):
            return SimpleNamespace(returncode=0, stdout="", stderr="Identifier=com.fuzzlove.sensor\nTeamIdentifier=TEAM123456\nCDHash=abc\nCodeDirectory=flags=0x10000(runtime)\ndesignated => identifier \"com.fuzzlove.sensor\"\n")
        if argv[0].endswith("file"):
            return SimpleNamespace(returncode=0, stdout=f"{self.sensor}: Mach-O 64-bit executable arm64\n", stderr="")
        if argv[0].endswith("spctl"):
            return SimpleNamespace(returncode=0, stdout="", stderr="accepted")
        if argv[0].endswith("launchctl"):
            return SimpleNamespace(returncode=0 if self.running else 113, stdout="state = running\n" if self.running else "", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="")


def test_build_artifact_is_not_an_installed_sensor(tmp_path):
    sensor = tmp_path / "dist" / "sensor"
    sensor.parent.mkdir()
    sensor.write_bytes(b"fixture")
    evidence = inspect_runtime_environment(sensor_path=sensor, health_path=tmp_path / "missing", runner=Runner(sensor), required_owner_uid=os.getuid())
    assert evidence.sensor_artifact_exists
    assert not evidence.sensor_installed
    assert evidence.entitlement_embedded
    assert not evidence.entitlement_accepted
    assert not evidence.endpoint_security_connected


def test_untrusted_or_stale_health_cannot_grant_live_predicates(tmp_path):
    sensor = tmp_path / "sensor"
    sensor.write_bytes(b"fixture")
    health = tmp_path / "health.json"
    health.write_text(json.dumps({"build_id":"source","boot_session_id":"wrong","recorded_at":1,"client_result":"SUCCESS","connected":True,"entitlement_accepted":True,"privacy_approval_present":True}))
    evidence = inspect_runtime_environment(sensor_path=sensor, health_path=health, runner=Runner(sensor, True), required_owner_uid=os.getuid(), now=100)
    assert not evidence.fresh
    assert not evidence.entitlement_accepted
    assert not evidence.tcc_approval_present
    assert not evidence.endpoint_security_connected
    assert evidence.sensor_details["live_health_evidence"] in {"identity_mismatch", "stale"}


def test_current_protected_health_is_field_independent(tmp_path):
    sensor = tmp_path / "sensor"
    sensor.write_bytes(b"fixture")
    runner = Runner(sensor, True)
    boot_probe = inspect_runtime_environment(sensor_path=sensor, health_path=tmp_path / "missing", runner=runner, required_owner_uid=os.getuid(), now=100)
    boot = boot_probe.current_boot_session_id
    health = tmp_path / "health.json"
    health.write_text(json.dumps({"build_id":"build-1","boot_session_id":boot,"recorded_at":100,"client_result":"SUCCESS","connected":True,"entitlement_accepted":True,"privacy_approval_present":False,"subscriptions_active":True,"live_event_seen":True,"sequence_tracking_active":True}))
    health.chmod(0o600)
    evidence = inspect_runtime_environment(current_build_id="build-1", sensor_path=sensor, health_path=health, runner=runner, required_owner_uid=os.getuid(), now=100)
    assert evidence.endpoint_security_connected
    assert evidence.entitlement_accepted
    assert not evidence.tcc_approval_present
    assert evidence.endpoint_security_subscriptions_active
    assert evidence.endpoint_security_live_event_seen
    assert evidence.endpoint_security_client_result is ESClientResult.SUCCESS


def test_not_privileged_client_result_is_preserved(tmp_path):
    sensor = tmp_path / "sensor"
    sensor.write_bytes(b"fixture")
    runner = Runner(sensor, True)
    boot_probe = inspect_runtime_environment(
        sensor_path=sensor,
        health_path=tmp_path / "missing",
        runner=runner,
        required_owner_uid=os.getuid(),
        now=100,
    )
    health = tmp_path / "health.json"
    health.write_text(
        json.dumps(
            {
                "build_id": "source",
                "boot_session_id": boot_probe.current_boot_session_id,
                "recorded_at": 100,
                "client_result": "NOT_PRIVILEGED",
                "connected": False,
            }
        )
    )
    health.chmod(0o600)
    evidence = inspect_runtime_environment(
        sensor_path=sensor,
        health_path=health,
        runner=runner,
        required_owner_uid=os.getuid(),
        now=100,
    )
    assert evidence.endpoint_security_client_result is ESClientResult.NOT_PRIVILEGED
    assert not evidence.endpoint_security_connected
