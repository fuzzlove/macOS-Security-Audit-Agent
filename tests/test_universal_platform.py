from __future__ import annotations

import subprocess
from pathlib import Path

from mac_audit_agent.platform import architecture
from mac_audit_agent.platform.capabilities import CapabilityState, evaluate_platform_capabilities
from mac_audit_agent.platform.dependency_probe import probe_dependency
from mac_audit_agent.platform.execution_mode import detect_execution_mode
from mac_audit_agent.platform.paths import resolve_platform_paths


def test_arm64_native_and_universal2_interpreter(monkeypatch) -> None:
    monkeypatch.setattr(architecture.platform, "machine", lambda: "arm64")
    def run(args, timeout=3.0):
        if "sysctl.proc_translated" in args: return 0, "0", ""
        if "hw.optional.arm64" in args: return 0, "1", ""
        if "lipo" in args[0]: return 0, "x86_64 arm64", ""
        return None, "", "unexpected"
    monkeypatch.setattr(architecture, "_run", run)
    info=architecture.detect_architecture()
    assert info.native_hardware == "arm64" and info.native_execution
    assert info.universal2_interpreter


def test_rosetta_and_intel_detection(monkeypatch) -> None:
    monkeypatch.setattr(architecture.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(architecture, "_run", lambda args, timeout=3.0: (0, "1", "") if "sysctl.proc_translated" in args else (0, "1", "") if "hw.optional.arm64" in args else (0, "x86_64", ""))
    info=architecture.detect_architecture()
    assert info.native_hardware == "arm64" and info.process == "x86_64" and info.rosetta_translated and not info.native_execution


def test_probe_timeout_is_structured(monkeypatch) -> None:
    def timeout(*args, **kwargs): raise subprocess.TimeoutExpired(args[0], 3)
    monkeypatch.setattr(architecture.subprocess, "run", timeout)
    code, stdout, error=architecture._run(["sysctl"])
    assert code is None and not stdout and "TimeoutExpired" in error


def test_platform_paths_separate_resources_and_mutable_data() -> None:
    paths=resolve_platform_paths()
    assert paths.immutable_resources != paths.user_data
    assert "Application Support" in paths.user_data
    assert Path(paths.temporary).is_absolute()


def test_execution_mode_and_dependency_probe_are_structured() -> None:
    assert detect_execution_mode().mode in {"source_checkout","pip_installation","packaged_app","packaged_executable"}
    probe=probe_dependency("definitely-missing-msaa-package","definitely_missing_msaa_module",category="optional")
    assert not probe.available and probe.version == "missing"


def test_security_capabilities_never_claim_endpoint_sensor_active() -> None:
    statuses=evaluate_platform_capabilities()
    assert statuses["endpoint_security"].state is CapabilityState.NOT_ENTITLED
    assert not statuses["endpoint_security"].available
    assert statuses["full_disk_access"].state is CapabilityState.PERMISSION_REQUIRED
