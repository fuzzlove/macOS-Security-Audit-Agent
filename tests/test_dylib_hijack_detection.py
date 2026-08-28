from __future__ import annotations

from pathlib import Path

from mac_audit_agent.rootkit_detection.dylib_hijack import (
    DylibHijackScanner,
    MachOLoadInfo,
    resolve_special_path,
    rootkit_findings_from_dylibs,
)


def _signature(path: Path) -> dict:
    if path.name == "App":
        return {"valid": True, "team_id": "GOODTEAM", "hardened_runtime": False, "disable_library_validation": False}
    if "early" in str(path):
        return {"valid": False, "team_id": "", "hardened_runtime": False, "disable_library_validation": False}
    return {"valid": True, "team_id": "GOODTEAM", "hardened_runtime": False, "disable_library_validation": False}


def test_existing_earlier_rpath_library_is_high_confidence_hijack_candidate(tmp_path: Path) -> None:
    app = tmp_path / "App"
    app.write_bytes(b"binary")
    early = tmp_path / "early"
    intended = tmp_path / "intended"
    early.mkdir()
    intended.mkdir()
    (early / "libExample.dylib").write_bytes(b"bad")
    (intended / "libExample.dylib").write_bytes(b"good")
    info = MachOLoadInfo(executable=True, architectures=1, rpaths=[str(early), str(intended)], dylibs=["@rpath/libExample.dylib"])
    scanner = DylibHijackScanner(parser=lambda _path: (info, "available"), signing_provider=_signature)

    candidates, warnings = scanner.scan_binary(app, running=True)

    assert warnings == []
    assert candidates[0].issue_type == "loaded_rpath_shadow"
    assert candidates[0].severity == "critical"
    finding = rootkit_findings_from_dylibs(candidates)[0]
    assert finding.category == "dynamic_library_hijack"
    assert "not confirmation of a rootkit" in finding.description


def test_writable_missing_earlier_slot_is_exposure_not_active_hijack(tmp_path: Path) -> None:
    app = tmp_path / "App"
    app.write_bytes(b"binary")
    earlier = tmp_path / "writable" / "missing"
    intended = tmp_path / "intended"
    intended.mkdir()
    (intended / "libExample.dylib").write_bytes(b"good")
    info = MachOLoadInfo(executable=True, architectures=1, rpaths=[str(earlier), str(intended)], dylibs=["@rpath/libExample.dylib"])
    scanner = DylibHijackScanner(parser=lambda _path: (info, "available"), signing_provider=_signature)

    candidates, _warnings = scanner.scan_binary(app)

    assert candidates[0].issue_type == "writable_rpath_slot"
    assert candidates[0].severity == "medium"
    assert "No hijacking library was found" in rootkit_findings_from_dylibs(candidates)[0].description


def test_hardened_runtime_with_library_validation_suppresses_static_false_positive(tmp_path: Path) -> None:
    app = tmp_path / "App"
    app.write_bytes(b"binary")
    info = MachOLoadInfo(executable=True, architectures=1, rpaths=["/tmp/one", "/tmp/two"], dylibs=["@rpath/lib.dylib"])
    protected = {"valid": True, "team_id": "TEAM", "hardened_runtime": True, "disable_library_validation": False}
    scanner = DylibHijackScanner(parser=lambda _path: (info, "available"), signing_provider=lambda _path: protected)

    assert scanner.scan_binary(app)[0] == []


def test_special_dyld_paths_are_resolved_without_shell_expansion(tmp_path: Path) -> None:
    binary = tmp_path / "Contents" / "MacOS" / "App"
    assert resolve_special_path("@executable_path/../Frameworks", binary).endswith("Contents/Frameworks")
