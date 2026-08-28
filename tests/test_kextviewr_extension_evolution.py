from __future__ import annotations

import plistlib
from pathlib import Path

from mac_audit_agent.rootkit_detection.extension_inventory import _path_item, findings_from_extensions, parse_kmutil_showloaded
from mac_audit_agent.rootkit_detection.extension_inventory import _signature_metadata


def test_kmutil_parser_preserves_collection_address_and_architecture() -> None:
    item = parse_kmutil_showloaded("1 0 0xffffff800123 4096 arm64 aux com.example.driver (1.0)")[0]
    assert item.bundle_id == "com.example.driver"
    assert item.address == "0xffffff800123"
    assert item.architecture == "arm64"
    assert item.collection == "auxiliary"
    assert item.visibility_sources == ["kmutil"]


def test_extension_bundle_uses_real_identifier_and_flags_invalid_signature(tmp_path: Path, monkeypatch) -> None:
    bundle = tmp_path / "Example.kext"
    contents = bundle / "Contents"
    contents.mkdir(parents=True)
    with (contents / "Info.plist").open("wb") as handle:
        plistlib.dump({"CFBundleIdentifier": "com.example.driver", "CFBundleExecutable": "Driver"}, handle)
    monkeypatch.setattr(
        "mac_audit_agent.rootkit_detection.extension_inventory._signature_metadata",
        lambda _path: {"signed_status": "invalid", "team_id": "", "authority": "", "verification": "invalid"},
    )

    item = _path_item(bundle, "kernel_extension")

    assert item.bundle_id == "com.example.driver"
    assert "declared extension executable is missing" in item.risk_flags
    assert "extension signature is invalid" in item.risk_flags
    finding = findings_from_extensions([item])[0]
    assert finding.severity == "high"


def test_codesign_permission_failure_is_unknown_not_unsigned(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "Example.kext"
    target.mkdir()

    class Result:
        returncode = 1
        stdout = ""
        stderr = "Operation not permitted"

    monkeypatch.setattr("mac_audit_agent.rootkit_detection.extension_inventory._run", lambda *_args, **_kwargs: ("", "Operation not permitted"))
    monkeypatch.setattr("mac_audit_agent.rootkit_detection.extension_inventory.subprocess.run", lambda *_args, **_kwargs: Result())

    assert _signature_metadata(target)["signed_status"] == "unknown"
