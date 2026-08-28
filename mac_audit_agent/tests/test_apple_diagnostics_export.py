from __future__ import annotations

import json
import subprocess
import zipfile

from mac_audit_agent.apple_diagnostics.collection import collect_apple_diagnostic_context
from mac_audit_agent.apple_diagnostics.exporter import PRIVACY_WARNING, export_apple_evidence_package, redact_payload, verify_apple_evidence_package


def test_apple_evidence_package_exports_manifest_hashes_and_review_warning(tmp_path) -> None:
    package = export_apple_evidence_package(
        {
            "id": "f1",
            "title": "Apple security update gap",
            "category": "Apple Security",
            "severity": "high",
            "evidence": "User /Users/alice observed issue from 192.168.1.10",
        },
        output_dir=tmp_path,
        create_archive=True,
    )
    manifest = json.loads(open(package.manifest_path, encoding="utf-8").read())
    assert manifest["privacy_review_required"] is True
    assert manifest["no_auto_submission"] is True
    assert PRIVACY_WARNING in manifest["privacy_warning"]
    assert package.package_hash
    assert package.archive_path
    with zipfile.ZipFile(package.archive_path) as archive:
        assert any(name.endswith("msaa_finding.json") for name in archive.namelist())


def test_redaction_removes_username_ip_and_mac() -> None:
    payload = {
        "path": "/Users/alice/Library/Logs/example.log",
        "ip": "10.0.0.55",
        "mac": "AA:BB:CC:DD:EE:FF",
        "serial": "C02TESTSERIAL",
        "environment": {"TOKEN": "secret"},
    }
    redacted = redact_payload(payload, redaction_level="standard")
    text = json.dumps(redacted)
    assert "10.0.0.55" not in text
    assert "AA:BB:CC:DD:EE:FF" not in text
    assert "TOKEN" not in text
    assert "<redacted-ip>" in text
    assert "<redacted-mac>" in text


def test_package_includes_watermarked_capture_context_and_detects_change(tmp_path) -> None:
    screenshot = tmp_path / "capture.png"
    screenshot.write_bytes(b"\x89PNG\r\n\x1a\n" + b"sealed-image-fixture")
    package = export_apple_evidence_package(
        export_profile="Hardware / Apple Diagnostics Evidence Checklist",
        output_dir=tmp_path,
        extra_context={"case_id": "INC-42", "serial_number": "SERIAL-SECRET"},
        screenshot_path=screenshot,
    )

    manifest = json.loads(open(package.manifest_path, encoding="utf-8").read())
    assert "watermarked_screen_capture.png" in manifest["artifact_hashes"]
    assert "apple_diagnostic_context.json" in manifest["artifact_hashes"]
    assert "not immutable" in manifest["integrity_model"]
    assert verify_apple_evidence_package(package)["valid"] is True

    captured = tmp_path / package.package_id / "watermarked_screen_capture.png"
    captured.chmod(0o600)
    captured.write_bytes(captured.read_bytes() + b"changed")
    verification = verify_apple_evidence_package(package)
    assert verification["valid"] is False
    assert any(item["artifact"] == "watermarked_screen_capture.png" and not item["valid"] for item in verification["checks"])


def test_bounded_apple_diagnostic_context_is_read_only_and_explicit_about_limits() -> None:
    commands: list[list[str]] = []

    def runner(command, **_kwargs):
        commands.append(list(command))
        if command == ["/usr/bin/sw_vers"]:
            return subprocess.CompletedProcess(command, 0, "ProductVersion:\t15.5\n", "")
        return subprocess.CompletedProcess(command, 0, '{"SPHardwareDataType": [{"machine_model": "Mac"}]}', "")

    context = collect_apple_diagnostic_context(runner)

    assert commands[0] == ["/usr/bin/sw_vers"]
    assert commands[1][0] == "/usr/sbin/system_profiler"
    assert context["system_profiler"]["data"]["SPHardwareDataType"][0]["machine_model"] == "Mac"
    assert context["apple_diagnostics_reference_code"] == "user_entry_required"
    assert any("does not run" in item for item in context["limitations"])
