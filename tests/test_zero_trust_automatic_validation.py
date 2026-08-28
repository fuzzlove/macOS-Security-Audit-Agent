import json
from pathlib import Path
from types import SimpleNamespace

from mac_audit_agent.not_signed.models import InstalledSoftwareItem, ProcessRecord, SigningAssessment, SoftwareTrustClassification
from mac_audit_agent.rootkit_detection.models import SystemIntegrityPosture
from mac_audit_agent.zero_trust.automatic_validation import (
    collect_automatic_posture_evidence,
    firewall_status_evidence,
    network_activity_evidence,
    parse_secure_boot_profile,
    persistence_report_evidence,
    software_provenance_evidence,
)


class Result:
    returncode = 0
    stdout = json.dumps({"SPHardwareDataType": [{"secure_boot_level": "Full Security"}]})
    stderr = ""
    error = ""


class Firewall:
    enabled = True
    errors = ()


def test_core_validation_uses_explicit_collector_results() -> None:
    posture = SystemIntegrityPosture(filevault_status="enabled", sip_status="enabled")
    result = collect_automatic_posture_evidence(
        system_integrity_collector=lambda: (posture, ["fdesetup status", "csrutil status"]),
        firewall_collector=lambda **_kwargs: Firewall(),
        command_runner=lambda *_args, **_kwargs: Result(),
    )
    assert result.values == {"filevault_enabled": True, "secure_boot_verified": True, "sip_enabled": True, "firewall_enabled": True}
    assert result.observations["secure_boot_verified"]["collector"].startswith("system_profiler")


def test_secure_boot_missing_or_malformed_remains_unknown() -> None:
    assert parse_secure_boot_profile("not-json")[0] is None
    assert parse_secure_boot_profile(json.dumps({"SPHardwareDataType": [{"chip_type": "Apple M4"}]}))[0] is None


def test_not_signed_inventory_supplies_unknown_developer_and_running_counts() -> None:
    signing = SigningAssessment(SoftwareTrustClassification.UNKNOWN, None, None, None)
    process = ProcessRecord(10, 1, "demo", Path("/tmp/demo"), "tester")
    item = InstalledSoftwareItem("id", "Demo", Path("/tmp/demo"), None, None, None, None, signing, running_processes=(process,))
    values = software_provenance_evidence([item])
    assert values["unsigned_applications"] == 0
    assert values["unknown_developer_applications"] == 1
    assert values["unvalidated_processes"] == 1


def test_existing_persistence_report_is_reused_without_rescanning() -> None:
    report = SimpleNamespace(
        findings=[object(), object()], errors=[],
        coverage=[{"coverage_status": "healthy"}, {"coverage_status": "complete"}],
    )
    assert persistence_report_evidence(report) == {
        "unapproved_persistence_items": 2,
        "persistence_scan_complete": True,
    }
    report.coverage.append({"coverage_status": "partial"})
    assert persistence_report_evidence(report)["persistence_scan_complete"] is False


def test_network_snapshot_does_not_invent_missing_signing_evidence() -> None:
    high = SimpleNamespace(risk_level="high", connections=(object(), object()))
    normal = SimpleNamespace(risk_level="info", connections=(object(),))
    values = network_activity_evidence(SimpleNamespace(groups=(high, normal)))
    assert values["suspicious_outbound_connections"] == 2
    assert values["unvalidated_network_connections"] is None


def test_firewall_section_status_is_normalized() -> None:
    status = {"state": "ENABLED", "evidence": {"application_firewall": {"enabled": True}}}
    assert firewall_status_evidence(status) == {"firewall_enabled": True}
