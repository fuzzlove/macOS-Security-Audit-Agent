from mac_audit_agent.zero_trust import ZeroTrustPostureEngine
from mac_audit_agent.models import ProcessSnapshot, ScanResult


def test_unknown_evidence_is_not_treated_as_trusted() -> None:
    posture = ZeroTrustPostureEngine().calculate({"calculated_at": "2026-01-01T00:00:00+00:00"})
    assert posture.score == 0
    assert posture.evidence_coverage_percent == 0
    assert all(signal.state == "unknown" for signal in posture.signals)


def test_validated_reference_posture_scores_100() -> None:
    evidence = {
        "filevault_enabled": True, "secure_boot_verified": True, "sip_enabled": True, "firewall_enabled": True,
        "unsigned_applications": 0, "unknown_developer_applications": 0, "unvalidated_processes": 0,
        "unapproved_persistence_items": 0, "persistence_scan_complete": True, "approved_dns": True,
        "suspicious_outbound_connections": 0, "unvalidated_network_connections": 0,
    }
    posture = ZeroTrustPostureEngine().calculate(evidence)
    assert posture.score == 100
    assert posture.evidence_coverage_percent == 100


def test_concerns_reduce_score_and_include_framework_context() -> None:
    evidence = {"filevault_enabled": True, "unsigned_applications": 4, "suspicious_outbound_connections": 1}
    posture = ZeroTrustPostureEngine().calculate(evidence)
    unsigned = next(item for item in posture.signals if item.signal_id == "unsigned_applications")
    assert unsigned.state == "concern"
    assert "AC-6" in unsigned.nist_controls
    assert "T1553.002" in unsigned.mitre_techniques
    assert posture.score < 100


def test_scan_adapter_uses_observed_process_and_persistence_evidence_only() -> None:
    scan = ScanResult("scan-1", "2026-01-01T00:00:00+00:00", "host", "user", collected_artifacts={
        "processes": {"all": [ProcessSnapshot(42, 1, "user", "/tmp/tool", "tool", "unsigned", "untrusted")]},
        "launch_snapshots": [],
        "ports": {"active_connections": []},
    })
    evidence = ZeroTrustPostureEngine().evidence_from_scan(scan)
    assert evidence["unsigned_applications"] == 1
    assert evidence["unvalidated_processes"] == 1
    assert evidence["persistence_scan_complete"] is True
    assert "filevault_enabled" not in evidence


def test_automatic_evidence_provenance_is_preserved_on_signal() -> None:
    evidence = {
        "firewall_enabled": True,
        "_evidence_metadata": {
            "firewall_enabled": {
                "source": "Firewall Status",
                "collected_at": "2026-08-26T12:00:00+00:00",
                "freshness": "current",
                "automatic": True,
            }
        },
    }
    signal = next(item for item in ZeroTrustPostureEngine().calculate(evidence).signals if item.signal_id == "firewall_enabled")
    assert signal.automatically_collected is True
    assert signal.evidence_source == "Firewall Status"
    assert signal.evidence_freshness == "current"
