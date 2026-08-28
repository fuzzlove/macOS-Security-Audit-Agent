from __future__ import annotations

import json

import pytest

from mac_audit_agent.mitre_coverage import CoverageStatus, DetectionCoverage, MITRECoverageMatrix
from mac_audit_agent.models import Finding, ScanResult
from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json, security_assurance_for_findings


def test_positive_coverage_requires_detector_evidence_and_validation() -> None:
    with pytest.raises(ValueError, match="lacks detector"):
        MITRECoverageMatrix((DetectionCoverage("T9999", "Synthetic", "Test", CoverageStatus.IMPLEMENTED),))


def test_mapping_does_not_promote_unassessed_technique_to_coverage() -> None:
    result = security_assurance_for_findings([{"category": "process", "mitre_attack": ["T1059"]}])
    matrix = result["mitre_attack_coverage"]
    entry = next(item for item in matrix["techniques"] if item["technique_id"] == "T1059")
    assert entry["status"] == "not_assessed"
    assert "T1059" in matrix["observed_techniques"]


def test_coverage_summary_counts_only_fully_implemented_as_implemented() -> None:
    matrix = MITRECoverageMatrix().to_dict()
    assert matrix["summary"]["implemented"] == 4
    assert matrix["summary"]["partial"] == 6
    assert matrix["summary"]["unavailable"] == 1
    assert matrix["summary"]["not_assessed"] == 1
    assert matrix["summary"]["fully_implemented_percent_of_assessed"] == 40.0


def test_assurance_payload_is_json_serializable_and_preserves_unmapped_limit() -> None:
    result = security_assurance_for_findings([{"category": "unknown_new_detector", "title": "Review"}])
    assert result["control_mappings"][0]["mapped"] is False
    assert result["control_mappings"][0]["limitations"]
    json.dumps(result)


def test_scan_exports_include_qualified_coverage_matrix(tmp_path) -> None:
    finding = Finding(
        id="f-1", category="Persistence", title="LaunchAgent added", severity="high",
        description="Review.", evidence="test", command_used="persistence inventory",
        remediation_suggestion="Verify ownership and provenance.", warning="Preserve evidence before changes.",
    )
    scan = ScanResult(scan_id="scan-1", timestamp="2026-07-17T00:00:00Z", hostname="test", current_user="analyst", findings=[finding])
    json_path = export_scan_result_json(scan, tmp_path / "report.json")
    html_path = export_scan_result_html(scan, tmp_path / "report.html")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["security_control_assurance"]["mitre_attack_coverage"]["qualification"].startswith("Coverage is detector")
    html_text = html_path.read_text(encoding="utf-8")
    assert "MITRE ATT&amp;CK Detection Coverage" in html_text
    assert "not_assessed" in html_text
