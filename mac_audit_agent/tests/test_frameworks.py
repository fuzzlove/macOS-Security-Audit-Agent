import json
import re
from pathlib import Path

from mac_audit_agent.frameworks import (
    NIST_CSF_FUNCTIONS,
    framework_summary_for_findings,
    mappings_for_finding,
    validate_mapping_payload,
)
from mac_audit_agent.models import Finding, ScanResult
from mac_audit_agent.reporting import export_scan_result_html, export_scan_result_json
from mac_audit_agent.rules import RULES, validate_rule_registry


def test_rule_registry_framework_mappings_are_valid() -> None:
    assert validate_rule_registry() == []
    for rule in RULES.values():
        for mapping in rule.framework_mappings:
            assert validate_mapping_payload(mapping.to_dict()) == []


def test_every_high_critical_rule_has_framework_mapping() -> None:
    missing = [
        rule.rule_id
        for rule in RULES.values()
        if rule.severity in {"high", "critical"} and not rule.framework_mappings
    ]
    assert missing == []


def test_every_persistence_rule_has_attack_mapping_where_applicable() -> None:
    missing = []
    for rule in RULES.values():
        if rule.category != "persistence":
            continue
        if not any(mapping.framework == "MITRE_ATTACK_MACOS" for mapping in rule.framework_mappings):
            missing.append(rule.rule_id)
    assert missing == []


def test_nist_csf_functions_and_mitre_ids_are_valid() -> None:
    for rule in RULES.values():
        for mapping in rule.framework_mappings:
            if mapping.framework == "NIST_CSF_2_0":
                assert mapping.category in NIST_CSF_FUNCTIONS
            if mapping.framework == "MITRE_ATTACK_MACOS":
                assert re.match(r"^T\d{4}(?:\.\d{3})?$", mapping.id)


def test_cve_and_kev_findings_include_nvd_and_cisa_mappings() -> None:
    mappings = mappings_for_finding(
        {
            "title": "Apple CVE",
            "category": "Vulnerability",
            "severity": "high",
            "cve_ids": ["CVE-2026-0001"],
            "kev": True,
            "kev_cves": ["CVE-2026-0001"],
        }
    )
    frameworks = {(mapping.framework, mapping.id) for mapping in mappings}
    assert ("NVD_CVE", "CVE-2026-0001") in frameworks
    assert ("CISA_KEV", "CVE-2026-0001") in frameworks


def test_framework_summary_counts_mapped_findings() -> None:
    summary = framework_summary_for_findings(
        [
            {"title": "LaunchDaemon Added", "category": "persistence", "rule_id": "launchdaemon_added"},
            {"title": "New Listener", "category": "network", "rule_id": "new_listener_detected"},
        ]
    )
    assert summary["nist_csf"]["Detect"] >= 2
    assert summary["mitre_attack_macos"]["Persistence"] >= 1
    assert summary["unmapped_count"] == 0


def test_reports_render_framework_mappings(tmp_path: Path) -> None:
    finding = Finding(
        id="finding-1",
        category="Persistence",
        title="LaunchDaemon Added",
        severity="high",
        description="LaunchDaemon was added.",
        evidence="/Library/LaunchDaemons/example.plist",
        command_used="persistence monitor",
        remediation_suggestion="Review the LaunchDaemon.",
        warning="Disabling the wrong service can break software.",
    )
    scan = ScanResult(
        scan_id="scan-1",
        timestamp="2026-06-27T00:00:00+00:00",
        hostname="mac.local",
        current_user="m",
        findings=[finding],
        collected_artifacts={
            "ports": {"listening": [], "active_connections": [], "suspicious_review_needed": [], "errors": []},
            "localhost_scan": {},
            "processes": {"all": [], "suspicious": [], "errors": []},
        },
    )
    json_path = export_scan_result_json(scan, tmp_path / "report.json")
    html_path = export_scan_result_html(scan, tmp_path / "report.html")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    html_content = html_path.read_text(encoding="utf-8")
    assert "framework_summary" in payload["report_summary"]
    assert "Framework Summary" in html_content
    assert "NIST CSF 2.0" in html_content
    assert "MITRE ATT&amp;CK macOS" in html_content


def test_no_unsupported_compliance_claim_wording() -> None:
    root = Path(__file__).resolve().parents[2]
    banned = [
        "compliant with NIST",
        "government certified",
        "meets federal requirements",
    ]
    text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in [root / "README.md", root / "docs" / "FRAMEWORK_MAPPING.md"]
    )
    lowered = text.lower()
    assert not any(phrase in lowered for phrase in banned)
