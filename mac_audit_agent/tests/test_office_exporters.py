from __future__ import annotations

import importlib.util
import zipfile

import pytest

from mac_audit_agent.assessment import SecurityAssessment
from mac_audit_agent.exporters import (
    ExportOptions,
    build_export_assessment_data,
    export_assessment_excel,
    export_assessment_word,
    get_suggested_fix,
)


def _assessment() -> SecurityAssessment:
    finding = {
        "id": "F-1",
        "title": "LaunchDaemon added",
        "severity": "high",
        "confidence": "high",
        "category": "Admin & Persistence",
        "description": "A new LaunchDaemon was recorded.",
        "evidence_summary": "com.example.test.plist",
        "framework_mappings": [
            {"framework": "NIST_800_53_REV5", "id": "SI-4", "name": "System Monitoring", "category": "Detect", "confidence": "high", "relevance": "Mapped to monitoring review."}
        ],
    }
    return SecurityAssessment(
        assessment_id="assessment-test",
        created_at="2026-06-28T12:00:00+00:00",
        hostname="test-mac",
        macos_version="15.0",
        app_version="0.1.1",
        assessment_status="ready",
        overall_score=82,
        risk_level="medium",
        executive_summary="Assessment summary.",
        top_risks=[finding],
        high_findings=[finding],
        recommended_actions=[],
        framework_summary={"NIST_800_53_REV5": {"SI-4": 1}},
        apple_exposure_summary={
            "status": "collected",
            "summary": "Apple exposure checked.",
            "generated_at": "2026-06-01T00:00:00Z",
            "display_cards": [
                {
                    "card_id": "apple-card-1",
                    "title": "Safari/WebKit Security Update",
                    "affected_local_product": "Safari/WebKit",
                    "detected_version": "17.0",
                    "fixed_version": "17.1",
                    "forecast_level": "urgent",
                    "recommended_action": "Install available Apple updates.",
                    "references": ["https://support.apple.com/en-us/100100"],
                }
            ],
        },
        network_activity_summary={"status": "no findings", "summary": "No network findings."},
        admin_persistence_summary={"status": "collected", "items": [finding]},
        physical_device_summary={"status": "no findings", "summary": "No physical device findings."},
        monitor_integrity_summary={"status": "healthy", "summary": "Monitor healthy."},
        limitations=["Test limitation."],
    )


def test_remediation_launchdaemon_finding_gets_safe_fix() -> None:
    advice = get_suggested_fix({"title": "LaunchDaemon added", "severity": "high"})
    assert "Review the LaunchDaemon plist" in advice.suggested_fix
    assert "Re-run the persistence scan" in advice.validation_step
    assert "Preserve evidence" in advice.suggested_fix


def test_remediation_common_security_categories_get_useful_safe_fixes() -> None:
    cases = [
        ("New USB HID device", "expected", "Physical Device"),
        ("New network listener", "owning process", "Network"),
        ("Apple CVE exposure", "Apple security update", "Apple Exposure"),
        ("Admin user added", "intentionally created", "Admin"),
        ("Monitor degraded", "Restart the monitor", "Monitor Integrity"),
    ]
    for title, expected_text, category in cases:
        advice = get_suggested_fix({"title": title, "category": category, "severity": "high"})
        combined = f"{advice.suggested_fix} {advice.validation_step}"
        assert expected_text in combined
        assert "delete this" not in combined.lower()


def test_export_model_includes_findings_fixes_and_framework_mappings() -> None:
    data = build_export_assessment_data(_assessment())
    assert data.findings
    assert data.findings[0]["suggested_fix"]
    assert data.findings[0]["validation_step"]
    assert data.findings[0]["false_positive_notes"]
    assert data.framework_mappings
    assert data.cmmc_summary["total_requirements"] > 0
    assert data.cmmc_evidence_matrix
    assert data.cmmc_poam
    assert data.cmmc_source_versions
    assert data.limitations == ["Test limitation."]


def test_export_model_includes_apple_update_guidance_for_office_reports() -> None:
    data = build_export_assessment_data(_assessment())
    assert data.apple_exposure
    assert data.apple_exposure[0]["update_guidance_title"]
    assert data.apple_exposure[0]["update_guidance_summary"]
    assert data.apple_exposure[0]["verification_steps"]
    assert data.apple_exposure[0]["evidence_preservation_notes"]
    assert data.apple_exposure[0]["official_references"]


def test_export_model_includes_integrity_mismatch_diagnostics() -> None:
    assessment = _assessment()
    assessment.monitor_integrity_summary = {
        "application_integrity": {
            "overall_status": "stale",
            "manifest_path": "/tmp/msaa_integrity_manifest.json",
            "source_type": "source_tree",
            "current_install_mode": "source_tree",
            "manifest_app_version": "0.9.4",
            "current_app_version": "0.9.5",
            "manifest_build_id": "old",
            "current_build_id": "new",
            "manifest_git_commit": "abc",
            "current_git_commit": "def",
            "manifest_package_version": "0.9.4",
            "current_package_version": "0.9.5",
            "manifest_root_path": "/tmp/old",
            "current_root_path": "/tmp/current",
            "manifest_created_at": "2026-06-01T00:00:00+00:00",
            "manifest_hash": "hash",
            "verification_result_id": "verify-1",
            "verified_at": "2026-07-01T00:00:00+00:00",
            "cached_result": False,
            "cache_valid": True,
            "cache_invalidated_reason": "bypassed",
            "exact_mismatch_reason": "Manifest version 0.9.4 differs from current app version 0.9.5.",
            "matched_count": 10,
            "mismatched_count": 0,
            "missing_count": 0,
            "extra_count": 0,
            "recommended_actions": ["Create new trusted manifest after verifying update."],
        }
    }

    data = build_export_assessment_data(assessment)

    row = data.application_integrity[0]
    assert row["status"] == "stale"
    assert row["manifest_app_version"] == "0.9.4"
    assert row["current_app_version"] == "0.9.5"
    assert row["verification_result_id"] == "verify-1"
    assert row["cache_invalidated_reason"] == "bypassed"
    assert "does not by itself prove tampering" not in row["exact_mismatch_reason"].lower()


def test_export_model_honors_client_safe_options() -> None:
    data = build_export_assessment_data(
        _assessment(),
        options=ExportOptions(
            include_detailed_findings=False,
            include_framework_mappings=False,
            include_remediation_plan=False,
            include_limitations=False,
            redact_usernames_hostnames=True,
        ),
    )
    assert data.metadata["hostname"] == "Redacted Host"
    assert data.findings == []
    assert data.framework_mappings == []
    assert data.remediation_items == []
    assert data.limitations == []


def test_word_export_creates_docx_when_dependency_available(tmp_path) -> None:
    if importlib.util.find_spec("docx") is None:
        pytest.skip("python-docx is not installed")
    path = export_assessment_word(_assessment(), tmp_path / "assessment.docx")
    assert path.exists()
    assert path.suffix == ".docx"
    with zipfile.ZipFile(path) as archive:
        document_xml = archive.read("word/document.xml").decode("utf-8")
    assert "CMMC / NIST Readiness" in document_xml
    assert "Evidence Matrix" in document_xml


def test_excel_export_creates_xlsx_when_dependency_available(tmp_path) -> None:
    if importlib.util.find_spec("openpyxl") is None:
        pytest.skip("openpyxl is not installed")
    path = export_assessment_excel(_assessment(), tmp_path / "assessment.xlsx")
    assert path.exists()
    assert path.suffix == ".xlsx"
    with zipfile.ZipFile(path) as archive:
        workbook_xml = archive.read("xl/workbook.xml").decode("utf-8")
    assert "CMMC Summary" in workbook_xml
    assert "Evidence Matrix" in workbook_xml
    assert "POA&amp;M" in workbook_xml
